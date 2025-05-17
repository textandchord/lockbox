import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from datetime import datetime
import ntplib
from tzlocal import get_localzone
import base64
import os

# AES block size (16 bytes for AES-CBC)
BLOCK_SIZE = AES.block_size
# Length of the HMAC-SHA256 tag
HMAC_SIZE = SHA256.digest_size


def derive_keys(password: str):
    """Derive two 256-bit keys from the user’s password."""
    pw = password.encode('utf-8')
    key_enc = hashlib.sha256(pw + b'enc').digest()
    key_mac = hashlib.sha256(pw + b'mac').digest()
    return key_enc, key_mac


def encrypt_secret(plaintext: str, key_enc: bytes) -> bytes:
    """Encrypt the given plaintext string using AES-CBC."""
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key_enc, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode('utf-8'), BLOCK_SIZE)
    ct = cipher.encrypt(padded)
    # Prepend IV to ciphertext
    return iv + ct


def decrypt_secret(blob: bytes, key_enc: bytes) -> str:
    """Decrypt the given blob (IV || ciphertext)."""
    # Split blob into IV and ciphertext
    iv, ct = blob[:BLOCK_SIZE], blob[BLOCK_SIZE:]
    cipher = AES.new(key_enc, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ct)
    # Unpad and decode to UTF-8
    return unpad(padded, BLOCK_SIZE).decode('utf-8')


def write_lockbox():
    """
    Handle the lockbox creation process:
    1. Prompt for an expiry date and validate its format (loops until valid).
    2. Prompt for the path to the file to encrypt (loops until file readable).
    3. Automatically name the output lockbox file based on the input filename (e.g., foo.txt -> foo.lb).
    4. Read file content, encode to base64, extract filename base and extension, combine.
    5. Derive keys and encryption password.
    6. Encrypt the combined value, compute HMAC over date+blob.
    7. Write to file: [expiry]\n[encrypted_blob][HMAC tag].
    """
    # 1. Loop for expiry date input and validation
    while True:
        expiry_str = input('Enter expiry date (DD/MM/YYYY HH:MM:SS): ')
        try:
            datetime.strptime(expiry_str, '%d/%m/%Y %H:%M:%S')
            break  # Exit loop if date format is valid
        except ValueError:
            print('Invalid date format. Please use DD/MM/YYYY HH:MM:SS format.')

    # 2. Loop for file path input and processing
    while True:
        filepath = input('Enter path to file to encrypt: ')
        try:
            # Read file content in binary mode
            with open(filepath, 'rb') as f:
                file_content = f.read()
            # Encode file content to base64
            base64_content = base64.b64encode(file_content).decode('ascii')
            # Extract filename base and extension from the input file path
            filename_with_ext = os.path.basename(filepath)
            filename_base, file_extension = os.path.splitext(filename_with_ext)
            extension = file_extension.lstrip('.')  # Remove leading dot if present
            # Combine filename base, extension, and base64 content
            secret_value_with_info = f"{filename_base}:{extension}:{base64_content}"

            # 3. Automatically determine output filename based on input filename base
            filename = filename_base + '.lb'

            break  # Exit loop if file is successfully read and processed
        except FileNotFoundError:
            print(f"Error: File not found at '{filepath}'. Please try again.")
        except IOError:
            print(f"Error reading file '{filepath}'. Please check permissions and try again.")
        except Exception as e:  # Catch any other potential errors during base64/splitting
            print(f"An unexpected error occurred while processing the file: {e}. Please try again.")

    # 5. Prompt for encryption password
    password = input('Enter encryption password: ')

    # 5. Derive encryption and MAC keys
    key_enc, key_mac = derive_keys(password)

    # 6. Encrypt the combined value (filename_base:extension:base64_content)
    encrypted_blob = encrypt_secret(secret_value_with_info, key_enc)

    # 6. Compute HMAC-SHA256 over date+blob
    msg = expiry_str.encode('ascii') + b'\n' + encrypted_blob
    h = HMAC.new(key_mac, digestmod=SHA256)
    h.update(msg)
    tag = h.digest()

    # 7. Write expiry, encrypted blob, and HMAC tag to file
    try:
        with open(filename, 'wb') as f:
            f.write(msg)
            f.write(tag)
        print(f'Lockbox saved to {filename}')
    except IOError:
        print(f"Error writing lockbox file to '{filename}'. Please check permissions.")


def read_lockbox():
    """
    Handle the lockbox decryption process:
    1. Prompt for lockbox filename (without .lb) (loops until file readable) and adds .lb.
    2. Read the entire file, split off the HMAC tag.
    3. Verify HMAC over date+blob; fail if tampered or wrong password.
    4. Parse expiry date, fetch current time via NTP, compare.
    5. If expired, decrypt, recover filename base, extension, and base64 content,
       decode base64, and save to a new file using the recovered filename base and extension.
       Otherwise notify.
    """
    # 1. Loop for lockbox filename input and reading
    while True:
        filename_base_input = input('Enter lockbox filename: ')
        if not filename_base_input:
            print("Filename cannot be empty. Please try again.")
            continue

        # Add .lb extension if not already present
        filename = filename_base_input if filename_base_input.lower().endswith('.lb') else filename_base_input + '.lb'

        try:
            # Read the lockbox file in binary mode
            with open(filename, 'rb') as f:
                content = f.read()
            break  # Exit loop if file is successfully read
        except FileNotFoundError:
            print(f"Lockbox file '{filename}' not found. Please check the name and try again.")
        except IOError:
            print(f"Error reading lockbox file '{filename}'. Please check permissions and try again.")

    # Prompt for decryption password
    password = input('Enter decryption password: ')
    # Derive encryption and MAC keys using the provided password
    key_enc, key_mac = derive_keys(password)

    # 2. Check if content is too small to contain HMAC tag
    if len(content) <= HMAC_SIZE:
        print('Lockbox file is corrupted or too small.')
        return # Exit read_lockbox if file is fundamentally wrong size

    # Split content into message and HMAC tag
    msg, tag = content[:-HMAC_SIZE], content[-HMAC_SIZE:]

    # 3. Verify HMAC of the message
    h = HMAC.new(key_mac, digestmod=SHA256)
    h.update(msg)
    try:
        h.verify(tag)
        print("Integrity check successful.")
    except ValueError:
        print('Integrity check failed: file tampered or wrong password.')
        return # Exit if integrity check fails (wrong password or tampered)

    # 4. Split message into expiry date line and encrypted blob
    try:
        expiry_line, encrypted_blob = msg.split(b'\n', 1)
    except ValueError:
        print('Lockbox format error: could not find expiry line.')
        return # Exit if file format is wrong

    # 4. Parse expiry date and assign local timezone
    try:
        exp_dt = datetime.strptime(expiry_line.decode('ascii'), '%d/%m/%Y %H:%M:%S')
    except ValueError:
        print('Invalid expiry date format in file.')
        return # Exit if expiry date in file is malformed

    local_tz = get_localzone()
    exp_dt = exp_dt.replace(tzinfo=local_tz)

    # 4. Fetch current time via NTP for tamper-resistance
    try:
        ntp_client = ntplib.NTPClient()
        resp = ntp_client.request('ntp1.inrim.it')
        now = datetime.fromtimestamp(resp.tx_time).astimezone(local_tz)
    except Exception:
        print('Could not fetch NTP time; aborting for safety.')
        return # Exit if NTP time cannot be fetched

    # 4. Compare current time with expiry date
    if now < exp_dt:
        print(f"The timer has not expired yet. Expiration date: {exp_dt}")
        return # Exit if timer not expired

    # 5. Decrypt the secret (which contains filename_base:extension:base64_content)
    try:
        decrypted_value = decrypt_secret(encrypted_blob, key_enc)
    except ValueError:
        print('Decryption failed: wrong password or corrupted data.')
        return # Exit if decryption fails

    # 5. Parse decrypted value into filename base, extension, and base64 content
    try:
        parts = decrypted_value.split(':', 2)
        if len(parts) != 3:
            raise ValueError("Incorrect number of parts after splitting decrypted content")
        filename_base, extension, base64_content = parts

        # Decode the base64 content back to binary data
        file_content = base64.b64decode(base64_content)
    except ValueError as e:
        print(f'Error parsing decrypted content: {e}')
        return
    except base64.binascii.Error:
        print('Error decoding base64 content.')
        return

    # 5. Construct the final output filename
    output_filename = f"{filename_base}_decrypted.{extension}" if extension else f"{filename_base}_decrypted"

    # 5. Write the decoded binary data to a file
    try:
        with open(output_filename, 'wb') as f:
            f.write(file_content)
        print(f"File successfully decrypted and saved to '{output_filename}'")
    except IOError:
        print(f"Error writing decrypted file to '{output_filename}'. Please check permissions.")


def main():
    """
    Main program entry point:
    - [1] to write a new lockbox
    - [2] to read an existing lockbox
    - [3] to exit the program
    """
    while True:  # Loop main menu until valid choice or exit
        choice = input('- [1] for write  - [2] for read  - [3] for exit\nChoose: ')
        if choice == '1':
            write_lockbox()
            # Stays in loop, returns to menu after operation
        elif choice == '2':
            read_lockbox()
            # Stays in loop, returns to menu after operation
        elif choice == '3':
            print("Exit.")
            break # Exit the main loop, ending the program
        else:
            print('Invalid choice. Please enter 1, 2, or 3.')

if __name__ == '__main__':
    main()