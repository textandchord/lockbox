import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from datetime import datetime
import ntplib
from tzlocal import get_localzone

# AES block size (16 bytes for AES-CBC)
BLOCK_SIZE = AES.block_size

def derive_key(password: str) -> bytes:
    """
    Derive a 256-bit AES key from the user’s password using SHA-256.
    Returns a 32-byte digest.
    """
    return hashlib.sha256(password.encode()).digest()

def encrypt_password(plaintext: str, user_key: bytes) -> bytes:
    """
    Encrypt the given plaintext string using AES-CBC with PKCS#7 padding.
    Generates a random IV and prepends it to the ciphertext.
    Returns IV || ciphertext.
    """
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(user_key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode('utf-8'), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext

def decrypt_password(blob: bytes, user_key: bytes) -> str:
    """
    Decrypt the given blob (IV || ciphertext).
    Splits out the IV, decrypts and removes PKCS#7 padding, then decodes to UTF-8.
    """
    iv, ct = blob[:BLOCK_SIZE], blob[BLOCK_SIZE:]
    cipher = AES.new(user_key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ct)
    plaintext = unpad(padded, BLOCK_SIZE)  # may raise ValueError if padding is incorrect
    return plaintext.decode('utf-8')

def write_lockbox():
    """
    Create a lockbox file:
    1. Prompt for an expiry date and validate its format.
    2. Prompt for the secret value and an encryption password.
    3. Prompt for an output filename and ensure it ends with '.lb'.
    4. Derive the key, encrypt the secret, and write to file:
       - first line: expiry date in cleartext
       - rest: encrypted blob (IV + ciphertext)
    """
    expiry_str = input('Enter expiry date (DD/MM/YYYY HH:MM:SS): ')
    try:
        # Validate date format
        datetime.strptime(expiry_str, '%d/%m/%Y %H:%M:%S')
    except ValueError:
        print('Invalid date format')
        return

    secret_value = input('Enter value to encrypt: ')
    user_password = input('Enter encryption password: ')
    filename = input('Enter output filename (must end with .lb): ')

    # Check .lb extension
    if not filename.lower().endswith('.lb'):
        print("Error: filename must have a '.lb' extension.")
        return

    # Derive encryption key from user password
    key = derive_key(user_password)
    encrypted_blob = encrypt_password(secret_value, key)

    # Write expiry date and encrypted blob to file
    with open(filename, 'wb') as f:
        f.write((expiry_str + '\n').encode('ascii'))
        f.write(encrypted_blob)

    print(f'Lockbox saved to {filename}')

def read_lockbox():
    """
    Read and decrypt a lockbox file:
    1. Prompt for the filename and decryption password.
    2. Ensure the filename ends with '.lb'.
    3. Read the expiry date (plaintext) and encrypted blob.
    4. Fetch current time via NTP for tamper-resistance.
    5. If expired, attempt to decrypt. If the password is wrong, notify the user.
    """
    filename = input('Enter lockbox filename (must end with .lb): ')
    if not filename.lower().endswith('.lb'):
        print("Error: filename must have a '.lb' extension.")
        return

    user_password = input('Enter decryption password: ')
    key = derive_key(user_password)

    try:
        with open(filename, 'rb') as f:
            expiry_line = f.readline().decode('ascii').strip()
            encrypted_blob = f.read()

        # Parse expiry date and assign local timezone
        exp_dt = datetime.strptime(expiry_line, '%d/%m/%Y %H:%M:%S')
        local_tz = get_localzone()
        exp_dt = exp_dt.replace(tzinfo=local_tz)

        # Get accurate current time via NTP
        ntp_client = ntplib.NTPClient()
        resp = ntp_client.request('ntp1.inrim.it')
        now = datetime.fromtimestamp(resp.tx_time).astimezone(local_tz)

        # Compare current time to expiry
        if now < exp_dt:
            print(f"The timer has not expired yet. Expiration date: {exp_dt}")
            return

        # Attempt decryption and check password correctness
        try:
            decrypted_value = decrypt_password(encrypted_blob, key)
        except (ValueError, KeyError):
            print('Incorrect decryption password.')
            return

        # If successful, show the secret
        print(f"Decrypted value: {decrypted_value}")

    except FileNotFoundError:
        print('Lockbox file not found.')
    except Exception as e:
        print('Failed to read or decrypt the lockbox:', e)

def main():
    """
    Program entry point:
    - [1] to write a new lockbox
    - [2] to read an existing lockbox
    """
    choice = input('- [1] for write  - [2] for read\nChoose: ')
    if choice == '1':
        write_lockbox()
    elif choice == '2':
        read_lockbox()
    else:
        print('Invalid choice')

if __name__ == '__main__':
    main()
