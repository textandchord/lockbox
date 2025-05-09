import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from datetime import datetime
import ntplib
from tzlocal import get_localzone

# AES block size (16 bytes for AES-CBC)
BLOCK_SIZE = AES.block_size
# Length of the HMAC-SHA256 tag
HMAC_SIZE = SHA256.digest_size

def derive_keys(password: str):
    """
    Derive two 256-bit keys from the user’s password:
    - key_enc = SHA256(password || b'enc')
    - key_mac = SHA256(password || b'mac')
    Returns (key_enc, key_mac).
    """
    pw = password.encode('utf-8')
    key_enc = hashlib.sha256(pw + b'enc').digest()
    key_mac = hashlib.sha256(pw + b'mac').digest()
    return key_enc, key_mac

def encrypt_secret(plaintext: str, key_enc: bytes) -> bytes:
    """
    Encrypt the given plaintext string using AES-CBC with PKCS#7 padding.
    Generates a random IV and prepends it to the ciphertext.
    Returns IV || ciphertext.
    """
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key_enc, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode('utf-8'), BLOCK_SIZE)
    ct = cipher.encrypt(padded)
    return iv + ct

def decrypt_secret(blob: bytes, key_enc: bytes) -> str:
    """
    Decrypt the given blob (IV || ciphertext).
    Splits out the IV, decrypts, removes PKCS#7 padding, and decodes to UTF-8.
    May raise ValueError if padding is incorrect (wrong key).
    """
    iv, ct = blob[:BLOCK_SIZE], blob[BLOCK_SIZE:]
    cipher = AES.new(key_enc, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ct)
    return unpad(padded, BLOCK_SIZE).decode('utf-8')

def write_lockbox():
    """
    Create a lockbox file:
    1. Prompt for an expiry date and validate its format.
    2. Prompt for the secret value and an encryption password.
    3. Prompt for an output filename and ensure it ends with '.lb'.
    4. Derive keys, encrypt the secret, compute HMAC over date+blob.
    5. Write to file: [expiry]\n[encrypted_blob][HMAC tag].
    """
    expiry_str = input('Enter expiry date (DD/MM/YYYY HH:MM:SS): ')
    try:
        # Validate date format
        datetime.strptime(expiry_str, '%d/%m/%Y %H:%M:%S')
    except ValueError:
        print('Invalid date format')
        return

    secret_value = input('Enter value to encrypt: ')
    password     = input('Enter encryption password: ')
    filename     = input('Enter output filename (must end with .lb): ')
    if not filename.lower().endswith('.lb'):
        print("Error: filename must have a '.lb' extension.")
        return

    # Derive two keys from the password
    key_enc, key_mac = derive_keys(password)

    # Encrypt the secret
    encrypted_blob = encrypt_secret(secret_value, key_enc)

    # Build the message to authenticate: expiry_line || '\n' || encrypted_blob
    msg = expiry_str.encode('ascii') + b'\n' + encrypted_blob

    # Compute HMAC-SHA256 over msg
    h = HMAC.new(key_mac, digestmod=SHA256)
    h.update(msg)
    tag = h.digest()

    # Write all to file
    with open(filename, 'wb') as f:
        f.write(msg)
        f.write(tag)

    print(f'Lockbox saved to {filename}')

def read_lockbox():
    """
    Read and decrypt a lockbox file:
    1. Prompt for filename (ensuring .lb) and decryption password.
    2. Read the entire file, split off the HMAC tag.
    3. Verify HMAC over date+blob; fail if tampered or wrong password.
    4. Parse expiry date, fetch current time via NTP, compare.
    5. If expired, decrypt and display; otherwise notify.
    """
    filename = input('Enter lockbox filename (must end with .lb): ')
    if not filename.lower().endswith('.lb'):
        print("Error: filename must have a '.lb' extension.")
        return

    password = input('Enter decryption password: ')
    key_enc, key_mac = derive_keys(password)

    try:
        with open(filename, 'rb') as f:
            content = f.read()
    except FileNotFoundError:
        print('Lockbox file not found.')
        return

    # Split off the HMAC tag
    if len(content) <= HMAC_SIZE:
        print('Lockbox file is corrupted or too small.')
        return
    msg, tag = content[:-HMAC_SIZE], content[-HMAC_SIZE:]

    # Verify HMAC
    h = HMAC.new(key_mac, digestmod=SHA256)
    h.update(msg)
    try:
        h.verify(tag)
    except ValueError:
        print('Integrity check failed: file tampered or wrong password.')
        return

    # Split expiry date and encrypted blob
    try:
        expiry_line, encrypted_blob = msg.split(b'\n', 1)
    except ValueError:
        print('Lockbox format error.')
        return

    # Parse expiry date and assign local timezone
    try:
        exp_dt = datetime.strptime(expiry_line.decode('ascii'), '%d/%m/%Y %H:%M:%S')
    except ValueError:
        print('Invalid expiry date format in file.')
        return
    local_tz = get_localzone()
    exp_dt = exp_dt.replace(tzinfo=local_tz)

    # Fetch current time via NTP for tamper-resistance
    try:
        ntp_client = ntplib.NTPClient()
        resp = ntp_client.request('ntp1.inrim.it')
        now = datetime.fromtimestamp(resp.tx_time).astimezone(local_tz)
    except Exception:
        print('Could not fetch NTP time; aborting for safety.')
        return

    # Compare times
    if now < exp_dt:
        print(f"The timer has not expired yet. Expiration date: {exp_dt}")
        return

    # Decrypt and display the secret
    try:
        decrypted_value = decrypt_secret(encrypted_blob, key_enc)
    except ValueError:
        print('Decryption failed: wrong password or corrupted data.')
        return

    print(f"Decrypted value: {decrypted_value}")

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
