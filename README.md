# Lockbox

A simple command-line tool to store an arbitrary secret string in an encrypted “lockbox” file that only becomes readable after a user-specified expiry date. The encryption key is derived from a password you choose at creation time—so **you** are responsible for remembering the key.

## Features

- **Expiry-based release**  
  Embeds a cleartext expiry timestamp in the file header and will only decrypt once the system clock (queried via NTP) has reached or passed that timestamp.

- **User-supplied encryption key**  
  Derives a 256-bit AES key via SHA-256 from the password you enter, avoiding any hard-coded “master” password.

- **AES-CBC with PKCS#7 padding**  
  Uses a fresh random IV per file; stores IV prepended to ciphertext.

- **Tamper-resistant timestamp & contents**  
  - Fetches current time from an NTP server (`ntp1.inrim.it`) to defeat local clock manipulation.  
  - Computes an HMAC-SHA256 over `expiry_date || encrypted_blob` so that any manual edits to the date or ciphertext will be detected and rejected.

- **File extension validation**  
  Ensures that lockbox files use the `.lb` extension to avoid accidental overwrites or confusion.

## Prerequisites

- Python 3.6+
- [`pycryptodome`](https://pypi.org/project/pycryptodome/)  
- [`ntplib`](https://pypi.org/project/ntplib/)  
- [`tzlocal`](https://pypi.org/project/tzlocal/`)

Install dependencies via:

```sh
pip install pycryptodome ntplib tzlocal
```

## Usage

1. **Clone the repository**  
   ```sh
   git clone https://github.com/your-username/lockbox.git
   cd lockbox
   ```

2. **Run the tool**  
   ```sh
   python lockbox.py
   ```

3. **Choose an operation**  
   - `[1]` to **write** a new lockbox  
     1. Enter expiry date (`DD/MM/YYYY HH:MM:SS`)  
     2. Enter the secret string  
     3. Enter an encryption password  
     4. Enter output filename (must end with `.lb`)  

   - `[2]` to **read** an existing lockbox  
     1. Enter lockbox filename (must end with `.lb`)  
     2. Enter decryption password  

## Examples

```console
$ python lockbox.py
- [1] for write  - [2] for read
Choose: 1

Enter expiry date (DD/MM/YYYY HH:MM:SS): 10/05/2025 12:00:00
Enter value to encrypt: SuperSecret123
Enter encryption password: myPassword!
Enter output filename (must end with .lb): secret.lb

Lockbox saved to secret.lb
```

```console
$ python lockbox.py
- [1] for write  - [2] for read
Choose: 2

Enter lockbox filename (must end with .lb): secret.lb
Enter decryption password: myPassword!

Decrypted value: SuperSecret123
```

**Before expiry**:
```console
The timer has not expired yet. Expiration date: 2025-05-10 12:00:00+02:00
```

**Wrong password**:
```console
Incorrect decryption password.
```

**Tampering detected** (e.g. editing the date or ciphertext):
```console
Integrity check failed: file tampered or wrong password.
```

## Security Notes

- **Key management**  
  The security of your secret hinges on keeping your password safe. If you lose it, you will be unable to decrypt your lockbox.

- **Clock integrity**  
  The script relies on an external NTP server to prevent local clock tampering. If NTP is unavailable, decryption will abort for safety.

- **File authenticity**  
  Any manual edits to the `.lb` file—whether to the timestamp or the ciphertext—will be detected by the embedded HMAC and rejected.

- **Storage of lockbox files**  
  Treat `.lb` files like sensitive data—anyone with access **and** your password can decrypt them after expiry.

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.
