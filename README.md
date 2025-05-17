# Lockbox

A simple command-line tool to encrypt the **content of a file** and store it in an encrypted “lockbox” file that only becomes readable after a user-specified expiry date. The encryption key is derived from a password you choose at creation time—so **you** are responsible for remembering the key.

## Features

- **File Content Encryption**
  Encrypts the binary content of a chosen file after encoding it in Base64.

- **Expiry-based release**
  Embeds a cleartext expiry timestamp in the file header and will only decrypt once the system clock (queried via NTP) has reached or passed that timestamp.

- **User-supplied encryption key**
  Derives a 256-bit AES key via SHA-256 from the password you enter, avoiding any hard-coded “master” password.

- **AES-CBC with PKCS#7 padding**
  Uses a fresh random IV per file; stores IV prepended to ciphertext.

- **Tamper-resistant timestamp & contents**
    - Fetches current time from an NTP server (`ntp1.inrim.it`) to defeat local clock manipulation.
    - Computes an HMAC-SHA256 over `expiry_date || encrypted_blob` so that any manual edits to the date or ciphertext will be detected and rejected.

- **Automated File Naming**
    - In write mode, the output lockbox file (`.lb`) is automatically named based on the input file's name (e.g., `document.txt` becomes `document.lb`).
    - In read mode, the decrypted file is automatically named using the original filename and extension stored within the lockbox, appending `_decrypted` (e.g., `document_decrypted.txt`).

- **Flexible Lockbox Filename Input**
  The `.lb` extension is automatically added if omitted when specifying the lockbox filename in both write and read modes.

- **Input Validation Loops**
  The program now re-prompts for input if the format is incorrect or the file cannot be accessed (e.g., invalid date, non-existent file path).

## Prerequisites

- Python 3.6+
- [`pycryptodome`](https://pypi.org/project/pycryptodome/)
- [`ntplib`](https://pypi.org/project/ntplib/)
- [`tzlocal`](https://pypi.org/project/tzlocal/)

Install dependencies via:

```sh
pip install pycryptodome ntplib tzlocal