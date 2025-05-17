# Lockbox

A command-line tool to securely encrypt and time-lock **files** in a `.lb` (lockbox) container. The tool supports encrypting any file, embeds the original filename and extension, and releases the decrypted file only after a user-specified expiry date. Encryption and integrity checks rely on strong, battle-tested cryptographic primitives.

## Features

- **Expiry-based release**  
  Embeds a cleartext expiry timestamp in the file header and decrypts the file only once the system clock (queried via NTP) has reached or passed that timestamp.

- **File encryption**
  - Accepts a file path as input, encodes the file’s binary content in Base64, and packages it with the original filename and extension.
  - Upon decryption, reconstructs and writes the original file content to disk.

- **Automatic output naming**  
  Derives the `.lb` output filename automatically from the input filename (e.g., `document.pdf` → `document.lb`), preventing accidental overwrites.

- **Decryption to file**  
  After expiry, the tool writes the decrypted data to a new file named `<original_name>_decrypted.<extension>` (e.g., `document_decrypted.pdf`).

- **Tamper-resistant timestamp & contents**
  - Fetches the current time from an NTP server (`ntp1.inrim.it`) to prevent local clock manipulation.
  - Computes an HMAC-SHA256 over `expiry_date || encrypted_blob` so that any edits to the timestamp or ciphertext are detected and rejected.

- **Strong cryptography**
  - AES-CBC with PKCS#7 padding and a fresh random IV per file.
  - Keys derived from the user password via SHA-256 (one key for encryption, one for HMAC).

## Prerequisites

- Python 3.6+
- `pycryptodome`
- `ntplib`
- `tzlocal`

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
  - **[1] Write a new lockbox**
    1. Enter expiry date (`DD/MM/YYYY HH:MM:SS`)
    2. Enter the **path** to the file to encrypt
    3. Enter an encryption password
    - The `.lb` file is saved alongside the input file, named `<input_base>.lb`.

  - **[2] Read (decrypt) an existing lockbox**
    1. Enter the lockbox filename (with or without `.lb` extension)
    2. Enter the decryption password
    - If the current time ≥ expiry date, the original file is restored to `<input_base>_decrypted.<extension>`.

  - **[3] Exit** – quits the program.

## Examples

```console
$ python lockbox.py
- [1] for write  - [2] for read  - [3] for exit
Choose: 1

Enter expiry date (DD/MM/YYYY HH:MM:SS): 25/05/2025 09:00:00
Enter path to file to encrypt: ./report.pdf
Enter encryption password: myPassword!

Lockbox saved to report.lb
```

```console
$ python lockbox.py
- [1] for write  - [2] for read  - [3] for exit
Choose: 2

Enter lockbox filename: report.lb
Enter decryption password: myPassword!

Integrity check successful.
File decrypted and saved to 'report_decrypted.pdf'
```

## Security Notes

- **Key management**  
  The password is the sole means of decryption. Losing it means permanent loss of access.

- **Clock integrity**  
  Operations rely on a trusted NTP server; if unable to fetch NTP time, actions are aborted for safety.

- **File authenticity**  
  Any edits to the `.lb` file—whether to the timestamp or ciphertext—are detected by the embedded HMAC and rejected.

- **Storage of lockbox files**  
  Treat `.lb` files as sensitive data—anyone with both the file and the password can decrypt them after expiry.

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
