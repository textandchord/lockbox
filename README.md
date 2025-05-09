# Lockbox

A simple command-line tool to store an arbitrary secret string in an encrypted “lockbox” file that only becomes readable after a user-specified expiry date. The encryption key is derived from a password you choose at creation time—so **you** are responsible for remembering the key.

## Features

- **Expiry-based release**  
  The tool embeds a cleartext expiry timestamp in the file header and will only decrypt once the system clock (queried via NTP) has reached or passed that timestamp.

- **User-supplied encryption key**  
  Derives a 256-bit AES key via SHA-256 from the password you enter, avoiding any hard-coded “master” password.

- **AES-CBC with PKCS#7 padding**  
  Uses a fresh random IV per file; stores IV prepended to ciphertext.

- **Tamper-resistant timestamp**  
  Fetches current time from an NTP server (`ntp1.inrim.it`) to defeat local clock manipulation.

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
     - Enter expiry date (`DD/MM/YYYY HH:MM:SS`)  
     - Enter the secret string  
     - Enter an encryption password  
     - Enter output filename (e.g. `mysecret.lb`)  

   - `[2]` to **read** an existing lockbox  
     - Enter lockbox filename  
     - Enter decryption password  

## Example

```console
$ python lockbox.py
- [1] for write  - [2] for read
Choose: 1

Enter expiry date (DD/MM/YYYY HH:MM:SS): 10/05/2025 12:00:00
Enter value to encrypt: SuperSecret123
Enter encryption password: myPassword!
Enter output filename (e.g. name.lb): secret.lb

Lockbox saved to secret.lb
```

```console
$ python lockbox.py
- [1] for write  - [2] for read
Choose: 2

Enter lockbox filename: secret.lb
Enter decryption password: myPassword!

Decrypted value: SuperSecret123
```

If you try to read before the expiry date, you’ll see:

```console
The timer has not expired yet. Expiration date: 2025-05-10 12:00:00+02:00
```

And if you supply the wrong password:

```console
Incorrect decryption password.
```

## Security Notes

- **Key management**  
  The security of your secret hinges on keeping your password safe. If you lose it, you will be unable to decrypt your lockbox.

- **Clock integrity**  
  The script relies on an external NTP server to prevent local clock tampering. If NTP is unavailable, decryption may fail or be delayed.

- **Storage of lockbox files**  
  Treat `.lb` files like sensitive data—anyone with access **and** your password can decrypt them after expiry.

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.
