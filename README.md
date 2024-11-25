# Cryptone

A Python-based command-line tool for encrypting and decrypting files using both symmetric and asymmetric encryption methods. ***Ensures the security and privacy of your sensitive data.***

## Features

- **Symmetric Encryption**: Use a password to encrypt and decrypt files with AES-CBC encryption.
- **Asymmetric Encryption**: Use RSA keys to encrypt files for sharing or secure storage.
- **Key Generation**: Automatically generate RSA key pairs for asymmetric encryption.
- **Cross-Platform**: Works on Windows, macOS, and Linux.

---

## Prerequisites

- Python 3.7 or later
- `pip` for installing dependencies

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/skravco/cryptone.git
   cd cryptone
   ```

2. Set up a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate      # For Linux/Mac
   venv\Scripts\activate         # For Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

### Symmetric Encryption

Symmetric encryption uses a password for encrypting and decrypting files.

#### Encrypt a File
```bash
python3 cryptone.py symmetric encrypt --file <file_path> --password <your_password>
```

Example:
```bash
python3 cryptone.py symmetric encrypt --file myfile.txt --password mypassword
```
Output:
- Encrypted file: `myfile.txt.enc`

#### Decrypt a File
```bash
python3 cryptone.py symmetric decrypt --file <file_path> --password <your_password>
```

Example:
```bash
python3 cryptone.py symmetric decrypt --file myfile.txt.enc --password mypassword
```
Output:
- Decrypted file: `myfile.dec`

---

### Asymmetric Encryption

Asymmetric encryption uses a pair of RSA keys (private and public). The public key encrypts the file, and the private key decrypts it.

#### Generate RSA Keys
To generate a pair of RSA keys:
```bash
python3 cryptone.py asymmetric generate-keys --private-key <private_key_path> --public-key <public_key_path>
```

Example:
```bash
python3 cryptone.py asymmetric generate-keys --private-key private.pem --public-key public.pem
```
Output:
- `private.pem` - Private key
- `public.pem` - Public key

#### Encrypt a File
Encrypt a file using the public key:
```bash
python3 cryptone.py asymmetric encrypt --file <file_path> --public-key <public_key_path>
```

Example:
```bash
python3 cryptone.py asymmetric encrypt --file myfile.txt --public-key public.pem
```
Output:
- Encrypted file: `myfile.txt.enc`

#### Decrypt a File
Decrypt a file using the private key:
```bash
python3 cryptone.py asymmetric decrypt --file <file_path> --private-key <private_key_path>
```

Example:
```bash
python3 cryptone.py asymmetric decrypt --file myfile.txt.enc --private-key private.pem
```
Output:
- Decrypted file: `myfile.dec`

---

## File Format Details

### Symmetric Encryption
- The encrypted file contains:
  1. **Salt** (16 bytes)
  2. **IV** (16 bytes)
  3. **Ciphertext**

### Asymmetric Encryption
- The encrypted file contains the ciphertext encrypted with the RSA public key.

---

## Example Workflow

### Encrypt and Decrypt with Symmetric Encryption
1. Encrypt a file:
   ```bash
   python3 pwn.py symmetric encrypt --file secrets.txt --password strongpassword
   ```
   Output:
   - Encrypted file: `secrets.txt.enc`

2. Decrypt the file:
   ```bash
   python3 pwn.py symmetric decrypt --file secrets.txt.enc --password strongpassword
   ```
   Output:
   - Decrypted file: `secrets.dec`

---

### Encrypt and Decrypt with Asymmetric Encryption
1. Generate RSA keys:
   ```bash
   python3 pwn.py asymmetric generate-keys --private-key private.pem --public-key public.pem
   ```

2. Encrypt a file:
   ```bash
   python3 pwn.py asymmetric encrypt --file report.txt --public-key public.pem
   ```
   Output:
   - Encrypted file: `report.txt.enc`

3. Decrypt the file:
   ```bash
   python3 pwn.py asymmetric decrypt --file report.txt.enc --private-key private.pem
   ```
   Output:
   - Decrypted file: `report.dec`

---

## Security Notes

- Keep your **private key** and **passwords** secure. Losing them will make decryption impossible.
- Do not share your private key; only the public key should be distributed for encryption.

---

## Troubleshooting

- **Error: File and public key path are required for encryption.**
  Ensure you specify both `--file` and `--public-key` when using `encrypt` with asymmetric encryption.

- **Error: Decryption failed. Invalid padding or password.**
  Ensure you are using the correct password for symmetric decryption or the correct private key for asymmetric decryption.

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---