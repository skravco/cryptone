import os
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives import padding as sym_padding
from base64 import b64encode, b64decode


# Helper function for deriving symmetric encryption keys from a password
def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derives a symmetric key using PBKDF2 (Password-Based Key Derivation Function 2).
    :param password: The input password to derive the key.
    :param salt: The salt to make the key unique.
    :param length: Length of the derived key (default: 32 bytes).
    :return: Derived key as bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA-256 for the key derivation
        length=length,  # Desired key length
        salt=salt,  # Salt for the derivation
        iterations=100000,  # Iteration count for better security
        backend=default_backend(),  # Cryptographic backend
    )
    return kdf.derive(password.encode())


# Symmetric Encryption Class
class SymmetricEncryptor:
    """
    Handles symmetric encryption and decryption using AES-CBC with PKCS7 padding.
    """

    def __init__(self, password: str):
        """
        Initialize with a password to derive the encryption key.
        """
        self.password = password
        self.salt = os.urandom(16)  # Generate a random salt
        self.key = derive_key(password, self.salt)  # Derive the encryption key

    def encrypt(self, file_path: str):
        """
        Encrypts a file using the symmetric key.
        :param file_path: Path to the file to encrypt.
        """
        with open(file_path, "rb") as f:
            plaintext = f.read()  # Read the file's content

        iv = os.urandom(16)  # Generate a random Initialization Vector (IV)
        cipher = Cipher(
            algorithms.AES(self.key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Add PKCS7 padding to the plaintext to make it a multiple of the block size
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Perform the encryption
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Write the encrypted file, prepending the salt and IV
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as f:
            f.write(self.salt + iv + ciphertext)  # Save salt, IV, and ciphertext

        print(f"File encrypted: {encrypted_file_path}")

    def decrypt(self, file_path: str):
        """
        Decrypts a file using the symmetric key.
        :param file_path: Path to the file to decrypt.
        """
        with open(file_path, "rb") as f:
            file_content = f.read()  # Read the encrypted file content

        # Extract the salt, IV, and ciphertext
        salt = file_content[:16]  # First 16 bytes: salt
        iv = file_content[16:32]  # Next 16 bytes: IV
        ciphertext = file_content[32:]  # Remaining: ciphertext

        # Derive the decryption key using the extracted salt
        key = derive_key(self.password, salt)

        # Set up the AES cipher in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Perform the decryption
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        try:
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError:
            print("Decryption failed. Invalid padding or password.")
            return

        # Save the decrypted file
        decrypted_file_path = file_path.replace(".enc", ".dec")
        with open(decrypted_file_path, "wb") as f:
            f.write(plaintext)

        print(f"File decrypted: {decrypted_file_path}")


# Asymmetric Encryption Class
class AsymmetricEncryptor:
    """
    Handles asymmetric encryption and decryption using RSA.
    """

    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self, private_key_path: str, public_key_path: str):
        """
        Generates a pair of RSA keys and saves them to files.
        :param private_key_path: Path to save the private key.
        :param public_key_path: Path to save the public key.
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,  # Commonly used public exponent
            key_size=2048,  # Key size in bits
            backend=default_backend(),
        )
        self.public_key = self.private_key.public_key()

        # Save private key to a file
        with open(private_key_path, "wb") as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save public key to a file
        with open(public_key_path, "wb") as f:
            f.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

        print(f"Keys generated: {private_key_path}, {public_key_path}")

    def encrypt(self, file_path: str, public_key_path: str):
        """
        Encrypts a file using a public RSA key.
        :param file_path: Path to the file to encrypt.
        :param public_key_path: Path to the public key file.
        """
        # Load the public key from the file
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

        with open(file_path, "rb") as f:
            plaintext = f.read()  # Read plaintext file

        # Encrypt the plaintext with RSA
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Write the ciphertext to a file
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as f:
            f.write(ciphertext)

        print(f"File encrypted: {encrypted_file_path}")

    def decrypt(self, file_path: str, private_key_path: str):
        """
        Decrypts a file using a private RSA key.
        :param file_path: Path to the file to decrypt.
        :param private_key_path: Path to the private key file.
        """
        # Load the private key from the file
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

        with open(file_path, "rb") as f:
            ciphertext = f.read()  # Read ciphertext

        # Decrypt the ciphertext with RSA
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Write the plaintext to a file
        decrypted_file_path = file_path.replace(".enc", ".dec")
        with open(decrypted_file_path, "wb") as f:
            f.write(plaintext)

        print(f"File decrypted: {decrypted_file_path}")


# Command-Line Interface
def main():
    """
    Command-line interface for encryption and decryption.
    """
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt files using symmetric or asymmetric encryption."
    )
    subparsers = parser.add_subparsers(dest="command")

    # Symmetric encryption parser
    sym_parser = subparsers.add_parser(
        "symmetric", help="Symmetric encryption operations"
    )
    sym_parser.add_argument(
        "operation", choices=["encrypt", "decrypt"], help="Operation to perform"
    )
    sym_parser.add_argument("file", help="File to encrypt/decrypt")
    sym_parser.add_argument(
        "--password", required=True, help="Password for encryption/decryption"
    )

    # Asymmetric encryption parser
    asym_parser = subparsers.add_parser(
        "asymmetric", help="Asymmetric encryption operations"
    )
    asym_parser.add_argument(
        "operation",
        choices=["encrypt", "decrypt", "generate-keys"],
        help="Operation to perform",
    )
    asym_parser.add_argument(
        "--file", help="File to encrypt/decrypt (not required for generate-keys)"
    )
    asym_parser.add_argument("--private-key", help="Path to private key file")
    asym_parser.add_argument("--public-key", help="Path to public key file")

    args = parser.parse_args()

    if args.command == "symmetric":
        sym_encryptor = SymmetricEncryptor(args.password)
        if args.operation == "encrypt":
            sym_encryptor.encrypt(args.file)
        elif args.operation == "decrypt":
            sym_encryptor.decrypt(args.file)
    elif args.command == "asymmetric":
        asym_encryptor = AsymmetricEncryptor()
        if args.operation == "generate-keys":
            if not args.private_key or not args.public_key:
                print("Private and public key paths are required for key generation.")
                return
            asym_encryptor.generate_keys(args.private_key, args.public_key)
        elif args.operation == "encrypt":
            if not args.file or not args.public_key:
                print("File and public key path are required for encryption.")
                return
            asym_encryptor.encrypt(args.file, args.public_key)
        elif args.operation == "decrypt":
            if not args.file or not args.private_key:
                print("File and private key path are required for decryption.")
                return
            asym_encryptor.decrypt(args.file, args.private_key)


if __name__ == "__main__":
    main()
