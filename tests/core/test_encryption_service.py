import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from pathlib import Path

class EncryptionService:
    """
    A service class for encrypting and decrypting files using symmetric encryption (Fernet/AES).

    This class manages a local symmetric key, allowing for file-level encryption
    and decryption with consistent and secure storage of the key file.
    """

    def __init__(self, key_path: str, password: str = None):
        """
        Initializes the EncryptionService.

        Args:
            key_path (str): Path to the symmetric encryption key file (.key).
            password (str, optional): Passphrase to derive the encryption key. Overrides stored key.
        """
        self.key_path = Path(key_path).expanduser()
        self.password = password
        self.key = self.load_or_create_key()
        self.fernet = Fernet(self.key)

    @staticmethod
    def generate_key() -> bytes:
        """
        Generates a new symmetric encryption key using Fernet (AES-128 under the hood).

        Returns:
            bytes: The newly generated encryption key.
        """
        return Fernet.generate_key()

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes) -> bytes:
        """
        Derives a Fernet-compatible key from a password using Scrypt.

        Args:
            password (str): The passphrase.
            salt (bytes): A unique salt.

        Returns:
            bytes: A 32-byte base64-encoded key.
        """
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def save_key(self, key: bytes, salt: bytes = None) -> None:
        """
        Saves the encryption key to the key file path.

        Args:
            key (bytes): The encryption key to save.
            salt (bytes, optional): Optional salt to prepend.
        """
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.key_path, 'wb') as f:
            if salt:
                f.write(salt + b'\n' + key)
            else:
                f.write(key)

    def load_key(self) -> bytes:
        """
        Loads the encryption key from the key file.

        Returns:
            bytes: The loaded encryption key.
        """
        with open(self.key_path, 'rb') as f:
            data = f.read()

        if self.password:
            salt, encoded_key = data.split(b'\n', 1)
            return self.derive_key_from_password(self.password, salt)
        return data

    def load_or_create_key(self) -> bytes:
        """
        Loads the encryption key if it exists, or creates and saves a new one if not.

        Returns:
            bytes: The encryption key.
        """
        if self.key_path.exists():
            return self.load_key()

        if self.password:
            salt = os.urandom(16)
            derived = self.derive_key_from_password(self.password, salt)
            self.save_key(derived, salt)
            return derived

        key = self.generate_key()
        self.save_key(key)
        return key

    def encrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Encrypts a file and writes the encrypted content to a new file.

        Args:
            input_path (str): Path to the original (plaintext) file.
            output_path (str): Path where the encrypted file will be saved.
        """
        with open(input_path, 'rb') as file:
            encrypted = self.fernet.encrypt(file.read())
        with open(output_path, 'wb') as file:
            file.write(encrypted)

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Decrypts an encrypted file and writes the decrypted content to a new file.

        Args:
            input_path (str): Path to the encrypted input file.
            output_path (str): Path where the decrypted file will be saved.
        """
        with open(input_path, 'rb') as file:
            decrypted = self.fernet.decrypt(file.read())
        with open(output_path, 'wb') as file:
            file.write(decrypted)