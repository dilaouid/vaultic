import hashlib
import hmac
import json
import os
import base64
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from core.utils import console
from core.encryption.key_derivation import load_or_generate_key_via_passphrase

class EncryptionService:
    """
    A service class for encrypting and decrypting files using symmetric encryption (Fernet/AES).

    This class manages a local symmetric key, allowing for file-level encryption
    and decryption with consistent and secure storage of the key file.
    """

    def __init__(self, passphrase: str, meta_path: Path):
        """
        Initializes the EncryptionService.

        Args:
            key_path (str): Path to the symmetric encryption key file (.key).
        """
        self.meta_path = Path(meta_path).expanduser()
        self.passphrase = passphrase.encode()
        self.meta = self.load_or_create_metadata()
        self.salt = self.meta["salt"]
        self.key = self.derive_key("ENCRYPT")
        self.hmac_key = self.derive_key("HMAC")
        self.fernet = Fernet(self.key)

    @staticmethod
    def generate_key() -> bytes:
        """
        Generates a new symmetric encryption key using Fernet (AES-128 under the hood).

        Returns:
            bytes: The newly generated encryption key.
        """
        return Fernet.generate_key()
    
    def derive_key(self, purpose: str) -> bytes:
        salt = bytes.fromhex(self.meta["salt"])
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390_000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(self.passphrase + purpose.encode()))

    def save_key(self, key: bytes) -> None:
        """
        Saves the encryption key to the key file path.

        Args:
            key (bytes): The encryption key to save.
        """
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.key_path, 'wb') as f:
            f.write(key)

    def load_key(self) -> bytes:
        """
        Loads the encryption key from the key file.

        Returns:
            bytes: The loaded encryption key.
        """
        with open(self.key_path, 'rb') as f:
            return f.read()

    def load_or_create_key(self) -> bytes:
        """
        Loads the encryption key if it exists, or creates and saves a new one if not.

        Returns:
            bytes: The encryption key.
        """
        if self.key_path.exists():
            if self.key_path.suffix == ".pem":
                return self.load_key()  # legacy Fernet key file
            else:
                return load_or_generate_key_via_passphrase()
        else:
            return load_or_generate_key_via_passphrase()


    def encrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Encrypts a file and writes the encrypted content to a new file.

        Args:
            input_path (str): Path to the original (plaintext) file.
            output_path (str): Path where the encrypted file will be saved.
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        hmac_path = output_path.with_suffix(output_path.suffix + ".hmac")

        content = input_path.read_bytes()
        encrypted = self.fernet.encrypt(content)
        output_path.write_bytes(encrypted)

        # 🔐 Generate the HMAC of the encrypted file
        tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()
        hmac_path.write_bytes(tag)
        console.print(f"[cyan]🔏 HMAC saved:[/cyan] {hmac_path}")

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Decrypts an encrypted file and writes the decrypted content to a new file.

        Args:
            input_path (str): Path to the encrypted input file.
            output_path (str): Path where the decrypted file will be saved.
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        hmac_path = input_path.with_suffix(input_path.suffix + ".hmac")

        encrypted = input_path.read_bytes()

        # ✅ Check HMAC
        if not hmac_path.exists():
            raise ValueError("Missing HMAC file for integrity check")

        expected_tag = hmac_path.read_bytes()
        actual_tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()

        if not hmac.compare_digest(expected_tag, actual_tag):
            raise ValueError("HMAC mismatch: file may have been tampered with")

        decrypted = self.fernet.decrypt(encrypted)
        output_path.write_bytes(decrypted)
        console.print(f"[green]✅ Decrypted with verified integrity:[/green] {output_path}")

    def load_or_create_metadata(self) -> dict:
        if self.meta_path.exists():
            return json.loads(self.meta_path.read_text())

        salt = os.urandom(16).hex()
        meta = {"salt": salt, "version": 1}
        self.meta_path.parent.mkdir(parents=True, exist_ok=True)
        self.meta_path.write_text(json.dumps(meta))
        return meta
    
    def create_meta_test_file(self):
        test_path = self.meta_path.parent / ".meta-test"
        test_data = b"vaultic-test"
        encrypted = self.fernet.encrypt(test_data)
        test_path.write_bytes(encrypted)

    def verify_passphrase(self):
        test_path = self.meta_path.parent / ".meta-test"
        if not test_path.exists():
            self.create_meta_test_file()
            return
        try:
            encrypted = test_path.read_bytes()
            decrypted = self.fernet.decrypt(encrypted)
            if decrypted != b"vaultic-test":
                raise ValueError("Corrupted .meta-test")
        except Exception:
            raise ValueError("❌ Invalid passphrase or mismatched salt. Decryption test failed.")
