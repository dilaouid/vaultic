import hashlib
import hmac
import json
import os
import base64
import zlib
from typing import Optional
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from core.utils import console

MAGIC_HEADER = b"VAULTICv1\n"
class EncryptionService:
    """
    EncryptionService handles file encryption and decryption using Fernet (AES) symmetric encryption,
    enhanced with compression and HMAC integrity checking.
    Keys are securely derived from passphrases using PBKDF2HMAC.
    """

    def __init__(self, passphrase: str, meta_path: Path):
        """
        Initializes the encryption service with a passphrase and metadata file.

        Args:
            passphrase (str): User-supplied passphrase for key derivation.
            meta_path (Path): Path to metadata file containing salt.
        """
        self.meta_path = Path(meta_path).expanduser()
        self.passphrase = passphrase.encode()
        self.meta = self._load_or_create_metadata()
        self.salt = self.meta["salt"]
        self.key = self._derive_key("ENCRYPT")
        self.hmac_key = self._derive_key("HMAC")
        self.fernet = Fernet(self.key)

    def _derive_key(self, purpose: str) -> bytes:
        """
        Derives a secure encryption key using PBKDF2HMAC.

        Args:
            purpose (str): Specific purpose for key derivation ("ENCRYPT" or "HMAC").

        Returns:
            bytes: Derived encryption key.
        """
        salt = bytes.fromhex(self.salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390_000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(self.passphrase + purpose.encode()))
    
    def encrypt_bytes(self, data: bytes, output_path: str, hmac_path: str) -> None:
        """
        Encrypts raw bytes, writes to encrypted file, and writes HMAC.

        Args:
            data (bytes): The data to encrypt.
            output_path (str): Path to write the encrypted content.
            hmac_path (str): Path to write the HMAC.
        """

        compressed_content = zlib.compress(data, level=9)
        encrypted = self.fernet.encrypt(compressed_content)

        Path(output_path).write_bytes(MAGIC_HEADER + encrypted)

        tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()
        Path(hmac_path).write_bytes(tag)

        console.print(f"[cyan]🔏 HMAC saved:[/cyan] {hmac_path}")


    def encrypt_file(self, input_path: str, output_path: str, hmac_path: Optional[str] = None):
        """
        Encrypts and compresses a file, then writes the result and its HMAC.

        Args:
            input_path (str): Path to the plaintext input file.
            output_path (str): Path to save the encrypted file.
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        hmac_path = Path(hmac_path) if hmac_path else output_path.with_suffix(output_path.suffix + ".hmac")

        original_content = input_path.read_bytes()
        compressed_content = zlib.compress(original_content, level=9)

        encrypted = self.fernet.encrypt(compressed_content)
        output_path.write_bytes(MAGIC_HEADER + encrypted)

        tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()
        hmac_path.write_bytes(tag)
        console.print(f"[cyan]🔏 HMAC saved:[/cyan] {hmac_path}")

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Decrypts and decompresses a file after verifying its HMAC.

        Args:
            input_path (str): Path to the encrypted file.
            output_path (str): Path to save the decrypted file.

        Raises:
            ValueError: If HMAC integrity check fails or magic header is missing.
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        hmac_path = input_path.with_suffix(input_path.suffix + ".hmac")

        encrypted = input_path.read_bytes()

        if not encrypted.startswith(MAGIC_HEADER):
            raise ValueError("Invalid or missing Vaultic magic header")

        encrypted = encrypted[len(MAGIC_HEADER):]

        if not hmac_path.exists():
            raise ValueError("Missing HMAC file for integrity check")

        expected_tag = hmac_path.read_bytes()
        actual_tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()

        if not hmac.compare_digest(expected_tag, actual_tag):
            raise ValueError("HMAC mismatch: file integrity compromised")

        decrypted_compressed = self.fernet.decrypt(encrypted)
        original_content = zlib.decompress(decrypted_compressed)

        output_path.write_bytes(original_content)
        console.print(f"[green]✅ Decrypted and decompressed:[/green] {output_path}")

    def _load_or_create_metadata(self) -> dict:
        """
        Loads or creates metadata containing the salt.

        Returns:
            dict: Metadata with salt and version.
        """
        if self.meta_path.exists():
            return json.loads(self.meta_path.read_text())

        salt = os.urandom(16).hex()
        meta = {"salt": salt, "version": 1}
        self.meta_path.parent.mkdir(parents=True, exist_ok=True)
        self.meta_path.write_text(json.dumps(meta))
        return meta

    def create_meta_test_file(self):
        """
        Creates an encrypted test file for passphrase validation.
        """
        test_path = self.meta_path.parent / ".meta-test"
        test_data = b"vaultic-test"
        encrypted = self.fernet.encrypt(test_data)
        test_path.write_bytes(encrypted)

    def verify_passphrase(self):
        """
        Verifies the correctness of the passphrase.

        Raises:
            ValueError: If the passphrase is incorrect or metadata is corrupted.
        """
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
            raise ValueError("Invalid passphrase or mismatched salt.")