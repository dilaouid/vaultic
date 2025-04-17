"""
Encryption Service - Provides secure file encryption and decryption using AES.
"""
import hashlib
import hmac
import json
import os
import base64
import zlib
from typing import Optional
from pathlib import Path
from rich import print

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from core.config import Config

# Get the pepper from environment variable or generate a secure default
# Each installation will have its own unique pepper for additional security
DEFAULT_PEPPER = os.urandom(32).hex()
PEPPER = os.getenv('VAULTIC_PEPPER', DEFAULT_PEPPER).encode()

# Magic header for identifying Vaultic encrypted files
MAGIC_HEADER = b"VAULTICv1\n"

class EncryptionService:
    """
    EncryptionService handles file encryption and decryption using Fernet (AES-256) symmetric encryption,
    enhanced with compression and HMAC integrity checking.
    Keys are securely derived from passphrases using PBKDF2HMAC with an additional pepper.
    """

    def __init__(self, passphrase: str, meta_path: Path):
        """
        Initialize the encryption service with a passphrase and metadata file.
        """
        self.meta_path = Path(meta_path).expanduser()
        
        # Store the passphrase (keep as string for now)
        self.passphrase_str = passphrase
        self.meta = self._load_or_create_metadata()
        self.salt = self.meta["salt"]
        
        # Derive keys
        self.key = self._derive_key("ENCRYPT")
        self.hmac_key = self._derive_key("HMAC")
        self.fernet = Fernet(self.key)
        
        # Create a copy of the test content for verification
        self.test_content = b"vaultic-test"
        
        # For new vaults, create the test file
        if self._is_new:
            print("New vault detected, creating test file...")
            self.create_meta_test_file()


    def _secure_clear_passphrase(self):
        """
        Attempt to clear the passphrase from memory.
        This is not foolproof due to Python's memory management,
        but provides an additional security measure.
        """
        # Overwrite with random data before deletion
        if hasattr(self, 'passphrase'):
            for i in range(len(self.passphrase)):
                self.passphrase = os.urandom(len(self.passphrase))
            del self.passphrase

    def _derive_key(self, purpose: str) -> bytes:
        """
        Derive a secure encryption key using PBKDF2HMAC with an additional pepper.
        """
        print(f"[yellow]Deriving key for purpose: {purpose}[/yellow]")
        
        # Convert passphrase to bytes if it's a string
        if isinstance(self.passphrase_str, str):
            passphrase_bytes = self.passphrase_str.encode('utf-8')
        else:
            passphrase_bytes = self.passphrase_str

        # Convert salt to bytes
        salt = bytes.fromhex(self.salt)

        # Add the pepper
        peppered_passphrase = passphrase_bytes + PEPPER + purpose.encode()

        # Create KDF
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390_000,
            backend=default_backend()
        )

        # Derive key
        derived_key = kdf.derive(peppered_passphrase)
        encoded_key = base64.urlsafe_b64encode(derived_key)

        return encoded_key

    def _save_metadata(self):
        """Save the current metadata to the metadata file."""
        self.meta_path.write_text(json.dumps(self.meta, indent=2))

    def encrypt_bytes(self, data: bytes, output_path: str, hmac_path: str) -> None:
        """
        Encrypt raw bytes, write to encrypted file, and write HMAC.

        Args:
            data (bytes): The data to encrypt
            output_path (str): Path to write the encrypted content
            hmac_path (str): Path to write the HMAC
        """
        # Compress data before encryption for better storage efficiency
        compressed_content = zlib.compress(data, level=9)

        # Encrypt the compressed data
        encrypted = self.fernet.encrypt(compressed_content)

        # Write encrypted data with magic header
        Path(output_path).write_bytes(MAGIC_HEADER + encrypted)

        # Generate and write HMAC for integrity verification
        tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()
        Path(hmac_path).write_bytes(tag)

    def encrypt_file(self, input_path: str, output_path: str, hmac_path: Optional[str] = None):
        """
        Encrypt and compress a file, then write the result and its HMAC.

        Args:
            input_path (str): Path to the plaintext input file
            output_path (str): Path to save the encrypted file
            hmac_path (Optional[str]): Optional custom path for the HMAC file
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        hmac_path = Path(hmac_path) if hmac_path else output_path.with_suffix(output_path.suffix + ".hmac")

        # Read the original file
        original_content = input_path.read_bytes()

        # Compress the content
        compressed_content = zlib.compress(original_content, level=9)

        # Encrypt the compressed content
        encrypted = self.fernet.encrypt(compressed_content)

        # Write encrypted data with magic header
        output_path.write_bytes(MAGIC_HEADER + encrypted)

        # Generate and write HMAC for integrity verification
        tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()
        hmac_path.write_bytes(tag)

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Decrypt and decompress a file after verifying its HMAC.

        Args:
            input_path (str): Path to the encrypted file
            output_path (str): Path to save the decrypted file

        Raises:
            ValueError: If HMAC integrity check fails or magic header is missing
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        hmac_path = input_path.with_suffix(input_path.suffix + ".hmac")

        # Read the encrypted file
        encrypted = input_path.read_bytes()

        # Verify magic header to ensure this is a Vaultic encrypted file
        if not encrypted.startswith(MAGIC_HEADER):
            raise ValueError("Invalid or missing Vaultic magic header")

        # Remove magic header before decryption
        encrypted = encrypted[len(MAGIC_HEADER):]

        # Verify file integrity with HMAC
        if not hmac_path.exists():
            raise ValueError("Missing HMAC file for integrity check")

        expected_tag = hmac_path.read_bytes()
        actual_tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()

        if not hmac.compare_digest(expected_tag, actual_tag):
            raise ValueError("HMAC mismatch: file integrity compromised")

        # Decrypt and decompress
        decrypted_compressed = self.fernet.decrypt(encrypted)
        original_content = zlib.decompress(decrypted_compressed)

        # Write the decrypted file
        output_path.write_bytes(original_content)
        print(f"[green]✅ Decrypted to:[/green] {output_path}")

    def _load_or_create_metadata(self) -> dict:
        """
        Loads or creates metadata containing the salt.

        Returns:
            dict: Metadata with salt and version.
        """
        if self.meta_path.exists():
            print(f"Loading existing metadata from: {self.meta_path}")
            try:
                with open(self.meta_path, 'r') as f:
                    metadata = json.load(f)
                    print(f"Loaded metadata: {metadata}")
                    
                # Check if salt exists
                if 'salt' not in metadata:
                    print("WARNING: No salt found in metadata, adding it")
                    salt = os.urandom(16).hex()
                    metadata['salt'] = salt

                # Add pepper hash for security validation
                pepper_hash = hashlib.sha256(PEPPER).hexdigest()
                metadata['pepper_hash'] = pepper_hash

                # Save metadata
                with open(self.meta_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                self._is_new = False
                return metadata
            except Exception as e:
                print(f"Error loading metadata: {str(e)}")

        # Create new metadata with random salt
        print("Creating new metadata")
        salt = os.urandom(16).hex()
        pepper_hash = hashlib.sha256(PEPPER).hexdigest()

        meta = {
            "salt": salt, 
            "pepper_hash": pepper_hash,
            "version": 1,
            "created_at": __import__('time').time()
        }

        self.meta_path.parent.mkdir(parents=True, exist_ok=True)
        self.meta_path.write_text(json.dumps(meta, indent=2))
        print(f"Created metadata with salt: {salt}")
        self._is_new = True
        return meta

    def create_meta_test_file(self):
        """Create an encrypted test file for passphrase validation."""
        test_path = self.meta_path.parent / ".meta-test"
        test_data = self.test_content
        print(f"Creating test file at: {test_path}")

        # Encrypt and store
        encrypted = self.fernet.encrypt(test_data)
        print(f"Encrypted test data: {encrypted[:20]}...")
        test_path.write_bytes(encrypted)
        print(f"Test file created with size: {len(encrypted)} bytes")

    def verify_passphrase(self):
        """
        Verify the correctness of the passphrase.

        Raises:
            ValueError: If the passphrase is incorrect or metadata is corrupted
        """
        test_path = self.meta_path.parent / ".meta-test"
        print(f"Verifying passphrase using test file: [yellow]{test_path}[/yellow]")

        if not test_path.exists():
            print(f"[red]Test file not found at: {test_path}[/red]")
            raise ValueError("Missing .meta-test file for verification")

        try:
            encrypted = test_path.read_bytes()
            
            try:
                decrypted = self.fernet.decrypt(encrypted)
                
                if decrypted != self.test_content:
                    print(f"[red]Content mismatch. Expected: {self.test_content}, Got: {decrypted}[/red]")
                    raise ValueError("Corrupted .meta-test file - content doesn't match")
                    
                print(f"[green]✅ Passphrase verification successful![/green]")
            except Exception as e:
                print(f"Error during decryption: {str(e)}")
                raise
                
        except Exception as e:
            print(f"Exception during verification: {type(e).__name__}: {str(e)}")
            raise ValueError(f"Invalid passphrase or corrupted metadata: {str(e)}")
        
        # Now that verification is complete, we can clear the passphrase
        self._secure_clear_passphrase()
