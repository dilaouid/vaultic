import json
import hashlib
from pathlib import Path

from core.encryption.service import EncryptionService

def encrypt_index(index_data: dict, enc_service: EncryptionService, encrypted_dir: Path):
    """
    Encrypts and stores the Vaultic index data as an in-memory object.

    Args:
        index_data (dict): Dictionary containing index mappings.
        enc_service (EncryptionService): Active encryption service.
        encrypted_dir (Path): Base encrypted directory (contains content/ and hmac/).
    """
    # Serialize the index to JSON bytes
    index_bytes = json.dumps(index_data, indent=2).encode("utf-8")

    hashed_index = hashlib.sha256(b"index.json").hexdigest() + ".enc"
    content_path = encrypted_dir / "content" / hashed_index
    hmac_path = encrypted_dir / "hmac" / (hashed_index + ".hmac")

    enc_service.encrypt_bytes(index_bytes, str(content_path), str(hmac_path))