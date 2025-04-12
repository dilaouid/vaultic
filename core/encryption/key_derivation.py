from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode
from pathlib import Path
from getpass import getpass
import os
import json

DEFAULT_META_PATH = Path(".vaultic/keys/vaultic_meta.json")
PBKDF2_ITERATIONS = 390_000
KEY_SIZE = 32 

def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return urlsafe_b64encode(kdf.derive(passphrase.encode()))

def load_or_generate_key_via_passphrase(meta_path: Path = DEFAULT_META_PATH) -> bytes:
    meta_path.parent.mkdir(parents=True, exist_ok=True)

    if meta_path.exists():
        data = json.loads(meta_path.read_text())
        salt = bytes.fromhex(data["salt"])
    else:
        salt = os.urandom(16)
        meta_path.write_text(json.dumps({
            "salt": salt.hex(),
            "version": 1
        }, indent=2))

    passphrase = getpass("🔐 Enter your Vaultic passphrase: ")
    return derive_key_from_passphrase(passphrase, salt)