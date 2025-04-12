from pathlib import Path
from cryptography.fernet import Fernet

key_path = Path(".vaultic/keys/vaultic_key.pem")
key_path.parent.mkdir(parents=True, exist_ok=True)

if not key_path.exists():
    key = Fernet.generate_key()
    key_path.write_bytes(key)
    print(f"✅ Fernet key generated at {key_path}")
else:
    print(f"ℹ️ Fernet key already exists at {key_path}")