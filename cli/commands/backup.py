import typer
from core.config import Config
from core.encryption.service import EncryptionService
from pathlib import Path

app = typer.Typer()

@app.command()
def file(file_path: str):
    enc = EncryptionService(Config.KEY_PATH)
    encrypted_path = str(Path(file_path).with_suffix(".enc"))
    enc.encrypt_file(file_path, encrypted_path)
    print(f"✅ Encrypted: {encrypted_path}")