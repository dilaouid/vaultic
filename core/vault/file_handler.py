import json
import time
import hashlib
from pathlib import Path

from core.utils import console
from core.config import Config
from core.utils.security import secure_delete, is_rotational
from core.utils.dos import register_error
from core.vault.index_writer import encrypt_index


def handle_file(
    src_path: Path,
    rel_path: Path,
    enc_service,
    encrypted_dir: Path,
    provider
):
    """
    Handles encryption, HMAC, upload, secure deletion, and index update of a single file.

    Args:
        src_path (Path): The full path of the original file.
        rel_path (Path): The relative path from the vault root.
        enc_service (EncryptionService): The encryption service.
        encrypted_dir (Path): The .vaultic/encrypted/<subfolder> path.
        provider: The storage provider instance.
    """
    hashed_name = hashlib.sha256(str(rel_path).encode()).hexdigest() + ".enc"
    content_dir = encrypted_dir / "content"
    hmac_dir = encrypted_dir / "hmac"
    content_dir.mkdir(parents=True, exist_ok=True)
    hmac_dir.mkdir(parents=True, exist_ok=True)

    encrypted_path = content_dir / hashed_name
    hmac_path = hmac_dir / (hashed_name + ".hmac")
    file_size = src_path.stat().st_size

    if encrypted_path.exists():
        from core.config import Config
        import typer
        if Config.OVERWRITE_EXISTING == "no":
            console.print(f"[yellow]↪ Already encrypted: {hashed_name}, skipping.[/yellow]")
            return
        elif Config.OVERWRITE_EXISTING == "ask":
            confirm = typer.confirm(f"❓ Overwrite '{hashed_name}'?", default=False)
            if not confirm:
                console.print(f"[blue]⏩ Skipped:[/blue] {rel_path}")
                return
        console.print(f"[red]⚠ Overwriting existing:[/red] {hashed_name}")

    console.print(f"[yellow]🔐 Encrypting:[/yellow] {rel_path}")
    enc_service.encrypt_file(str(src_path), str(encrypted_path), str(hmac_path))

    console.print(f"☁️  [yellow]Uploading to {Config.PROVIDER}:[/yellow] {rel_path}.enc")
    provider.upload_file(encrypted_path, str(rel_path) + ".enc")

    try:
        if is_rotational(src_path):
            secure_delete(src_path, passes=3)
        else:
            src_path.unlink()
        console.print(f"[grey]🧹 Deleted original: {rel_path}[/grey]")
    except Exception as e:
        console.print(f"[red]⚠️ Failed to delete original file: {e}[/red]")
        register_error()

    # Update encrypted index (in memory → encrypted write)
    index_data = {}
    index_path = encrypted_dir.parent / "index.json"
    if index_path.exists():
        index_data = json.loads(index_path.read_text())

    index_data[str(rel_path)] = {
        "hash": hashed_name,
        "size": file_size,
        "timestamp": time.time()
    }

    encrypt_index(index_data, enc_service, encrypted_dir)