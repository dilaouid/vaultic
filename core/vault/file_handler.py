"""
File Handler - Manages the encryption, storage, and indexing of files in a vault.
"""
import json
import time
import hashlib
from pathlib import Path
from typing import Optional

from rich import print
from core.utils.security import secure_delete, is_rotational
from core.utils.dos import register_error
from core.config import Config

def encrypt_and_store_file(
    src_path: Path,
    rel_path: Path,
    enc_service,
    encrypted_dir: Path,
    provider,
    provider_name: Optional[str] = None
) -> bool:
    """
    Handles the full lifecycle of a file:
    1. Encryption with HMAC generation
    2. Upload to storage provider
    3. Secure deletion of original
    4. Index update
    
    Args:
        src_path: Full path to the source file
        rel_path: Path relative to the vault root
        enc_service: Encryption service instance
        encrypted_dir: Path to the encrypted directory 
        provider: Storage provider instance
        provider_name: Optional name of the provider for display
        
    Returns:
        bool: True if operation was successful
    """
    try:
        # Prepare paths and directories
        hashed_name = hashlib.sha256(str(rel_path).encode()).hexdigest() + ".enc"
        content_dir = encrypted_dir / "content"
        hmac_dir = encrypted_dir / "hmac"
        content_dir.mkdir(parents=True, exist_ok=True)
        hmac_dir.mkdir(parents=True, exist_ok=True)

        encrypted_path = content_dir / hashed_name
        hmac_path = hmac_dir / (hashed_name + ".hmac")
        file_size = src_path.stat().st_size

        # Check if file already exists
        if encrypted_path.exists():
            if Config.OVERWRITE_EXISTING == "no":
                print(f"[yellow]↪ File already encrypted, skipping:[/yellow] {rel_path}")
                return False

            elif Config.OVERWRITE_EXISTING == "ask":
                import typer
                confirm = typer.confirm(f"❓ File '{rel_path}' already encrypted. Overwrite?", default=False)
                if not confirm:
                    print(f"[blue]⏩ Skipped:[/blue] {rel_path}")
                    return False

            print(f"[red]⚠ Overwriting existing file:[/red] {rel_path}")

        # Encrypt the file
        print(f"[yellow]🔐 Encrypting:[/yellow] {rel_path} ({file_size} bytes)")
        enc_service.encrypt_file(str(src_path), str(encrypted_path), str(hmac_path))

        # Upload to storage provider
        display_provider = provider_name or getattr(Config, "PROVIDER", "local") 
        print(f"☁️  [yellow]Uploading to {display_provider}:[/yellow] {rel_path}.enc")
        provider.upload_file(encrypted_path, str(rel_path) + ".enc")

        # Update index
        update_file_index(rel_path, hashed_name, file_size, encrypted_dir)

        # Delete original securely
        try:
            if is_rotational(src_path):
                secure_delete(src_path, passes=3)
            else:
                src_path.unlink()
            print(f"[grey]🧹 Deleted original: {rel_path}[/grey]")
        except Exception as e:
            print(f"[red]⚠️ Failed to delete original file: {e}[/red]")
            register_error()

        return True

    except Exception as e:
        print(f"[red]❌ Error processing file {rel_path}: {str(e)}[/red]")
        register_error()
        return False

def update_file_index(rel_path: Path, hashed_name: str, file_size: int, encrypted_dir: Path) -> None:
    """
    Updates the vault's index file with information about a processed file.

    Args:
        rel_path: Relative path of the file within the vault
        hashed_name: Hash-based encrypted filename
        file_size: Size of the original file in bytes
        encrypted_dir: Base directory for encrypted content
    """
    index_data = {}
    index_path = encrypted_dir.parent / "index.json"

    # Load existing index if it exists
    if index_path.exists():
        try:
            with open(index_path, 'r') as f:
                index_data = json.load(f)
        except json.JSONDecodeError:
            print(f"[yellow]⚠️ Invalid index file, creating new one[/yellow]")

    # Update index with file information
    index_data[str(rel_path)] = {
        "hash": hashed_name,
        "size": file_size,
        "timestamp": time.time()
    }

    # Write updated index
    with open(index_path, 'w') as f:
        json.dump(index_data, f, indent=2)

def get_file_metadata(rel_path: Path, encrypted_dir: Path) -> Optional[dict]:
    """
    Gets metadata for a specific file from the index.
    
    Args:
        rel_path: Relative file path to look up
        encrypted_dir: Base directory for encrypted content
        
    Returns:
        Optional[dict]: File metadata or None if not found
    """
    index_path = encrypted_dir.parent / "index.json"

    if not index_path.exists():
        return None

    try:
        with open(index_path, 'r') as f:
            index_data = json.load(f)

        return index_data.get(str(rel_path))
    except Exception:
        return None