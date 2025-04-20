"""
File Handler - Manages the encryption, storage, and indexing of files in a vault.
"""

import hashlib
import json
from pathlib import Path
from typing import Optional
from rich import print
import base64
import hmac

from core.utils.security import secure_delete
from core.vault.index_manager import VaultIndexManager
from core.encryption.service import (
    EncryptionService,
)


def get_encrypted_filename(rel_path: Path, enc_service: EncryptionService) -> str:
    """
    Get the encrypted filename for a given relative path.

    Args:
        rel_path: Relative path of the file
        enc_service: Encryption service instance

    Returns:
        str: Encrypted filename
    """
    # Use the HMAC key to hash the original filename
    filename_hash = hmac.new(
        enc_service.hmac_key, str(rel_path).encode(), hashlib.sha256
    ).digest()
    # Convert to base64url without padding
    return base64.urlsafe_b64encode(filename_hash).decode().rstrip("=") + ".enc"

def encrypt_and_store_file(
    src_path: Path,
    rel_path: Path,
    enc_service: EncryptionService,
    encrypted_dir: Path,
    provider,
    index_manager: VaultIndexManager,
) -> bool:
    """
    Encrypt and store a file in the vault.

    Args:
        src_path: Path to the source file
        rel_path: Relative path of the file in the vault
        enc_service: Encryption service instance
        encrypted_dir: Directory where encrypted files are stored
        provider: Storage provider instance
        index_manager: Index manager instance

    Returns:
        bool: True if file was encrypted and stored successfully
    """
    try:
        # Check if file exists
        if not src_path.exists():
            print(f"[red]❌ File not found: {src_path}[/red]")
            return False

        # Check if file already exists in vault
        file_info = index_manager.get_file_info(rel_path)
        if file_info:
            print(f"[yellow]⚠️ File already exists in vault: {rel_path}[/yellow]")
            return (
                True  # Return True to indicate success since file is already encrypted
            )

        # Read file content
        try:
            content = src_path.read_bytes()
        except Exception as e:
            print(f"[red]❌ Error reading file {src_path}: {str(e)}[/red]")
            return False

        # Get encrypted filename
        encrypted_filename = get_encrypted_filename(rel_path, enc_service)

        # Create directories if they don't exist
        content_dir = encrypted_dir / "content"
        hmac_dir = encrypted_dir / "hmac"
        index_dir = encrypted_dir / "index"
        content_dir.mkdir(parents=True, exist_ok=True)
        hmac_dir.mkdir(parents=True, exist_ok=True)
        index_dir.mkdir(parents=True, exist_ok=True)

        # Create encrypted file path
        enc_path = content_dir / encrypted_filename
        hmac_path = hmac_dir / f"{encrypted_filename}.hmac"

        # Encrypt file
        try:
            enc_service.encrypt_file(str(src_path), str(enc_path), str(hmac_path))
            print(f"[green]✓ File encrypted successfully: {rel_path}[/green]")
        except Exception as e:
            print(f"[red]❌ Error encrypting file {src_path}: {str(e)}[/red]")
            import traceback

            traceback.print_exc()
            return False

        # Update index with encrypted filename
        try:
            index_manager.add_file(rel_path, encrypted_filename, len(content))
        except Exception as e:
            print(f"[red]❌ Error updating index for {rel_path}: {str(e)}[/red]")
            return False

        # Save index
        try:
            index_manager.save(force=True)
            print(f"[green]✓ Index updated for: {rel_path}[/green]")
        except Exception as e:
            print(f"[red]❌ Error saving index: {e}[/red]")
            return False

        # Securely delete original file
        try:
            secure_delete(src_path)
            print(f"[green]✓ Original file deleted: {src_path}[/green]")
        except Exception as e:
            print(f"[yellow]⚠️ Could not delete original file: {e}[/yellow]")
            # Continue anyway as the file is already encrypted

        return True

    except Exception as e:
        import traceback

        print(f"[red]❌ Error encrypting file {src_path}: {str(e)}[/red]")
        traceback.print_exc()
        return False


def extract_file(
    rel_path: Path,
    enc_service: EncryptionService,
    encrypted_dir: Path,
    provider,
    index_manager: VaultIndexManager,
    output_dir: Optional[Path] = None,
) -> Optional[Path]:
    """
    Extract and decrypt a file from the vault.

    Args:
        rel_path: Relative path of the file in the vault
        enc_service: Encryption service instance
        encrypted_dir: Directory where encrypted files are stored
        provider: Storage provider instance
        index_manager: Index manager instance
        output_dir: Optional directory to extract to (defaults to vault root)

    Returns:
        Optional[Path]: Path to the extracted file if successful, None otherwise
    """
    try:
        # Get encrypted filename from index
        file_info = index_manager.get_file_info(rel_path)
        if not file_info:
            print(f"[red]❌ File not found in index: {rel_path}[/red]")
            return None

        encrypted_filename = file_info["encrypted_filename"]
        enc_path = encrypted_dir / "content" / encrypted_filename
        hmac_path = encrypted_dir / "hmac" / f"{encrypted_filename}.hmac"

        # Verify HMAC
        if not enc_service.verify_hmac(enc_path, hmac_path.read_bytes()):
            print(f"[red]❌ HMAC verification failed for: {rel_path}[/red]")
            return None

        # Create output directory if needed
        if output_dir is None:
            output_dir = encrypted_dir.parent
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create output path
        output_path = output_dir / rel_path

        # Decrypt file
        enc_service.decrypt_file(enc_path, output_path)

        return output_path

    except Exception as e:
        print(f"[red]❌ Error extracting file {rel_path}: {str(e)}[/red]")
        return None


def update_vault_file_count(vault_dir: Path, delta: int) -> None:
    """
    Update the file count in the vault metadata.

    Args:
        vault_dir: Path to the vault directory
        delta: Change in file count (positive for additions, negative for removals)
    """
    try:
        meta_path = vault_dir / "keys" / "vault-meta.json"
        if meta_path.exists():
            with open(meta_path, "r") as f:
                metadata = json.load(f)

            # Update file count, ensuring it doesn't go below 0
            current_count = metadata.get("file_count", 0)
            new_count = max(0, current_count + delta)
            metadata["file_count"] = new_count

            with open(meta_path, "w") as f:
                json.dump(metadata, f, indent=2)
    except Exception as e:
        print(
            f"[yellow]⚠️ Warning: Could not update file count in metadata: {e}[/yellow]"
        )
