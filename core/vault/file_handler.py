"""
File Handler - Manages the encryption, storage, and indexing of files in a vault.
"""

import hashlib
import os
import json

from rich import print
from pathlib import Path
from typing import Optional
from core.utils.security import secure_delete, is_rotational
from core.utils.dos import register_error
from core.config import Config
from core.vault.index_manager import VaultIndexManager


def encrypt_and_store_file(
    src_path: Path,
    rel_path: Path,
    enc_service,
    encrypted_dir: Path,
    provider,
    index_manager: Optional[VaultIndexManager] = None,
    provider_name: Optional[str] = None,
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
        index_manager: Index manager for encryption (required)
        provider_name: Optional name of the provider for display

    Returns:
        bool: True if operation was successful
    """
    try:
        # First check if file still exists
        if not src_path.exists():
            print(f"[yellow]File no longer exists: {src_path}[/yellow]")
            return False

        # Prepare paths and directories
        hashed_name = hashlib.sha256(str(rel_path).encode()).hexdigest() + ".enc"
        content_dir = encrypted_dir / "content"
        hmac_dir = encrypted_dir / "hmac"
        content_dir.mkdir(parents=True, exist_ok=True)
        hmac_dir.mkdir(parents=True, exist_ok=True)

        encrypted_path = content_dir / hashed_name
        hmac_path = hmac_dir / (hashed_name + ".hmac")
        file_size = src_path.stat().st_size

        # Debug output
        print(f"[blue]Processing file: {rel_path} ({file_size} bytes)[/blue]")
        print(f"[blue]  source: {src_path}[/blue]")
        print(f"[blue]  destination: {encrypted_path}[/blue]")

        # Check if file already exists (using index manager)
        file_exists = False
        if index_manager:
            file_info = index_manager.get_file_info(rel_path)
            file_exists = file_info is not None
            if file_exists:
                print(f"[blue]File exists in index: {rel_path}[/blue]")
        else:
            # Require index_manager - no more legacy support
            print("[red]❌ No index manager provided - cannot process file[/red]")
            return False

        if file_exists:
            if Config.OVERWRITE_EXISTING == "no":
                print(
                    f"[yellow]↪ File already encrypted, skipping:[/yellow] {rel_path}"
                )
                return False

            elif Config.OVERWRITE_EXISTING == "ask":
                import typer

                confirm = typer.confirm(
                    f"❓ File '{rel_path}' already encrypted. Overwrite?", default=False
                )
                if not confirm:
                    print(f"[blue]⏩ Skipped:[/blue] {rel_path}")
                    return False

            print(f"[red]⚠ Overwriting existing file:[/red] {rel_path}")

        # Encrypt the file
        print(f"[yellow]🔐 Encrypting:[/yellow] {rel_path} ({file_size} bytes)")
        enc_service.encrypt_file(str(src_path), str(encrypted_path), str(hmac_path))

        # Verify the encrypted file was created
        if not encrypted_path.exists() or encrypted_path.stat().st_size == 0:
            print("[red]❌ Encryption failed - encrypted file missing or empty[/red]")
            return False

        if not hmac_path.exists():
            print("[red]❌ Encryption failed - HMAC file missing[/red]")
            return False

        # Upload to storage provider
        display_provider = provider_name or getattr(Config, "PROVIDER", "local")
        print(f"☁️  [yellow]Uploading to {display_provider}:[/yellow] {rel_path}.enc")
        provider.upload_file(encrypted_path, str(rel_path) + ".enc")

        # Also upload the HMAC file
        provider.upload_file(hmac_path, str(rel_path) + ".enc.hmac")

        # Update index - must happen BEFORE deleting the original file
        if index_manager:
            index_manager.add_file(rel_path, hashed_name, file_size)
            print(f"[green]✅ Added to encrypted index: {rel_path}[/green]")

            # Update file count in metadata
            update_vault_file_count(encrypted_dir.parent, 1)
        else:
            # This should never happen as we check above
            print("[red]❌ Cannot update index - no index manager provided[/red]")
            return False

        # Delete original securely
        try:
            if is_rotational(src_path):
                secure_delete(src_path, passes=3)
            else:
                os.fsync(src_path)  # Ensure file is fully written to disk
                src_path.unlink()
            print(f"[grey]🧹 Deleted original: {rel_path}[/grey]")
        except Exception as e:
            print(f"[red]⚠️ Failed to delete original file: {e}[/red]")
            register_error()

        # Final verification
        print(f"[green]✅ Successfully encrypted and stored: {rel_path}[/green]")
        return True

    except Exception as e:
        print(f"[red]❌ Error processing file {rel_path}: {str(e)}[/red]")
        register_error()
        return False


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
