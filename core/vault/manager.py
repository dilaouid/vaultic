"""
Vault Manager - Core functionality for creating, selecting, and managing Vaultic vaults.
"""

import json
import uuid
import time
from rich import print
from pathlib import Path
from typing import Optional, Tuple, Dict, List

from core.encryption.service import EncryptionService
from core.config import Config


def get_vaults_directory() -> Path:
    """Returns the base directory where vaults are stored."""
    return Path(".vaultic")


def get_vault_path(vault_id: str) -> Path:
    """Returns the path to a specific vault directory."""
    return get_vaults_directory() / vault_id


def create_vault(
    name: Optional[str] = None, linked: bool = False, passphrase: Optional[str] = None
) -> str:
    """
    Create a new encrypted vault with the specified parameters.
    """
    # Create a unique vault ID if name is not provided
    vault_id = name or f"vault-{int(time.time())}-{uuid.uuid4().hex[:8]}"

    # Ensure base directories exist
    vault_root = get_vaults_directory()
    vault_root.mkdir(parents=True, exist_ok=True)

    vault_dir = vault_root / vault_id
    vault_dir.mkdir(parents=True, exist_ok=True)

    keys_dir = vault_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    # Create metadata file
    meta_path = keys_dir / "vault-meta.json"

    # Create metadatas according to salt
    metadata = {
        "vault_id": vault_id,
        "created_at": time.time(),
        "linked": linked,
        "file_count": 0,  # Initialize file count as metadata
        "config": {"backup_provider": Config.PROVIDER},
    }

    # Write init metadatas
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    # Init encryptonservice (will add salt to metadatas)
    enc_service = EncryptionService(passphrase or Config.DEFAULT_PASSPHRASE, meta_path)

    # Create folder structure
    (vault_dir / "encrypted").mkdir(parents=True, exist_ok=True)
    (vault_dir / "encrypted" / "content").mkdir(parents=True, exist_ok=True)
    (vault_dir / "encrypted" / "hmac").mkdir(parents=True, exist_ok=True)

    # Create file test for encryption
    enc_service.create_meta_test_file()

    # Create an encrypted index using VaultIndexManager
    from core.vault.index_manager import VaultIndexManager

    index_manager = VaultIndexManager(enc_service, vault_dir)
    index_manager.save(force=True)

    # Create README file
    readme_content = (
        f"# Vault: {vault_id}\n\n"
        "This is a Vaultic encrypted vault. Place files here to encrypt them automatically.\n\n"
        "- Files will be encrypted with AES-256 and stored in the 'encrypted' directory\n"
        "- Original files will be securely deleted after encryption\n"
        "- Do not modify the 'keys' or 'encrypted' directories manually\n"
    )
    (vault_dir / "README.md").write_text(readme_content)

    return vault_id


def list_vaults(passphrase: Optional[str] = None) -> List[Dict]:
    """
    List all available vaults with their metadata.

    Args:
        passphrase: Optional passphrase to decrypt encrypted indexes for accurate file counts

    Returns:
        List[Dict]: List of vault information dictionaries.
        Each dict contains an additional 'decrypted' boolean field indicating if the index was successfully decrypted.
    """
    vaults = []
    vault_root = get_vaults_directory()

    if not vault_root.exists():
        return vaults

    # Disable standard output if passphrase is provided to hide encryption messages
    original_print = None
    if passphrase:
        import builtins

        original_print = builtins.print
        builtins.print = lambda *args, **kwargs: None

    try:
        for vault_dir in vault_root.iterdir():
            if not vault_dir.is_dir() or vault_dir.name.startswith("."):
                continue

            meta_path = vault_dir / "keys" / "vault-meta.json"
            if not meta_path.exists():
                continue

            try:
                with open(meta_path, "r") as f:
                    metadata = json.load(f)

                # Default file count is 0
                file_count = 0
                # Default decryption status is False
                decrypted = False

                # Define index paths
                encrypted_index_path = (
                    vault_dir / "encrypted" / "content" / "index.json.enc"
                )
                encrypted_hmac_path = (
                    vault_dir / "encrypted" / "hmac" / "index.json.enc.hmac"
                )
                legacy_index_path = vault_dir / "encrypted" / "index.json"

                # Try to get accurate file count from encrypted index if it exists and passphrase is provided
                if (
                    passphrase
                    and encrypted_index_path.exists()
                    and encrypted_hmac_path.exists()
                ):
                    try:
                        from core.encryption.service import EncryptionService
                        from core.vault.index_manager import VaultIndexManager

                        # Try to decrypt the index with the provided passphrase
                        enc_service = EncryptionService(passphrase, meta_path)

                        # Verify passphrase silently
                        try:
                            enc_service.verify_passphrase()

                            # If valid, load and count entries in the index
                            index_manager = VaultIndexManager(enc_service, vault_dir)
                            index = index_manager.load()
                            file_count = len(index)
                            decrypted = True  # Mark as successfully decrypted
                        except Exception:
                            # Passphrase verification failed, will fall back to legacy or metadata
                            pass
                    except Exception:
                        # Decryption failed, will fall back to legacy or metadata
                        pass

                # If we couldn't get file count from encrypted index, fall back to legacy index
                if file_count == 0 and legacy_index_path.exists():
                    try:
                        with open(legacy_index_path, "r") as f:
                            index = json.load(f)
                            file_count = len(index)
                            decrypted = True  # Legacy index is not encrypted, treat as "decrypted"
                    except Exception:
                        # If legacy index can't be read, fall back to metadata
                        file_count = metadata.get("file_count", 0)
                # If no file count from indexes, use metadata
                elif file_count == 0:
                    file_count = metadata.get("file_count", 0)

                vaults.append(
                    {
                        "id": vault_dir.name,
                        "name": metadata.get("name", vault_dir.name),
                        "created_at": metadata.get("created_at", 0),
                        "linked": metadata.get("linked", False),
                        "file_count": file_count,
                        "decrypted": decrypted,  # Add decryption status to the result
                        "path": str(vault_dir),
                    }
                )
            except Exception as e:
                if original_print:
                    original_print(
                        f"[yellow]⚠️ Error reading vault metadata for {vault_dir.name}: {str(e)}[/yellow]"
                    )
    finally:
        # Restore original print function
        if original_print:
            import builtins

            builtins.print = original_print

    return vaults


def select_vault(vault_id: Optional[str] = None) -> Tuple[str, Path]:
    """
    Select a vault or prompt the user to choose one if multiple exist.

    Args:
        vault_id: Optional specific vault ID to select.

    Returns:
        Tuple[str, Path]: The selected vault ID and path to its metadata file.
    """
    from rich.prompt import Prompt

    vaults = list_vaults()

    if not vaults:
        raise ValueError("No vaults found. Create one first with 'vaultic create'.")

    if vault_id:
        vault_path = get_vaults_directory() / vault_id
        if vault_path.exists():
            meta_path = vault_path / "keys" / "vault-meta.json"
            if meta_path.exists():
                print(f"Found vault at: {vault_path}")
                print(f"Using metadata: {meta_path}")
                return vault_id, meta_path
            else:
                print(f"Metadata file not found: {meta_path}")
        else:
            print(f"Vault directory not found: {vault_path}")

    # If only one vault exists, select it automatically
    if len(vaults) == 1:
        vault = vaults[0]
        meta_path = Path(vault["path"]) / "keys" / "vault-meta.json"
        return vault["id"], meta_path

    # Multiple vaults - prompt user to select one
    print("[blue]Multiple vaults found. Select one:[/blue]")
    for i, vault in enumerate(vaults):
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(vault["created_at"]))
        print(
            f"  [{i+1}] {vault['id']} (Created: {created}, Files: {vault['file_count']})"
        )

    choice = Prompt.ask(
        "Enter vault number", choices=[str(i + 1) for i in range(len(vaults))]
    )
    selected = vaults[int(choice) - 1]
    meta_path = Path(selected["path"]) / "keys" / "vault-meta.json"

    return selected["id"], meta_path
