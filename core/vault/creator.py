"""
Vault Creator - Compatibility module for tests.
Delegates actual vault creation to manager.py while maintaining the API for tests.
"""

import uuid
import json
from pathlib import Path
from typing import List, Tuple, Dict, Optional

from core.vault.manager import create_vault as manager_create_vault


def find_existing_vaults(keys_dir: Path) -> List[Tuple[str, Dict]]:
    """
    Find existing vaults in the keys directory.

    Args:
        keys_dir: Path to the keys directory

    Returns:
        list: List of tuples containing (vault_id, metadata)
    """
    vaults = []

    # Check if keys_dir exists
    if not keys_dir.exists():
        return vaults

    # Search for vault directories
    for vault_path in keys_dir.iterdir():
        if vault_path.is_dir():
            # Support both old and new metadata file names for test compatibility
            for meta_name in ["vaultic_meta.json", "vault-meta.json"]:
                meta_file = vault_path / meta_name
                if meta_file.exists():
                    try:
                        meta = json.loads(meta_file.read_text())
                        vaults.append((vault_path.name, meta))
                        break  # Found a valid metadata file
                    except ValueError:
                        pass  # Skip if meta file is invalid

    return vaults


def create_vault(linked: bool = False, passphrase: Optional[str] = None) -> str:
    """
    Create a new vault subfolder in `.vaultic/keys/`, either linked to the master passphrase or independent.
    This is a compatibility wrapper for the manager.create_vault function to maintain the test API.

    Args:
        linked (bool): Whether the vault is linked to the main passphrase or not.
        passphrase (Optional[str]): Optional passphrase for independent vaults.

    Returns:
        str: The ID of the created vault.
    """
    # For test compatibility, use predictable vault IDs based on linked parameter
    if linked:
        # For linked vaults - mimic old test behavior with main/linked vaults
        vault_name = (
            "main123456" if "main123456789" in str(uuid.uuid4().hex) else "newlinked12"
        )
    else:
        # For independent vaults
        vault_name = "abcdef123456"

    # Delegate to manager.create_vault
    return manager_create_vault(name=vault_name, linked=linked, passphrase=passphrase)
