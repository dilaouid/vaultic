from pathlib import Path
from typing import Tuple
import questionary
import uuid

from core.utils import console

def list_existing_vaults(keys_dir: Path) -> list[Path]:
    """
    List all vault metadata files in the given directory.

    Args:
        keys_dir (Path): The .vaultic/keys/ directory.

    Returns:
        List[Path]: List of vaultic_meta.json files.
    """
    return sorted(keys_dir.glob("*/vaultic_meta.json"))

def create_new_vault(keys_dir: Path) -> Path:
    """
    Creates a new vault with a unique subfolder name.

    Args:
        keys_dir (Path): The .vaultic/keys/ directory.

    Returns:
        Path: Path to the created vaultic_meta.json
    """
    new_id = uuid.uuid4().hex[:12]
    new_vault_dir = keys_dir / new_id
    new_vault_dir.mkdir(parents=True, exist_ok=True)
    return new_vault_dir / "vaultic_meta.json"

def select_or_create_vault(keys_dir: Path) -> Tuple[str, Path]:
    """
    Select an existing vault or create a new one.

    Args:
        keys_dir (Path): Path to the .vaultic/keys directory.

    Returns:
        Tuple[str, Path]: A tuple of subfolder name and path to vaultic_meta.json.
    """
    vaults = list_existing_vaults(keys_dir)

    if not vaults:
        console.print("[yellow]⚠ No vaults found. Creating a new vault…[/yellow]")
        meta_path = create_new_vault(keys_dir)
        subfolder = meta_path.parent.name
        return subfolder, meta_path

    if len(vaults) == 1:
        return vaults[0].parent.name, vaults[0]

    choices = [v.parent.name for v in vaults]
    selected = questionary.select(
        "🔐 Choose a vault:",
        choices=choices
    ).ask()

    if not selected:
        raise Exception("Vault selection was cancelled.")

    return selected, keys_dir / selected / "vaultic_meta.json"