from pathlib import Path
from uuid import uuid4
import json
import typer
import getpass

from core.utils import console

def find_existing_vaults(keys_dir: Path):
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
            meta_file = vault_path / "vaultic_meta.json"
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text())
                    vaults.append((vault_path.name, meta))
                except:
                    pass  # Skip if meta file is invalid
    
    return vaults

def create_vault(linked: bool) -> str:
    """
    Create a vault subfolder in `.vaultic/keys/`, either linked to the master passphrase or independent.

    Args:
        linked (bool): Whether the vault is linked to the main passphrase or not.
        
    Returns:
        str: The ID of the created vault.
    """
    keys_dir = Path(".vaultic/keys")
    keys_dir.mkdir(parents=True, exist_ok=True)

    vault_id = uuid4().hex[:12]
    vault_path = keys_dir / vault_id
    vault_path.mkdir(parents=True, exist_ok=True)

    if linked:
        # Check if there are any existing vaults
        existing_vaults = find_existing_vaults(keys_dir)
        main_vault = None
        
        if not existing_vaults:
            # No existing vaults, need to create a main vault first
            console.print("[yellow]⚠️ No existing vaults found. Creating a main vault first.[/yellow]")
            
            # Use getpass for secure passphrase entry
            passphrase = getpass.getpass("Enter a passphrase for the main vault: ")
            passphrase_confirm = getpass.getpass("Confirm passphrase: ")
            
            if passphrase != passphrase_confirm:
                console.print("[red]❌ Passphrases do not match.[/red]")
                raise typer.Exit(1)
            
            # Create main vault
            main_vault_id = uuid4().hex[:12]
            main_vault_path = keys_dir / main_vault_id
            main_vault_path.mkdir(parents=True, exist_ok=True)
            
            # Use the entered passphrase to initialize the main vault
            from core.encryption.service import EncryptionService
            enc = EncryptionService(passphrase, main_vault_path / "vaultic_meta.json")
            enc.create_meta_test_file()
            
            console.print(f"[green]✅ Created main vault:[/green] {main_vault_id}")
            main_vault = main_vault_id
            main_meta_path = main_vault_path / "vaultic_meta.json"
            main_meta = json.loads(main_meta_path.read_text())
        else:
            # Let user select which vault to link to
            console.print("[blue]Select a vault to link to:[/blue]")
            for i, (v_id, meta) in enumerate(existing_vaults):
                linked_status = "🔗 Linked" if meta.get("linked", False) else "🔑 Main"
                console.print(f"{i+1}. {v_id} ({linked_status})")
            
            selection = typer.prompt("Enter number", type=int, default=1)
            if selection < 1 or selection > len(existing_vaults):
                console.print("[red]❌ Invalid selection.[/red]")
                raise typer.Exit(1)
            
            main_vault = existing_vaults[selection-1][0]
            main_meta_path = keys_dir / main_vault / "vaultic_meta.json"
            main_meta = json.loads(main_meta_path.read_text())
            
            # Verify the passphrase for the selected vault
            passphrase = getpass.getpass("Enter passphrase for selected vault: ")
            try:
                from core.encryption.service import EncryptionService
                enc = EncryptionService(passphrase, keys_dir / main_vault / "vaultic_meta.json")
                enc.verify_passphrase()
                console.print("[green]✅ Passphrase verified.[/green]")
            except Exception as e:
                console.print(f"[red]❌ Invalid passphrase: {str(e)}[/red]")
                raise typer.Exit(1)
        
        # Now create the linked vault with the same salt as the main vault
        meta = {
            "linked": True,
            "main_vault": main_vault,
            "salt": main_meta.get("salt", ""),  # Copy salt from main vault
            "pepper_hash": main_meta.get("pepper_hash", ""),  # Copy pepper hash if exists
            "version": 1
        }
        (vault_path / "vaultic_meta.json").write_text(json.dumps(meta, indent=2))
        
        # Create the test file for the linked vault using the same passphrase
        from core.encryption.service import EncryptionService
        enc = EncryptionService(passphrase, vault_path / "vaultic_meta.json")
        enc.create_meta_test_file()
        
        console.print(f"[green]✅ Created linked vault:[/green] {vault_id}")
        console.print(f"[blue]🔗 Linked to:[/blue] {main_vault}")
    else:
        # Independent vault with its own passphrase - use getpass for secure entry
        passphrase = getpass.getpass("Enter a new passphrase: ")
        passphrase_confirm = getpass.getpass("Confirm passphrase: ")
        
        if passphrase != passphrase_confirm:
            console.print("[red]❌ Passphrases do not match.[/red]")
            raise typer.Exit(1)
        
        from core.encryption.service import EncryptionService
        enc = EncryptionService(passphrase, vault_path / "vaultic_meta.json")
        enc.create_meta_test_file()
        console.print(f"[green]✅ Created independent vault:[/green] {vault_id}")

    console.print(f"[cyan]🔑 Vault path:[/cyan] {vault_path / 'vaultic_meta.json'}")
    
    return vault_id