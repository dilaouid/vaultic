import typer
import getpass
from pathlib import Path
from rich import print
from typing import Optional
from core.vault.selector import select_or_create_vault
from core.vault.watcher import start_vaultic_watcher

app = typer.Typer()

@app.callback(invoke_without_command=True)
def watch_vault(
    vault_id: Optional[str] = typer.Option(None, "--vault", "-v", help="Specific vault ID to watch (skips selection)")
):
    """
    Start a file system watcher that automatically encrypts files.
    
    This command monitors a directory for changes and automatically encrypts
    new or modified files, uploading them to the configured storage provider.
    """
    try:
        # Initialize vault directory
        vault_dir = Path(".vaultic")
        keys_dir = vault_dir / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        
        # If a specific vault ID is provided, use it directly
        if vault_id:
            meta_path = keys_dir / f"{vault_id}.meta"
            if not meta_path.exists():
                print(f"[red]❌ Vault with ID '{vault_id}' not found.[/red]")
                raise typer.Exit(1)
            print(f"[green]🔒 Using vault:[/green] {vault_id}")
        else:
            # Otherwise, let the user select a vault
            print("[blue]🔍 Selecting vault for watching...[/blue]")
            subfolder, meta_path = select_or_create_vault(keys_dir)
            print(f"[green]🔒 Starting watcher for vault:[/green] {subfolder}")

        # Get passphrase securely - never include it as a command line argument
        passphrase = getpass.getpass("Enter passphrase: ")
        
        # Start the watcher with the selected meta_path
        # This avoids double selection since we're passing the meta_path
        start_vaultic_watcher(passphrase=passphrase, meta_path=meta_path)
        
    except KeyboardInterrupt:
        print("\n[yellow]⚠️ Watcher stopped by user[/yellow]")
        
    except Exception as e:
        print(f"[red]❌ Error starting watcher:[/red] {str(e)}")
        raise typer.Exit(1)