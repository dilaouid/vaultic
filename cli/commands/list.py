"""
List Command - List files and vaults in the system.
"""

import typer
from rich import print
from rich.table import Table
from rich.console import Console
from getpass import getpass
from typing import Optional
import time
import traceback

from core.vault.manager import list_vaults, get_vault_path
from core.encryption.service import EncryptionService
from core.vault.index_manager import VaultIndexManager

app = typer.Typer()


@app.command("vaults")
def list_vaults_cmd():
    """
    List all available vaults.

    The command will prompt for a passphrase to decrypt index files for accurate file counts.
    """
    from getpass import getpass

    # Ask for passphrase securely (won't appear in terminal history)
    passphrase = None
    try:
        passphrase = getpass("🔑 Enter vault passphrase (or press Enter to skip): ")
        # Allow empty input to skip decryption
        if passphrase == "":
            passphrase = None
            print(
                "[yellow]Skipping index decryption. File counts may not be accurate.[/yellow]"
            )
    except KeyboardInterrupt:
        print(
            "\n[yellow]Passphrase input cancelled. Using metadata file counts.[/yellow]"
        )
        passphrase = None

    # Always get vaults list, even if passphrase is None or there's an error
    vaults = list_vaults(passphrase=passphrase)

    if not vaults:
        print(
            "[yellow]No vaults found. Create one with 'vaultic create vault'.[/yellow]"
        )
        return

    # Always display the table
    console = Console()
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Created")
    table.add_column("Files", justify="right")
    table.add_column("Status", justify="center")  # New column for decryption status
    table.add_column("Path", style="dim")

    for vault in vaults:
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(vault["created_at"]))

        # Set status indicator based on decryption status
        status = "[green]✓[/green]" if vault["decrypted"] else "[red]![/red]"

        # Format file count
        file_count = str(vault["file_count"])
        if not vault["decrypted"] and passphrase and vault["file_count"] == 0:
            # If we tried to decrypt but failed and count is 0, mark it specially
            file_count = "[yellow]" + file_count + "[/yellow]"

        table.add_row(
            vault["id"],
            vault.get("name", vault["id"]),
            created,
            file_count,
            status,
            vault["path"],
        )

    console.print(table)

    # Add legend if passphrase was provided
    if passphrase:
        print("\n[green]✓[/green] = Index successfully decrypted")
        print("[red]![/red] = Failed to decrypt index, counts may be inaccurate")


@app.command("files")
def list_files_cmd(
    vault_id: str = typer.Argument(..., help="ID of the vault to list files from"),
    passphrase: Optional[str] = typer.Option(
        None, help="Vault passphrase (will be prompted if not provided)"
    ),
):
    """
    List all files in a vault with their metadata.

    This command displays files, sizes, and timestamps for a specific vault.
    The vault passphrase is required to decrypt the index.
    """
    vault_path = get_vault_path(vault_id)

    if not vault_path.exists():
        print(f"[red]Vault not found: {vault_id}[/red]")
        raise typer.Exit(1)

    meta_path = vault_path / "keys" / "vault-meta.json"
    if not meta_path.exists():
        print(f"[red]Metadata not found for vault: {vault_id}[/red]")
        raise typer.Exit(1)

    # Print debug info about the vault path
    print(f"[blue]Vault path: {vault_path}[/blue]")
    print(f"[blue]Metadata path: {meta_path}[/blue]")

    # Check for encrypted index
    encrypted_dir = vault_path / "encrypted"
    encrypted_index_path = encrypted_dir / "content" / "index.json.enc"
    encrypted_hmac_path = encrypted_dir / "hmac" / "index.json.enc.hmac"

    # Legacy index path (for error messages only)
    legacy_index_path = encrypted_dir / "index.json"

    # Delete legacy index if found
    if legacy_index_path.exists():
        try:
            legacy_index_path.unlink()
            print(
                f"[green]✅ Removed legacy unencrypted index: {legacy_index_path}[/green]"
            )
        except Exception as e:
            print(f"[yellow]⚠️ Warning: Could not delete legacy index: {e}[/yellow]")

    if encrypted_index_path.exists():
        print(f"[blue]Size: {encrypted_index_path.stat().st_size} bytes[/blue]")
    else:
        print("[yellow]Encrypted index file not found. Vault may be empty.[/yellow]")

    # Try using encrypted index
    if encrypted_index_path.exists() and encrypted_hmac_path.exists():
        print("[green]Found encrypted index.[/green]")

        # Need passphrase for encrypted index
        if not passphrase:
            passphrase = getpass("🔑 Enter vault passphrase: ")

        # Initialize encryption service and verify passphrase
        try:
            enc_service = EncryptionService(passphrase, meta_path)
            enc_service.verify_passphrase()

            # Load encrypted index
            index_manager = VaultIndexManager(enc_service, vault_path)

            try:
                print("[blue]Loading encrypted index...[/blue]")
                index = index_manager.load()
                files_found = len(index)

            except Exception as e:
                print(f"[red]❌ Error decrypting index: {str(e)}[/red]")
                print(f"[red]Traceback: {traceback.format_exc()}[/red]")
                print("[red]No index available. Vault may be empty or damaged.[/red]")
                raise typer.Exit(1)

        except Exception as e:
            print(f"[red]❌ Invalid passphrase or corrupted metadata: {str(e)}[/red]")
            raise typer.Exit(1)

    else:
        print(f"[yellow]No index found for vault: {vault_id}[/yellow]")
        print(
            f"[blue]This vault appears to be empty. Add files to {vault_path} to encrypt them.[/blue]"
        )
        raise typer.Exit(0)

    # Display results
    if files_found == 0:
        print(f"[yellow]No files in vault: {vault_id}[/yellow]")
        print(f"[blue]Add files to {vault_path} to encrypt them.[/blue]")
        return

    console = Console()
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Filename")
    table.add_column("Size", justify="right")
    table.add_column("Encrypted", justify="center")
    table.add_column("Last Modified")

    for filepath, file_info in index.items():
        size = file_info.get("size", 0)
        size_str = f"{size:,} bytes"

        if size > 1024 * 1024:
            size_str = f"{size/(1024*1024):.1f} MB"
        elif size > 1024:
            size_str = f"{size/1024:.1f} KB"

        timestamp = file_info.get("timestamp", 0)
        date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))

        table.add_row(filepath, size_str, "✓", date_str)

    console.print(table)
    print(f"[green]Total: {files_found} file(s)[/green]")
