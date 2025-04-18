"""
List Command - View vaults and their contents.
"""
import typer
import json
import time
from rich import print
from rich.table import Table

from core.vault.manager import list_vaults, get_vault_path

# Main "list" command group
app = typer.Typer(name="list", help="List vaults or files inside vaults.")

# Subcommand: vaultic list vaults
@app.command("vaults")
def list_vaults_command():
    """
    List all available vaults.
    """
    vaults = list_vaults()

    if not vaults:
        print("[yellow]No vaults found.[/yellow]")
        print("[blue]Create one with:[/blue] vaultic create --linked")
        raise typer.Exit()

    table = Table(title="Vaultic Encrypted Vaults")
    table.add_column("ID", style="cyan")
    table.add_column("Files", style="green")
    table.add_column("Created", style="yellow")
    table.add_column("Mode", style="blue")
    table.add_column("Path", style="dim")

    for vault in vaults:
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(vault["created_at"]))
        mode = "Linked" if vault["linked"] else "Independent"

        table.add_row(
            vault["id"],
            str(vault["file_count"]),
            created,
            mode,
            vault["path"]
        )

    print(table)
    print("\n[blue]Use 'vaultic list files <vault-id>' to view files in a specific vault.[/blue]")

# Subcommand: vaultic list files <vault-id>
@app.command("files")
def list_files(
    vault_id: str = typer.Argument(..., help="ID of the vault to list files from"),
    show_hashes: bool = typer.Option(False, "--hashes", "-h", help="Show file hash identifiers")
):
    """
    List files in a specific vault.
    """
    vault_path = get_vault_path(vault_id)

    if not vault_path.exists():
        print(f"[red]Vault not found:[/red] {vault_id}")
        raise typer.Exit()

    index_path = vault_path / "index.json"

    if not index_path.exists():
        print(f"[yellow]No files in vault:[/yellow] {vault_id}")
        raise typer.Exit()

    try:
        with open(index_path, 'r') as f:
            index_data = json.load(f)
    except json.JSONDecodeError:
        print(f"[red]Invalid index file for vault:[/red] {vault_id}")
        raise typer.Exit()

    if not index_data:
        print(f"[yellow]No files in vault:[/yellow] {vault_id}")
        raise typer.Exit()

    table = Table(title=f"Files in Vault: {vault_id}")
    table.add_column("Filename", style="cyan")
    table.add_column("Size", style="green")
    table.add_column("Modified", style="yellow")

    if show_hashes:
        table.add_column("Hash", style="dim")

    # Sort files by timestamp (newest first)
    sorted_files = sorted(
        [(path, info) for path, info in index_data.items()],
        key=lambda x: x[1].get("timestamp", 0),
        reverse=True
    )

    for path, info in sorted_files:
        if path.startswith(".") or path == ".vaultic.lock":
            continue

        size = format_size(info.get("size", 0))
        timestamp = time.strftime(
            "%Y-%m-%d %H:%M",
            time.localtime(info.get("timestamp", 0))
        )

        if show_hashes:
            table.add_row(path, size, timestamp, info.get("hash", ""))
        else:
            table.add_row(path, size, timestamp)

    print(table)
    print(f"\n[green]Total Files:[/green] {len(sorted_files)}")
    print(f"[blue]To restore a file:[/blue] vaultic restore {vault_id} <filename>")

def format_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"