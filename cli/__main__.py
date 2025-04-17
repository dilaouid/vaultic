"""
Vaultic Command Line Interface - Main entry point.
"""
import typer
from rich import print
from pathlib import Path
import pkg_resources

from cli.commands import create, config, list, restore, watch, backup

app = typer.Typer(
    name="vaultic",
    help="Encrypted incremental backup tool with cloud storage support",
    no_args_is_help=True
)

# Register command modules
app.add_typer(create.app, name="create", help="Create a new vault")
app.add_typer(config.app, name="config", help="Configure Vaultic settings")
app.add_typer(list.app, name="list", help="List vaults and their contents")
app.add_typer(restore.app, name="restore", help="Restore files from a vault")
app.add_typer(watch.app, name="watch", help="Watch a vault for changes")
app.add_typer(backup.app, name="backup", help="Backup files and directories")

@app.callback()
def main():
    """
    🧾 Vaultic - Encrypted Incremental Backups
    
    A secure backup tool that encrypts your files locally
    before uploading them to cloud storage.
    """
    # Ensure .vaultic directory exists
    Path(".vaultic").mkdir(exist_ok=True)

@app.command("version")
def version():
    """
    Show Vaultic version information.
    """
    try:
        version = pkg_resources.get_distribution("vaultic").version
    except pkg_resources.DistributionNotFound:
        version = "development"
        
    print(f"[blue]🧾 Vaultic[/blue] version [green]{version}[/green]")
    print("[dim]https://github.com/vaultic-org/vaultic[/dim]")

if __name__ == "__main__":
    app()