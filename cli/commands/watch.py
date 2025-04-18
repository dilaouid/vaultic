"""
Watch Command - Monitor a vault for changes and automatically encrypt files.
"""

import typer
from rich import print
from getpass import getpass
from typing import Optional

from core.vault.watcher import start_vault_watcher
from core.vault.manager import list_vaults

app = typer.Typer()


@app.callback(invoke_without_command=True)
def watch(
    vault_id: Optional[str] = typer.Argument(
        None, help="ID of the vault to watch (leave empty to select)"
    ),
    passphrase: Optional[str] = typer.Option(
        None,
        "--passphrase",
        "-p",
        help="Vault passphrase (will prompt if not provided)",
    ),
    background: bool = typer.Option(
        False, "--background", "-b", help="Run watcher in background (daemon mode)"
    ),
):
    """
    Watch a vault for new files and encrypt them automatically.

    Files placed in the vault directory will be automatically encrypted,
    indexed, and uploaded to the configured storage provider.
    """
    try:
        # Get vault list
        vaults = list_vaults()

        if not vaults:
            print("[red]❌ No vaults found.[/red]")
            print("[blue]Create one first:[/blue] vaultic create --linked")
            raise typer.Exit(code=1)

        # Get passphrase if not provided
        if passphrase is None:
            passphrase = getpass("🔑 Enter vault passphrase: ")

        # Start watching
        if background:
            # TODO: Implement background/daemon mode
            print("[yellow]⚠️ Background mode not yet implemented.[/yellow]")
            print("[blue]Running in foreground instead.[/blue]")
        print("[green]Starting vault watcher...[/green]")
        start_vault_watcher(vault_id, passphrase)

    except KeyboardInterrupt:
        print("[yellow]🛑 Watcher stopped by user.[/yellow]")
    except Exception as e:
        print(f"[red]❌ Error starting watcher:[/red] {str(e)}")
        raise typer.Exit(code=1)
