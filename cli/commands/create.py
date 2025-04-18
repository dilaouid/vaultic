import typer
from rich import print
from typing import Optional
from getpass import getpass

from core.vault.manager import create_vault

app = typer.Typer()


@app.callback(invoke_without_command=True)
def create_new_vault(
    name: Optional[str] = typer.Option(
        None, "--name", "-n", help="Name for the new vault"
    ),
    linked: bool = typer.Option(
        False, "--linked", "-l", help="Link vault to main passphrase"
    ),
    independent: bool = typer.Option(
        False, "--independent", "-i", help="Use a separate passphrase for this vault"
    ),
):
    """
    Create a new encrypted vault.

    You must specify either --linked or --independent to determine the passphrase method.
    """
    try:
        if linked and independent:
            print(
                "[red]❌ Error:[/red] You can't use both --linked and --independent simultaneously."
            )
            raise typer.Exit(code=1)

        if not linked and not independent:
            print(
                "[red]❌ Error:[/red] You must specify either --linked or --independent."
            )
            raise typer.Exit(code=1)

        # Get custom vault name or use default naming
        vault_name = name

        # If independent, ask for a passphrase
        passphrase = None
        if independent:
            while True:
                passphrase = getpass("🔑 Enter new vault passphrase: ")
                confirm = getpass("🔑 Confirm passphrase: ")

                if passphrase == confirm:
                    break
                print("[red]❌ Passphrases don't match. Try again.[/red]")

        print("[blue]🔐 Creating new vault...[/blue]")
        vault_id = create_vault(name=vault_name, linked=linked, passphrase=passphrase)

        print(f"[green]✅ Vault created successfully:[/green] .vaultic/{vault_id}")
        return vault_id
    except Exception as e:
        print(f"[red]❌ Failed to create vault:[/red] {str(e)}")
        raise typer.Exit(code=1)
