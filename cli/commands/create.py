import typer
from rich import print
from core.vault.creator import create_vault

app = typer.Typer()

@app.callback(invoke_without_command=True)
def create_new_vault(
    linked: bool = typer.Option(False, "--linked", help="Attach vault to main passphrase"),
    independent: bool = typer.Option(False, "--independent", help="Use a new passphrase for this vault"),
):
    """
    Create a new vault. Either linked to the main passphrase, or independent with its own passphrase.
    """
    try:
        if linked and independent:
            print("[red]❌ You can't use both --linked and --independent at the same time.[/red]")
            raise typer.Exit(code=1)
            
        if not linked and not independent:
            print("[red]❌ You must specify either --linked or --independent.[/red]")
            raise typer.Exit(code=1)
            
        print("[blue]🔐 Creating new vault...[/blue]")
        result = create_vault(linked=linked)
        
        print(f"[green]✅ Vault created successfully:[/green] {result}")
        
    except Exception as e:
        print(f"[red]❌ Failed to create vault:[/red] {str(e)}")
        raise typer.Exit(1)