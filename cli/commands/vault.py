import typer
from core.vault.watcher import process_vault_dir

app = typer.Typer(help="Vault Mode: encrypt everything inside .vaultic/")

@app.command("encrypt")
def encrypt_vault_dir(
    dry_run: bool = typer.Option(False, help="Simulate the encryption process without modifying files")
):
    """
    Encrypt all files found in the .vaultic/ directory.
    """
    process_vault_dir(dry_run=dry_run)