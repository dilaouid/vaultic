import typer
from pathlib import Path
from rich import print
from core.config import Config
from core.encryption.service import EncryptionService
from core.storage.factory import get_provider

app = typer.Typer()

@app.command("file")
def restore_file(
    filename: str = typer.Argument(..., help="Relative path to the original file (ex: Folder/image1.jpg)"),
    output_dir: str = typer.Option("restored", help="Where to save the restored file"),
    provider: str = typer.Option(None, help="Override cloud provider defined in .env"),
):
    """
    Restore a single encrypted file from the cloud to local disk.
    """
    provider_name = provider or Config.PROVIDER
    storage = get_provider(provider_name)

    encrypted_filename = str(filename) + ".enc"
    local_encrypted_path = Path(".vaultic/temp") / encrypted_filename
    local_encrypted_path.parent.mkdir(parents=True, exist_ok=True)

    # Step 1: Download the file from cloud
    try:
        storage.download_file(encrypted_filename, local_encrypted_path)
        print(f"[blue]☁️ Downloaded:[/blue] {encrypted_filename}")
    except FileNotFoundError:
        print(f"[red]❌ File not found on remote:[/red] {encrypted_filename}")
        raise typer.Exit(1)

    # Step 2: Decrypt
    enc = EncryptionService(Config.KEY_PATH)
    output_path = Path(output_dir) / filename
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        enc.decrypt_file(local_encrypted_path, output_path)
        print(f"[green]✅ Restored to:[/green] {output_path}")
    except Exception as e:
        print(f"[red]❌ Failed to decrypt file:[/red] {e}")
        raise typer.Exit(1)
