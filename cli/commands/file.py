import typer
import getpass
from pathlib import Path
from rich import print
from core.config import Config
from core.encryption.service import EncryptionService

app = typer.Typer()


@app.callback(invoke_without_command=True)
def decrypt_file(
    encrypted_file: str = typer.Argument(..., help="Path to the encrypted file"),
    output_path: str = typer.Option(None, help="Path where to save the decrypted file"),
    meta_path: str = typer.Option(None, help="Path to the encryption metadata file"),
):
    """
    Decrypt a single file without using the backup index.
    """
    try:
        # Get passphrase securely - never include it as a command line argument
        passphrase = getpass.getpass("Enter passphrase: ")

        # Initialize encryption service
        enc = EncryptionService(
            passphrase=passphrase, meta_path=meta_path or Config.META_PATH
        )

        # Resolve paths
        input_path = Path(encrypted_file).resolve()
        output_path = (
            Path(output_path).resolve() if output_path else input_path.with_suffix("")
        )

        # Ensure input file exists
        if not input_path.exists():
            print(f"[red]❌ File not found:[/red] {input_path}")
            raise typer.Exit(1)

        # Create parent directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Decrypt file
        print(f"[blue]🔓 Decrypting:[/blue] {input_path}")
        enc.decrypt_file(str(input_path), str(output_path))

        print(f"✅ File restored successfully to {output_path}")

    except Exception as e:
        print(f"[red]❌ Decryption failed:[/red] {str(e)}")
        raise typer.Exit(1)
