import typer
from pathlib import Path
from rich import print
from core.config import Config
from core.encryption.service import EncryptionService

app = typer.Typer()

@app.command("file")
def restore_file(
    encrypted_file: str = typer.Argument(..., help="Path to the encrypted .enc file"),
    output_path: str = typer.Option(None, help="Destination path (default: remove .enc extension)"),
):
    """
    Decrypts a file encrypted with Vaultic and restores it to its original form.
    """
    input_path = Path(encrypted_file).resolve()

    if not input_path.exists():
        print(f"[red]❌ File not found: {input_path}[/red]")
        raise typer.Exit(1)

    if not input_path.name.endswith(".enc"):
        print(f"[red]❌ Invalid file: expected .enc extension[/red]")
        raise typer.Exit(1)

    if output_path:
        output_path = Path(output_path).resolve()
    else:
        output_path = input_path.with_name(input_path.name.replace(".enc", ""))

    print(f"[blue]🔓 Restoring:[/blue] {input_path.name} → {output_path.name}")

    enc = EncryptionService(Config.KEY_PATH)

    try:
        enc.decrypt_file(str(input_path), str(output_path))
        print(f"[green]✅ Restored successfully:[/green] {output_path}")
    except Exception as e:
        print(f"[red]❌ Decryption failed: {e}[/red]")
        raise typer.Exit(1)