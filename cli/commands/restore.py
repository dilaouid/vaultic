import typer
from pathlib import Path
from core.utils import console
from core.config import Config
from core.encryption.service import EncryptionService

app = typer.Typer()

@app.command("file")
def restore_file(
    encrypted_file: str = typer.Argument(..., help="Path to the encrypted .enc file"),
    output_path: str = typer.Option(None, help="Destination path (default: remove .enc extension)"),
    passphrase: str = typer.Option(..., prompt=True, hide_input=True, help="Encryption passphrase"),
    meta_path: str = typer.Option(None, help="Path to vaultic_meta.json (contains salt)")
):
    """
    Decrypts a file encrypted with Vaultic using passphrase and meta file, restoring it to original form.
    """
    input_path = Path(encrypted_file).resolve()

    if not input_path.exists():
        console.print(f"[red]❌ File not found: {input_path}[/red]")
        raise typer.Exit(1)

    if not input_path.name.endswith(".enc"):
        console.print(f"[red]❌ Invalid file: expected .enc extension[/red]")
        raise typer.Exit(1)

    output_path = Path(output_path).resolve() if output_path else input_path.with_suffix('')

    console.print(f"[blue]🔓 Restoring:[/blue] {input_path.name} → {output_path.name}")

    enc = EncryptionService(
        passphrase=passphrase, 
        meta_path=Path(meta_path).expanduser() if meta_path else Path(Config.META_PATH)
    )

    try:
        enc.decrypt_file(str(input_path), str(output_path))
        console.print(f"[green]✅ Restored successfully:[/green] {output_path}")
    except Exception as e:
        console.print(f"[red]❌ Decryption failed: {e}[/red]")
        raise typer.Exit(1)