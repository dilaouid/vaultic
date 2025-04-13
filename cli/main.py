from pathlib import Path
import typer
from cli.commands.backup import app as backup_app
from cli.commands.restore import app as restore_app

from core.config import Config
from core.encryption.service import EncryptionService
from core.utils import console

app = typer.Typer()
app.add_typer(backup_app, name="backup")
app.add_typer(restore_app, name="restore")

@app.command("list")
def call_list_files(
    index_path: str = typer.Option(None, help="Path to the index file"),
    json_output: bool = typer.Option(False, "--json", help="Output the raw index as JSON")
):
    from cli.commands.list import list_files
    from core.config import Config
    final_path = index_path or Config.INDEX_FILE
    return list_files(index_path=final_path, json_output=json_output)

@app.command("file")
def restore_file(
    encrypted_file: str = typer.Argument(...),
    output_path: str = typer.Option(None),
    passphrase: str = typer.Option(..., prompt=True, hide_input=True),
    meta_path: str = typer.Option(None)
):
    enc = EncryptionService(passphrase=passphrase, meta_path=meta_path or Config.META_PATH)

    input_path = Path(encrypted_file).resolve()
    output_path = Path(output_path).resolve() if output_path else input_path.with_suffix('')

    enc.decrypt_file(str(input_path), str(output_path))
    console.print(f"✅ File restored successfully to {output_path}")

if __name__ == "__main__":
    app()