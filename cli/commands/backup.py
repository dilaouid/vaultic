import typer
from pathlib import Path
from rich import print
from core.config import Config
from core.encryption.service import EncryptionService
from core.indexing.indexer import generate_index, save_index, load_index
from core.storage.factory import get_provider

app = typer.Typer()

@app.command("dir")
def backup_dir(
    source: str = typer.Argument(..., help="Path to the folder you want to back up"),
    provider: str = typer.Option(None, help="Override cloud provider defined in .env"),
    index_path: str = typer.Option(Config.INDEX_FILE, help="Path to the backup index file")
):
    """
    Backup an entire folder:
    - Indexes it
    - Compares with previous index
    - Encrypts modified/new files
    """
    source_dir = Path(source).resolve()
    encrypted_dir = Path(".vaultic/encrypted")
    encrypted_dir.mkdir(parents=True, exist_ok=True)
    provider_name = provider or Config.PROVIDER
    storage = get_provider(provider_name)

    if not source_dir.exists() or not source_dir.is_dir():
        print("[red]❌ Source directory does not exist or is not a folder.[/red]")
        raise typer.Exit(1)

    # Step 1: Load previous index if it exists
    old_index = {}
    index_path = Path(index_path)
    if index_path.exists():
        old_index = load_index(index_path)
        print("[blue]🔁 Existing index loaded.[/blue]")

    # Step 2: Generate new index
    print(f"[green]📦 Indexing folder:[/green] {source_dir}")
    new_index = generate_index(source_dir, encrypted_dir)

    # Step 3: Compare + encrypt modified/new files
    enc = EncryptionService(Config.KEY_PATH)
    updated_files = 0

    for file in new_index["files"]:
        file_hash = file["hash"]
        path = file["relative_path"]

        was_in_previous = any(f["relative_path"] == path and f["hash"] == file_hash for f in old_index.get("files", []))

        if not was_in_previous:
            updated_files += 1
            input_path = source_dir / path
            output_path = Path(file["encrypted_path"])
            output_path.parent.mkdir(parents=True, exist_ok=True)

            print(f"[yellow]🔐 Encrypting:[/yellow] {path}")
            enc.encrypt_file(str(input_path), str(output_path))
            storage.upload_file(output_path, str(path) + ".enc")
            print(f"[blue]☁️ Uploaded:[/blue] {path}.enc")

    # Step 4: Save new index
    save_index(new_index, index_path)
    print(f"\n[green]✅ Index saved to:[/green] {index_path}")
    print(f"[cyan]🗃 {updated_files} file(s) encrypted.[/cyan]")

    if updated_files == 0:
        print("[grey]No changes detected. Everything is up to date.[/grey]")
