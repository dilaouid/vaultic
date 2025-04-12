import typer
from pathlib import Path
from rich import print
from rich.table import Table
from core.config import Config
from core.indexing.indexer import load_index

app = typer.Typer()

@app.command()
def list(
    index_path: str = typer.Option(Config.INDEX_FILE, help="Path to the index file"),
    json_output: bool = typer.Option(False, "--json", help="Output the raw index as JSON")
):
    """
    Lists all files currently tracked in the index.
    """
    path = Path(index_path).resolve()
    if not path.exists():
        print(f"[red]❌ Index file not found at {path}[/red]")
        raise typer.Exit(1)

    index = load_index(path)

    if json_output:
        import json
        print(json.dumps(index, indent=2))
        return

    table = Table(title="🔐 Vaultic Tracked Files")
    table.add_column("📄 File", style="cyan")
    table.add_column("🔑 Hash", style="magenta")

    for f in index["files"]:
        table.add_row(f["relative_path"], f["hash"][:10] + "…")

    print(table)