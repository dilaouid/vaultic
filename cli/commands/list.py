import typer
from pathlib import Path
from core.utils import console
from rich.table import Table
from core.indexing.indexer import load_index

def list_files(
    index_path: str,
    json_output: bool = typer.Option(False, "--json", help="Output the raw index as JSON")
):
    """
    Lists all files currently tracked in the index.
    """
    path = Path(index_path).resolve()
    if not path.exists():
        console.print(f"[red]❌ Index file not found at {path}[/red]")
        raise typer.Exit(1)

    index = load_index(path)

    if json_output:
        import json
        console.print(json.dumps(index, indent=2))
        return

    table = Table(title="🔐 Vaultic Tracked Files")
    table.add_column("📄 File", style="cyan")
    table.add_column("🔑 Hash", style="magenta")

    for f in index["files"]:
        table.add_row(f["relative_path"], f["hash"][:10] + "…")

    console.print(table)