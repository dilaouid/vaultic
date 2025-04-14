import typer
import json
from pathlib import Path
from rich import print
from core.indexing.indexer import load_index

app = typer.Typer()

@app.callback(invoke_without_command=True)
def list_files(
    index_path: str = typer.Option(None, help="Path to the index file"),
    json_output: bool = typer.Option(False, "--json", help="Output the raw index as JSON")
):
    """
    List all files in the backup index.
    """
    try:
        index_path = Path(index_path)
        if not index_path.exists():
            print(f"[red]❌ Index file not found:[/red] {index_path}")
            raise typer.Exit(1)

        index = load_index(index_path)
        
        if json_output:
            print(json.dumps(index, indent=2))
            return
        
        print(f"[blue]📁 Backup root:[/blue] {index.get('root', 'N/A')}")
        print(f"[blue]🔢 Total files:[/blue] {len(index.get('files', []))}")
        
        print("\n[yellow]Files in backup:[/yellow]")
        for i, file in enumerate(sorted(index.get('files', []), key=lambda x: x.get('relative_path', ''))):
            size_kb = file.get('size', 0) / 1024
            print(f"{i+1}. [green]{file.get('relative_path')}[/green] ({size_kb:.1f} KB)")
    
    except Exception as e:
        print(f"[red]❌ Error reading index:[/red] {str(e)}")
        raise typer.Exit(1)