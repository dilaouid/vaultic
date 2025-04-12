import typer
from cli.commands.backup import app as backup_app
from cli.commands.restore import app as restore_app

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

if __name__ == "__main__":
    app()