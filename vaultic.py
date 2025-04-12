import typer
from pathlib import Path
from core.vault.watcher import start_vaultic_watcher
from core.utils import console

app = typer.Typer(help="Vaultic CLI entrypoint. Use this to start file monitoring.")

@app.command()
def watch(key_path: str = typer.Option(
    None,
    "--key-path",
    help="Path to your Vaultic PEM key file. Overrides default config if provided.")
):
    key_path_override = Path(key_path).expanduser() if key_path else None
    start_vaultic_watcher(key_path_override=key_path_override)

if __name__ == "__main__":
    app()