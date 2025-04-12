from typing import Optional
import typer
from pathlib import Path
from core.vault.watcher import start_vaultic_watcher

app = typer.Typer(help="Vaultic CLI entrypoint. Use this to start file monitoring.")

@app.command()
def watch(
    passphrase: str = typer.Option(..., prompt=True, hide_input=True, help="Your encryption passphrase."),
    meta_path: Optional[str] = typer.Option(None, help="Path to vaultic_meta.json (salt and config)")
):
    start_vaultic_watcher(passphrase=passphrase, meta_path=meta_path)

if __name__ == "__main__":
    app()