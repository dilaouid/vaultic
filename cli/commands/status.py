import typer
from pathlib import Path
from rich import print
from core.config import Config

app = typer.Typer()


@app.callback(invoke_without_command=True)
def status():
    """
    Show status of current vaultic configuration.
    """
    print("[blue]Vaultic Configuration Status[/blue]")

    # Check provider
    print(f"[green]Provider:[/green] {Config.PROVIDER}")

    # Check key file
    key_path = Path(Config.KEY_PATH).expanduser()
    if key_path.exists():
        print(f"[green]Encryption key:[/green] Found at {key_path}")
    else:
        print(f"[red]Encryption key:[/red] Not found at expected location {key_path}")
        print("  Run 'python scripts/init_env.py' to generate a key.")

    # Check vaultic directory
    vaultic_dir = Path(".vaultic")
    if vaultic_dir.exists():
        print(f"[green]Vaultic directory:[/green] Found at {vaultic_dir.resolve()}")
    else:
        print(
            "[yellow]Vaultic directory:[/yellow] Not found. Will be created when needed."
        )

    # Check index file
    index_path = Path(Config.INDEX_FILE)
    if index_path.exists():
        print(f"[green]Index file:[/green] Found at {index_path}")
    else:
        print(
            f"[yellow]Index file:[/yellow] Not found at {index_path}. Will be created during first backup."
        )
