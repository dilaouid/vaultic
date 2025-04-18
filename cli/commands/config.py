# cli\commands\config.py
import typer
from rich import print
from core.config import Config
from pathlib import Path
import dotenv

app = typer.Typer()


@app.command("show")
def show_config():
    """
    Display the current configuration.
    """
    print("[blue]Current Configuration:[/blue]")
    print(f"[green]Provider:[/green] {Config.PROVIDER}")
    print(f"[green]Backup Directory:[/green] {Config.BACKUP_DIR}")
    print(f"[green]Index File:[/green] {Config.INDEX_FILE}")
    print(f"[green]Log File:[/green] {Config.LOG_FILE}")
    print(f"[green]Encryption Key Path:[/green] {Config.KEY_PATH}")

    if Config.PROVIDER == "google_drive":
        print("\n[yellow]Google Drive Configuration:[/yellow]")
        print(
            f"[green]Client ID:[/green] {'Set' if Config.GOOGLE_CLIENT_ID else 'Not Set'}"
        )
        print(
            f"[green]Client Secret:[/green] {'Set' if Config.GOOGLE_CLIENT_SECRET else 'Not Set'}"
        )
        print(
            f"[green]Refresh Token:[/green] {'Set' if Config.GOOGLE_REFRESH_TOKEN else 'Not Set'}"
        )
        print(f"[green]Folder ID:[/green] {Config.GOOGLE_FOLDER_ID or 'Not Set'}")

    elif Config.PROVIDER == "backblaze":
        print("\n[yellow]Backblaze B2 Configuration:[/yellow]")
        print(
            f"[green]Account ID:[/green] {'Set' if Config.B2_ACCOUNT_ID else 'Not Set'}"
        )
        print(
            f"[green]Application Key:[/green] {'Set' if Config.B2_APPLICATION_KEY else 'Not Set'}"
        )
        print(f"[green]Bucket Name:[/green] {Config.B2_BUCKET_NAME or 'Not Set'}")


@app.command("set")
def set_config(
    key: str = typer.Argument(
        ..., help="Configuration key to set (e.g., PROVIDER, VAULTIC_BACKUP_DIR)"
    ),
    value: str = typer.Argument(..., help="Value to set for the configuration key"),
):
    """
    Set a configuration value in the .env file.
    """
    env_file = Path(".env")

    if not env_file.exists():
        # Create from .env.example if it exists
        example_file = Path(".env.example")
        if example_file.exists():
            with example_file.open("r") as src:
                with env_file.open("w") as dst:
                    dst.write(src.read())
            print("[green]Created .env file from .env.example[/green]")
        else:
            env_file.touch()
            print("[green]Created empty .env file[/green]")

    # Update the .env file
    dotenv_file = dotenv.find_dotenv()
    dotenv.set_key(dotenv_file, key, value)

    print(f"[green]✅ Successfully set {key}=[/green] {value}")
    print(
        "[yellow]Note: You need to restart the application for changes to take effect.[/yellow]"
    )
