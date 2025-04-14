#!/usr/bin/env python3
import typer
from cli.commands.backup import app as backup_app
from cli.commands.restore import app as restore_app
from cli.commands.list import app as list_app
from cli.commands.file import app as file_app
from cli.commands.status import app as status_app
from cli.commands.watch import app as watch_app
from cli.commands.config import app as config_app
from cli.commands.create import app as create_app
from cli.commands.decrypt import app as decrypt_app

app = typer.Typer(
    help="Vaultic - Encrypted Incremental Backups to the Cloud",
    add_completion=False
)

# Add subcommands
app.add_typer(backup_app, name="backup", help="Backup files or directories")
app.add_typer(restore_app, name="restore", help="Restore files from backup")
app.add_typer(list_app, name="list", help="List files in the backup index")
app.add_typer(file_app, name="file", help="Decrypt a file directly without using the backup index")
app.add_typer(status_app, name="status", help="Show status of current Vaultic configuration")
app.add_typer(watch_app, name="watch", help="Start a file system watcher that automatically encrypts files")
app.add_typer(config_app, name="config", help="Manage Vaultic configuration")
app.add_typer(create_app, name="create", help="Create a new vault")
app.add_typer(decrypt_app, name="decrypt", help="Shortcut to decrypt a single file")

if __name__ == "__main__":
    app()