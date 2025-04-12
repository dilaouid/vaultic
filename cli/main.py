import typer
from cli.commands import backup, restore

app = typer.Typer()
app.add_typer(backup.app, name="backup")
app.add_typer(restore.app, name="restore")

if __name__ == "__main__":
    app()