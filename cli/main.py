import typer
from cli.commands import backup, restore, list as list_cmd

app = typer.Typer()
app.add_typer(backup.app, name="backup")
app.add_typer(restore.app, name="restore")
app.add_typer(list_cmd.app, name="list")

if __name__ == "__main__":
    app()