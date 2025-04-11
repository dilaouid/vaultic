import typer
from cli.commands import backup

app = typer.Typer()
app.add_typer(backup.app, name="backup")

if __name__ == "__main__":
    app()