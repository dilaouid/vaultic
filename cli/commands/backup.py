"""
Backup Command - Encrypt and upload files to storage.
"""

import typer
from pathlib import Path
from rich import print
from getpass import getpass
from typing import Optional, List

from core.config import Config
from core.encryption.service import EncryptionService
from core.storage.factory import get_provider
from core.vault.manager import select_vault
from core.vault.file_handler import encrypt_and_store_file

app = typer.Typer()


@app.command("file")
def backup_file(
    source: str = typer.Argument(..., help="Path to the file you want to back up"),
    vault_id: Optional[str] = typer.Option(
        None, "--vault", "-v", help="Specific vault to use"
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="Override storage provider"
    ),
    passphrase: Optional[str] = typer.Option(
        None, "--passphrase", help="Vault passphrase (will prompt if not provided)"
    ),
):
    """
    Backup a single file to an encrypted vault.
    """
    try:
        # Verify source file exists
        source_path = Path(source).resolve()
        if not source_path.exists() or not source_path.is_file():
            print(f"[red]❌ Source file does not exist:[/red] {source}")
            raise typer.Exit(code=1)

        # Select vault
        selected_vault_id, meta_path = select_vault(vault_id)

        # Get passphrase if not provided
        if not passphrase:
            passphrase = getpass("🔑 Enter vault passphrase: ")

        # Create encryption service
        enc_service = EncryptionService(passphrase, meta_path)

        # Verify passphrase
        try:
            enc_service.verify_passphrase()
        except ValueError as e:
            print(f"[red]❌ {str(e)}[/red]")
            raise typer.Exit(code=1)

        # Set up paths
        vault_dir = meta_path.parent.parent
        encrypted_dir = vault_dir / "encrypted"
        encrypted_dir.mkdir(parents=True, exist_ok=True)

        # Get storage provider
        provider_name = provider or Config.PROVIDER
        storage = get_provider(provider_name)

        # Process the file
        filename = source_path.name
        rel_path = Path(filename)

        print(
            f"[blue]🔐 Backing up file to vault {selected_vault_id}:[/blue] {filename}"
        )

        success = encrypt_and_store_file(
            source_path, rel_path, enc_service, encrypted_dir, storage, provider_name
        )

        if success:
            print(f"[green]✅ File backed up successfully:[/green] {filename}")
        else:
            print(f"[red]❌ Failed to backup file:[/red] {filename}")
            raise typer.Exit(code=1)

    except Exception as e:
        print(f"[red]❌ Error backing up file:[/red] {str(e)}")
        raise typer.Exit(code=1)


@app.command("dir")
def backup_dir(
    source: str = typer.Argument(..., help="Path to the directory you want to back up"),
    vault_id: Optional[str] = typer.Option(
        None, "--vault", "-v", help="Specific vault to use"
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="Override storage provider"
    ),
    passphrase: Optional[str] = typer.Option(
        None, "--passphrase", help="Vault passphrase (will prompt if not provided)"
    ),
    exclude: List[str] = typer.Option(
        [], "--exclude", "-e", help="Patterns to exclude (can be used multiple times)"
    ),
    recursive: bool = typer.Option(
        True, "--recursive/--no-recursive", help="Backup subdirectories recursively"
    ),
):
    """
    Backup a directory to an encrypted vault.
    """
    try:
        # Verify source directory exists
        source_dir = Path(source).resolve()
        if not source_dir.exists() or not source_dir.is_dir():
            print(f"[red]❌ Source directory does not exist:[/red] {source}")
            raise typer.Exit(code=1)

        # Select vault
        selected_vault_id, meta_path = select_vault(vault_id)

        # Get passphrase if not provided
        if not passphrase:
            passphrase = getpass("🔑 Enter vault passphrase: ")

        # Create encryption service
        enc_service = EncryptionService(passphrase, meta_path)

        # Verify passphrase
        try:
            enc_service.verify_passphrase()
        except ValueError as e:
            print(f"[red]❌ {str(e)}[/red]")
            raise typer.Exit(code=1)

        # Set up paths
        vault_dir = meta_path.parent.parent
        encrypted_dir = vault_dir / "encrypted"
        encrypted_dir.mkdir(parents=True, exist_ok=True)

        # Get storage provider
        provider_name = provider or Config.PROVIDER
        storage = get_provider(provider_name)

        # Process files
        pattern = "**/*" if recursive else "*"
        files = list(source_dir.glob(pattern))
        files = [f for f in files if f.is_file()]

        # Apply exclusions
        if exclude:
            import fnmatch

            for pattern in exclude:
                files = [f for f in files if not fnmatch.fnmatch(str(f), pattern)]

        # Get total file count
        total_files = len(files)
        if total_files == 0:
            print(f"[yellow]⚠️ No files found in directory:[/yellow] {source_dir}")
            raise typer.Exit(code=0)

        print(
            f"[blue]🔐 Backing up {total_files} files to vault {selected_vault_id}...[/blue]"
        )

        # Process each file
        successful = 0
        from tqdm import tqdm

        for file_path in tqdm(files, desc="Processing files"):
            try:
                # Calculate path relative to source directory
                rel_path = file_path.relative_to(source_dir)

                success = encrypt_and_store_file(
                    file_path,
                    rel_path,
                    enc_service,
                    encrypted_dir,
                    storage,
                    provider_name,
                )

                if success:
                    successful += 1
            except Exception as e:
                print(f"[red]❌ Error processing {file_path}: {str(e)}[/red]")

        # Print summary
        print(
            f"[green]✅ Directory backup complete:[/green] {successful}/{total_files} files processed"
        )

        if successful < total_files:
            print(
                f"[yellow]⚠️ {total_files - successful} files failed to process[/yellow]"
            )
            raise typer.Exit(code=1)

    except Exception as e:
        print(f"[red]❌ Error backing up directory:[/red] {str(e)}")
        raise typer.Exit(code=1)
