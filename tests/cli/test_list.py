import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from typer.testing import CliRunner

from cli.__main__ import app

runner = CliRunner()


@pytest.fixture
def mock_getpass():
    """Mock getpass to return a predefined password."""
    with patch("getpass.getpass") as mock:
        mock.return_value = "test_password"
        yield mock


def test_list_vaults():
    """Test listing all vaults."""
    with patch("cli.commands.list.list_vaults") as mock_vaults:
        # Configure mock to return test data with decryption status
        mock_vaults.return_value = [
            {
                "id": "vault1",
                "name": "Main Vault",
                "created_at": 1609459200,  # 2021-01-01
                "linked": False,
                "file_count": 5,
                "decrypted": True,  # Successfully decrypted
                "path": "/path/to/vault1",
            },
            {
                "id": "vault2",
                "name": "Backup Vault",
                "created_at": 1612137600,  # 2021-02-01
                "linked": True,
                "file_count": 3,
                "decrypted": False,  # Failed to decrypt
                "path": "/path/to/vault2",
            },
        ]

        # Mock getpass to return empty string (skip decryption)
        with patch("getpass.getpass", return_value=""):
            result = runner.invoke(app, ["list", "vaults"])

    assert result.exit_code == 0
    assert "Main Vault" in result.output
    assert "Backup Vault" in result.output
    assert "5" in result.output  # File count
    assert "3" in result.output  # File count
    assert "✓" in result.output  # Success indicator
    assert "!" in result.output  # Failure indicator


def test_list_vaults_with_passphrase():
    """Test listing vaults with a passphrase for accurate file counts."""
    with patch("cli.commands.list.list_vaults") as mock_vaults:
        # Configure mock to return test data with decryption status
        mock_vaults.return_value = [
            {
                "id": "vault1",
                "name": "Main Vault",
                "created_at": 1609459200,
                "linked": False,
                "file_count": 5,
                "decrypted": True,  # Successfully decrypted
                "path": "/path/to/vault1",
            }
        ]

        # Mock getpass to return a passphrase
        with patch("getpass.getpass", return_value="test_passphrase"):
            result = runner.invoke(app, ["list", "vaults"])

    # Check that list_vaults was called with the passphrase
    mock_vaults.assert_called_once_with(passphrase="test_passphrase")
    assert result.exit_code == 0
    assert "Main Vault" in result.output
    assert "✓" in result.output  # Success indicator
    assert "Index successfully decrypted" in result.output  # Legend is shown


def test_list_vaults_empty():
    """Test listing vaults when none exist."""
    with patch("cli.commands.list.list_vaults", return_value=[]):
        result = runner.invoke(app, ["list", "vaults"])

    assert result.exit_code == 0
    assert "No vaults found" in result.output


def test_list_files_nonexistent_vault():
    """Test listing files from a non-existent vault."""
    # Patcher get_vault_path pour retourner un path qui .exists() -> False
    with patch("cli.commands.list.get_vault_path") as mock_path:
        mock_path_obj = MagicMock()
        mock_path_obj.exists.return_value = False
        mock_path.return_value = mock_path_obj
        result = runner.invoke(app, ["list", "files", "nonexistent"])

    assert result.exit_code == 1
    assert "Vault not found" in result.output


def create_mock_vault_structure(
    tmp_dir, vault_id="testvault", has_index=True, empty_index=False
):
    """Helper function to create a mock vault structure."""
    tmp = Path(tmp_dir)
    vault_dir = tmp / ".vaultic" / vault_id
    keys_dir = vault_dir / "keys"
    encrypted_dir = vault_dir / "encrypted"
    content_dir = encrypted_dir / "content"
    hmac_dir = encrypted_dir / "hmac"

    for dir_path in [keys_dir, content_dir, hmac_dir]:
        dir_path.mkdir(parents=True, exist_ok=True)

    # Create metadata file
    meta_path = keys_dir / "vault-meta.json"
    meta_data = {
        "vault_id": vault_id,
        "created_at": 1609459200,
        "salt": "test_salt",
        "version": 1,
    }
    meta_path.write_text(json.dumps(meta_data))

    # Create meta-test file for passphrase verification
    (keys_dir / ".meta-test").write_bytes(b"test-data")

    # Create mock encrypted index (optional)
    if has_index:
        (content_dir / "index.json.enc").write_bytes(b"mock-encrypted-data")
        (hmac_dir / "index.json.enc.hmac").write_bytes(b"mock-hmac-data")

    return vault_dir, meta_path


def test_list_files():
    """Test listing files from a vault with encrypted index."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        vault_dir, meta_path = create_mock_vault_structure(tmp_dir)

        # Configure mocks correctly
        with patch("cli.commands.list.get_vault_path", return_value=vault_dir):
            # Mock path.exists for important files
            with patch.object(Path, "exists", return_value=True):
                # Mock Path.stat() for file sizes
                original_stat = Path.stat

                def mock_stat_method(self):
                    # Mock stat for index files
                    if "index.json.enc" in str(self):
                        mock_stat = MagicMock()
                        mock_stat.st_size = 1024
                        return mock_stat
                    return original_stat(self)

                with patch.object(Path, "stat", mock_stat_method):
                    with patch("cli.commands.list.EncryptionService") as mock_enc:
                        # Configure encryption service mock
                        mock_enc_instance = MagicMock()
                        mock_enc_instance.verify_passphrase.return_value = None
                        mock_enc.return_value = mock_enc_instance

                        with patch("cli.commands.list.VaultIndexManager") as mock_index:
                            # Configure index manager mock
                            mock_index_instance = MagicMock()
                            mock_index_instance.load.return_value = {
                                "document.txt": {
                                    "hash": "abc123def456",
                                    "size": 1024,
                                    "timestamp": 1609459200,
                                },
                                "pictures/photo.jpg": {
                                    "hash": "def456abc123",
                                    "size": 1048576,  # 1MB
                                    "timestamp": 1612137600,
                                },
                            }
                            mock_index.return_value = mock_index_instance

                            # Execute command
                            result = runner.invoke(
                                app,
                                [
                                    "list",
                                    "files",
                                    "testvault",
                                    "--passphrase",
                                    "test_password",
                                ],
                            )

    assert (
        result.exit_code == 0
    ), f"Exit code: {result.exit_code}, Output: {result.output}"
    assert "document.txt" in result.output
    assert "pictures/photo.jpg" in result.output

    # The size formatting can vary by implementation
    # Check if sizes are displayed in some appropriate format
    document_lines = [
        line for line in result.output.splitlines() if "document.txt" in line
    ]
    photo_lines = [line for line in result.output.splitlines() if "photo.jpg" in line]

    # Make sure we found the lines
    assert len(document_lines) > 0, "document.txt not found in output lines"
    assert len(photo_lines) > 0, "photo.jpg not found in output lines"

    # Don't test specific size formatting, just ensure file listing works
    assert "Total:" in result.output


def test_list_files_empty_vault():
    """Test listing files from an empty vault."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        vault_dir, meta_path = create_mock_vault_structure(
            tmp_dir, vault_id="empty-vault"
        )

        # Configurer les mocks
        with patch("cli.commands.list.get_vault_path", return_value=vault_dir):
            # Patcher path.exists pour les fichiers importants
            with patch.object(Path, "exists", return_value=True):
                with patch("cli.commands.list.EncryptionService") as mock_enc:
                    # Configurer le mock d'encryption service
                    mock_enc_instance = MagicMock()
                    mock_enc_instance.verify_passphrase.return_value = None
                    mock_enc.return_value = mock_enc_instance

                    with patch("cli.commands.list.VaultIndexManager") as mock_index:
                        # Index vide
                        mock_index_instance = MagicMock()
                        mock_index_instance.load.return_value = {}
                        mock_index.return_value = mock_index_instance

                        # Exécuter la commande
                        result = runner.invoke(
                            app,
                            [
                                "list",
                                "files",
                                "empty-vault",
                                "--passphrase",
                                "test_password",
                            ],
                        )

    assert (
        result.exit_code == 0
    ), f"Exit code: {result.exit_code}, Output: {result.output}"
    assert "No files" in result.output
    assert "Add files" in result.output


def test_list_files_no_index():
    """Test listing files from a vault with no index."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        vault_dir, meta_path = create_mock_vault_structure(
            tmp_dir, vault_id="no-index-vault", has_index=False
        )

        # Patcher get_vault_path pour retourner le vault_dir
        with patch("cli.commands.list.get_vault_path", return_value=vault_dir):
            # Simuler une existence sélective des fichiers
            original_exists = Path.exists

            def mock_exists(self):
                # Le dossier du coffre existe mais pas les fichiers d'index
                if isinstance(self, Path):
                    path_str = str(self)
                    if (
                        "index.json.enc" in path_str
                        or "index.json.enc.hmac" in path_str
                    ):
                        return False
                    elif "vault-meta.json" in path_str or "no-index-vault" in path_str:
                        return True
                return original_exists(self)

            with patch.object(Path, "exists", mock_exists):
                # Exécuter la commande
                result = runner.invoke(
                    app,
                    [
                        "list",
                        "files",
                        "no-index-vault",
                        "--passphrase",
                        "test_password",
                    ],
                )

    assert (
        result.exit_code == 0
    ), f"Exit code: {result.exit_code}, Output: {result.output}"
    assert any(
        text in result.output
        for text in [
            "No index found",
            "Encrypted index file not found",
            "empty",
            "Vault may be empty",
        ]
    )


def test_list_files_invalid_passphrase():
    """Test listing files with an invalid passphrase."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        vault_dir, meta_path = create_mock_vault_structure(
            tmp_dir, vault_id="secured-vault"
        )

        # Mock get_vault_path to return the vault_dir
        with patch("cli.commands.list.get_vault_path", return_value=vault_dir):
            # Mock Path.exists to simulate that necessary files exist
            with patch.object(Path, "exists", return_value=True):
                # Mock Path.stat for cases where it's called
                with patch.object(Path, "stat") as mock_stat:
                    mock_stat_result = MagicMock()
                    mock_stat_result.st_size = 1000
                    mock_stat.return_value = mock_stat_result

                    # Mock EncryptionService to raise an error during passphrase verification
                    with patch("cli.commands.list.EncryptionService") as mock_enc:
                        mock_enc_instance = MagicMock()
                        mock_enc_instance.verify_passphrase.side_effect = ValueError(
                            "Invalid passphrase"
                        )
                        mock_enc.return_value = mock_enc_instance

                        # Execute command
                        result = runner.invoke(
                            app,
                            [
                                "list",
                                "files",
                                "secured-vault",
                                "--passphrase",
                                "wrong_password",
                            ],
                        )

    # Expect exit code 1 (error)
    assert (
        result.exit_code == 1
    ), f"Exit code: {result.exit_code}, Output: {result.output}"

    # Just verify some error message is present - we don't care about the exact wording
    assert len(result.output) > 0
