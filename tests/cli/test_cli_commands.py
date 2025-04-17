import tempfile
import os
from pathlib import Path
import pytest
from unittest.mock import patch
from typer.testing import CliRunner

from cli.__main__ import app

runner = CliRunner()

@pytest.fixture
def mock_getpass():
    """Mock getpass to return a predefined password."""
    with patch('getpass.getpass') as mock:
        mock.return_value = "test_password"
        yield mock

@pytest.fixture
def temp_env_setup():
    """Set up temporary environment for CLI tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        
        # Create basic directory structure
        vaultic_dir = tmp / ".vaultic"
        keys_dir = vaultic_dir / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Set environment variables
        old_env = os.environ.copy()
        os.environ["VAULTIC_PEPPER"] = "test_pepper_for_cli"
        os.environ["VAULTIC_META_PATH"] = str(vaultic_dir / "vaultic_meta.json")
        os.environ["VAULTIC_INDEX_FILE"] = str(vaultic_dir / "index.json")
        
        # Change working directory
        old_dir = os.getcwd()
        os.chdir(tmp)
        
        yield tmp, vaultic_dir, keys_dir
        
        # Restore environment
        os.environ.clear()
        os.environ.update(old_env)
        os.chdir(old_dir)

def test_status_command(temp_env_setup):
    """Test the status command."""
    result = runner.invoke(app, ["status"])
    
    assert result.exit_code == 0
    assert "Vaultic Configuration Status" in result.output
    assert "Provider:" in result.output

@patch("uuid.uuid4")
def test_create_independent_vault_command(mock_uuid, temp_env_setup, mock_getpass):
    """Test the create command with --independent flag."""
    mock_uuid.return_value.hex = "testindepend12" * 2
    
    result = runner.invoke(app, ["create", "--independent"])
    
    assert result.exit_code == 0
    assert "Created independent vault" in result.output
    assert "testindepend" in result.output  # Part of the vault ID should be in output

@patch("uuid.uuid4")
def test_create_linked_vault_command(mock_uuid, temp_env_setup, mock_getpass):
    """Test the create command with --linked flag."""
    mock_uuid.side_effect = [
        type('obj', (object,), {'hex': "mainvault1234" * 2}),
        type('obj', (object,), {'hex': "linkedvault12" * 2})
    ]
    
    result = runner.invoke(app, ["create", "--linked"])
    
    assert result.exit_code == 0
    assert "Created main vault" in result.output or "Created linked vault" in result.output
    
    # Should have created the vault directories
    _, _, keys_dir = temp_env_setup
    assert (keys_dir / "mainvault12").exists() or (keys_dir / "linkedvault").exists()

def test_create_command_missing_flag(temp_env_setup):
    """Test the create command without required flags."""
    result = runner.invoke(app, ["create"])
    
    assert result.exit_code != 0
    assert "must specify either --linked or --independent" in result.output

def test_create_command_conflicting_flags(temp_env_setup):
    """Test the create command with conflicting flags."""
    result = runner.invoke(app, ["create", "--linked", "--independent"])
    
    assert result.exit_code != 0
    assert "can't use both" in result.output

def test_decrypt_command(temp_env_setup, mock_getpass):
    """Test the decrypt command."""
    # Create a test file to decrypt
    tmp, vaultic_dir, _ = temp_env_setup
    test_file = tmp / "test.txt.enc"
    test_file.write_bytes(b"This is not really encrypted")
    
    # Mock the EncryptionService to avoid actual decryption
    with patch("core.encryption.service.EncryptionService") as mock_service:
        # Configure the mock
        mock_instance = mock_service.return_value
        
        result = runner.invoke(app, ["decrypt", str(test_file)])
        
        assert result.exit_code == 0
        assert mock_getpass.called  # Should have asked for passphrase
        assert mock_instance.decrypt_file.called  # Should have called decrypt_file

def test_file_command(temp_env_setup, mock_getpass):
    """Test the file command."""
    # Create a test file to decrypt
    tmp, vaultic_dir, _ = temp_env_setup
    test_file = tmp / "test.txt.enc"
    test_file.write_bytes(b"This is not really encrypted")
    
    # Mock the EncryptionService to avoid actual decryption
    with patch("core.encryption.service.EncryptionService") as mock_service:
        # Configure the mock
        mock_instance = mock_service.return_value
        
        result = runner.invoke(app, ["file", str(test_file)])
        
        assert result.exit_code == 0
        assert mock_getpass.called  # Should have asked for passphrase
        assert mock_instance.decrypt_file.called  # Should have called decrypt_file

def test_watch_command_vault_not_found(temp_env_setup, mock_getpass):
    """Test the watch command with a non-existent vault."""
    result = runner.invoke(app, ["watch", "--vault", "nonexistent"])
    
    assert result.exit_code != 0
    assert "not found" in result.output

@patch("core.vault.selector.select_or_create_vault")
def test_watch_command(mock_select, temp_env_setup, mock_getpass):
    """Test the watch command with vault selection."""
    # Mock the vault selection
    tmp, vaultic_dir, keys_dir = temp_env_setup
    test_vault_dir = keys_dir / "testvault"
    test_vault_dir.mkdir()
    meta_path = test_vault_dir / "vaultic_meta.json"
    meta_path.write_text('{"salt": "test", "version": 1}')
    
    mock_select.return_value = ("testvault", meta_path)
    
    # Mock the watcher to avoid actually starting it
    with patch("core.vault.watcher.start_vaultic_watcher") as mock_watcher:
        result = runner.invoke(app, ["watch"])
        
        assert result.exit_code == 0
        assert mock_select.called
        assert mock_getpass.called
        assert mock_watcher.called

def test_config_show_command(temp_env_setup):
    """Test the config show command."""
    result = runner.invoke(app, ["config", "show"])
    
    assert result.exit_code == 0
    assert "Current Configuration" in result.output
    assert "Provider" in result.output

def test_config_set_command(temp_env_setup):
    """Test the config set command."""
    # Create a .env file to modify
    tmp, _, _ = temp_env_setup
    env_file = tmp / ".env"
    env_file.write_text("# Test env file\n")
    
    with patch("dotenv.find_dotenv", return_value=str(env_file)):
        with patch("dotenv.set_key") as mock_set_key:
            result = runner.invoke(app, ["config", "set", "TEST_KEY", "test_value"])
            
            assert result.exit_code == 0
            assert mock_set_key.called
            assert "Successfully set" in result.output