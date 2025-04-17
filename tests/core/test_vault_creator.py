import os
import tempfile
import json
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

from core.vault.manager import create_vault, list_vaults, get_vaults_directory

@pytest.fixture
def mock_getpass():
    """Mock getpass to return a predefined password."""
    with patch('getpass.getpass') as mock:
        mock.return_value = "test_password"
        yield mock

@pytest.fixture
def temp_keys_dir():
    """Create a temporary directory for vault keys."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        vaultic_dir = tmp / ".vaultic"
        vaultic_dir.mkdir(parents=True, exist_ok=True)
        
        # Change current working dir to tmp for relative paths
        original_dir = os.getcwd()
        os.chdir(tmp)
        
        yield tmp, vaultic_dir
        
        # Change back to original dir
        os.chdir(original_dir)

def find_existing_vaults(vaultic_dir: Path):
    """
    Helper function to find vaults in a directory for test compatibility.
    """
    vaults = []
    
    # Check if vaultic_dir exists
    if not vaultic_dir.exists():
        return vaults
    
    # Look through vault directories
    for vault_dir in vaultic_dir.iterdir():
        if not vault_dir.is_dir() or vault_dir.name.startswith('.'):
            continue
        
        # Check for metadata file
        meta_path = vault_dir / "keys" / "vault-meta.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                vaults.append((vault_dir.name, meta))
            except:
                pass
    
    return vaults

def test_find_existing_vaults_empty_dir(temp_keys_dir):
    """Test finding vaults in an empty directory."""
    _, vaultic_dir = temp_keys_dir
    
    # Use list_vaults from manager instead of the old find_existing_vaults
    vaults = list_vaults()
    assert len(vaults) == 0

def test_find_existing_vaults_with_vaults(temp_keys_dir):
    """Test finding vaults when vaults exist."""
    _, vaultic_dir = temp_keys_dir
    
    # Create fake vault dirs with metadata
    vault1_dir = vaultic_dir / "vault1"
    vault1_dir.mkdir()
    keys_dir1 = vault1_dir / "keys"
    keys_dir1.mkdir()
    meta1 = {
        "vault_id": "vault1",
        "linked": False,
        "salt": "test_salt_1",
        "version": 1,
        "created_at": 1000000
    }
    (keys_dir1 / "vault-meta.json").write_text(json.dumps(meta1))
    
    vault2_dir = vaultic_dir / "vault2"
    vault2_dir.mkdir()
    keys_dir2 = vault2_dir / "keys"
    keys_dir2.mkdir()
    meta2 = {
        "vault_id": "vault2",
        "linked": True,
        "main_vault": "vault1",
        "salt": "test_salt_2",
        "version": 1,
        "created_at": 1000001
    }
    (keys_dir2 / "vault-meta.json").write_text(json.dumps(meta2))
    
    # Use our helper function to check the structure
    vaults = find_existing_vaults(vaultic_dir)
    
    assert len(vaults) == 2
    assert "vault1" in [v[0] for v in vaults]
    assert "vault2" in [v[0] for v in vaults]
    
    # Check metadata is loaded correctly
    vault1_meta = next(m for v, m in vaults if v == "vault1")
    vault2_meta = next(m for v, m in vaults if v == "vault2")
    
    assert vault1_meta["linked"] is False
    assert vault2_meta["linked"] is True
    assert vault2_meta["main_vault"] == "vault1"

    # Also test the new list_vaults function
    vaults_list = list_vaults()
    assert len(vaults_list) == 2

@patch("uuid.uuid4")
def test_create_independent_vault(mock_uuid, temp_keys_dir, mock_getpass):
    """Test creating an independent vault."""
    _, vaultic_dir = temp_keys_dir

    # Create a mock with a controlled hex attribute
    uuid_instance = MagicMock()
    uuid_instance.hex = "abcdef123456" * 2  # Make it long enough to be sliced
    mock_uuid.return_value = uuid_instance

    # Override the default passphrase for the test
    with patch("core.config.Config.DEFAULT_PASSPHRASE", "test_password"):
        # Mock EncryptionService to create actual meta files
        with patch("core.encryption.service.EncryptionService") as mock_enc:
            # Setup the mock instance
            instance = mock_enc.return_value
            instance.create_meta_test_file.return_value = None

            # Make sure construction creates metadata
            def create_metadata(passphrase, meta_path):
                meta_path = Path(meta_path)
                meta_path.parent.mkdir(parents=True, exist_ok=True)
                meta_data = {
                    "salt": "test_salt",
                    "pepper_hash": "test_hash",
                    "version": 1,
                    "linked": False
                }
                meta_path.write_text(json.dumps(meta_data))
                return instance

            mock_enc.side_effect = create_metadata

            # Run the function under test with the name parameter
            vault_id = create_vault(name="abcdef123456", linked=False)

            # Verify the results
            assert vault_id == "abcdef123456", f"Expected 'abcdef123456', got '{vault_id}'"

            # Check vault directory and metadata
            vault_dir = vaultic_dir / vault_id
            meta_file = vault_dir / "keys" / "vault-meta.json"

            assert vault_dir.exists(), f"Vault dir does not exist at {vault_dir}"
            assert meta_file.exists(), f"Meta file does not exist at {meta_file}"

@patch("uuid.uuid4")
def test_create_linked_vault_no_existing_vaults(mock_uuid, temp_keys_dir, mock_getpass):
    """Test creating a linked vault when no vaults exist."""
    _, vaultic_dir = temp_keys_dir
    
    # We need to mock two different UUID calls
    main_uuid = MagicMock()
    main_uuid.hex = "main123456789" * 2
    
    linked_uuid = MagicMock()
    linked_uuid.hex = "linked987654321" * 2
    
    # Setup the sequence of return values
    mock_uuid.side_effect = [main_uuid, linked_uuid]
    
    # Override the default passphrase for the test
    with patch("core.config.Config.DEFAULT_PASSPHRASE", "test_password"):
        # Mock EncryptionService
        with patch("core.encryption.service.EncryptionService") as mock_enc:
            instance = mock_enc.return_value
            instance.create_meta_test_file.return_value = None

            # Make constructor create metadata files
            def create_metadata(passphrase, meta_path):
                meta_path = Path(meta_path)
                meta_path.parent.mkdir(parents=True, exist_ok=True)

                meta_data = {
                    "salt": "test_salt",
                    "pepper_hash": "test_hash",
                    "version": 1,
                    "linked": True
                }

                meta_path.write_text(json.dumps(meta_data))
                return instance

            mock_enc.side_effect = create_metadata

            # Run the function under test - using name parameter directly
            vault_id = create_vault(name="main123456", linked=True)

            # Verify results
            assert vault_id == "main123456", f"Expected 'main123456', got '{vault_id}'"

            # Check vault directories and metadata files
            main_vault_dir = vaultic_dir / "main123456"

            assert main_vault_dir.exists(), f"Main vault dir not found at {main_vault_dir}" 
            assert (main_vault_dir / "keys" / "vault-meta.json").exists(), "Main vault metadata missing"

@patch("uuid.uuid4")
def test_create_linked_vault_with_existing_vault(mock_uuid, temp_keys_dir, mock_getpass):
    """Test creating a linked vault when a vault already exists."""
    _, vaultic_dir = temp_keys_dir

    # Create existing vault
    existing_id = "existing123"
    existing_dir = vaultic_dir / existing_id
    existing_dir.mkdir(parents=True, exist_ok=True)
    keys_dir = existing_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    # Create metadata for existing vault
    existing_meta = {
        "vault_id": existing_id,
        "salt": "test_salt",
        "version": 1,
        "linked": False,
        "pepper_hash": "pepper123",
        "created_at": 1000000
    }
    (keys_dir / "vault-meta.json").write_text(json.dumps(existing_meta))

    # Create test file
    (keys_dir / ".meta-test").write_bytes(b"test data")

    # Mock UUID for the new linked vault
    new_uuid = MagicMock()
    new_uuid.hex = "newlinked123456" * 2
    mock_uuid.return_value = new_uuid

    # Override the default passphrase for the test
    with patch("core.config.Config.DEFAULT_PASSPHRASE", "test_password"):
        # Mock EncryptionService
        with patch("core.encryption.service.EncryptionService") as mock_enc:
            instance = mock_enc.return_value
            instance.create_meta_test_file.return_value = None
            instance.verify_passphrase.return_value = None

            # Make constructor create metadata
            def create_metadata(passphrase, meta_path):
                meta_path = Path(meta_path)
                meta_path.parent.mkdir(parents=True, exist_ok=True)

                meta_data = {
                    "vault_id": "newlinked12",
                    "salt": "test_salt",
                    "version": 1, 
                    "linked": True,
                    "main_vault": existing_id,
                    "pepper_hash": "pepper123",
                    "created_at": 1000001
                }
                meta_path.write_text(json.dumps(meta_data))

                return instance

            mock_enc.side_effect = create_metadata

            # Run the function under test with explicit name
            vault_id = create_vault(name="newlinked12", linked=True, passphrase="test_password")

            # Verify results
            assert vault_id == "newlinked12", f"Expected 'newlinked12', got '{vault_id}'"

            # Check linked vault directory and metadata
            linked_dir = vaultic_dir / vault_id
            assert linked_dir.exists(), f"Linked vault dir not found at {linked_dir}"
            assert (linked_dir / "keys" / "vault-meta.json").exists(), "Linked vault metadata missing"