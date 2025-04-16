import os
import tempfile
import json
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

from core.vault.creator import create_vault, find_existing_vaults

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
        keys_dir = tmp / ".vaultic" / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Change current working dir to tmp for relative paths
        original_dir = os.getcwd()
        os.chdir(tmp)
        
        yield tmp, keys_dir
        
        # Change back to original dir
        os.chdir(original_dir)


def test_find_existing_vaults_empty_dir(temp_keys_dir):
    """Test finding vaults in an empty directory."""
    _, keys_dir = temp_keys_dir
    
    vaults = find_existing_vaults(keys_dir)
    assert len(vaults) == 0


def test_find_existing_vaults_with_vaults(temp_keys_dir):
    """Test finding vaults when vaults exist."""
    _, keys_dir = temp_keys_dir
    
    # Create fake vault dirs with metadata
    vault1 = keys_dir / "vault1"
    vault1.mkdir()
    meta1 = {
        "linked": False,
        "salt": "test_salt_1",
        "version": 1
    }
    (vault1 / "vaultic_meta.json").write_text(json.dumps(meta1))
    
    vault2 = keys_dir / "vault2"
    vault2.mkdir()
    meta2 = {
        "linked": True,
        "main_vault": "vault1",
        "salt": "test_salt_2",
        "version": 1
    }
    (vault2 / "vaultic_meta.json").write_text(json.dumps(meta2))
    
    vaults = find_existing_vaults(keys_dir)
    
    assert len(vaults) == 2
    assert "vault1" in [v[0] for v in vaults]
    assert "vault2" in [v[0] for v in vaults]
    
    # Check metadata is loaded correctly
    vault1_meta = next(m for v, m in vaults if v == "vault1")
    vault2_meta = next(m for v, m in vaults if v == "vault2")
    
    assert vault1_meta["linked"] is False
    assert vault2_meta["linked"] is True
    assert vault2_meta["main_vault"] == "vault1"


@patch("core.vault.creator.uuid4")
def test_create_independent_vault(mock_uuid, temp_keys_dir, mock_getpass):
    """Test creating an independent vault."""
    _, keys_dir = temp_keys_dir
    
    # Create a mock with a controlled hex attribute
    uuid_instance = MagicMock()
    uuid_instance.hex = "abcdef123456" * 2  # Make it long enough to be sliced
    mock_uuid.return_value = uuid_instance
    
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
                "version": 1,
                "linked": False
            }
            meta_path.write_text(json.dumps(meta_data))
            return instance
        
        mock_enc.side_effect = create_metadata
        
        # Run the function under test
        vault_id = create_vault(linked=False)
        
        # Verify the results
        assert vault_id == "abcdef123456", f"Expected 'abcdef123456', got '{vault_id}'"
        
        # Check vault directory and metadata
        vault_dir = keys_dir / vault_id
        meta_file = vault_dir / "vaultic_meta.json"
        
        assert vault_dir.exists(), f"Vault dir does not exist at {vault_dir}"
        assert meta_file.exists(), f"Meta file does not exist at {meta_file}"


@patch("core.vault.creator.uuid4")
def test_create_linked_vault_no_existing_vaults(mock_uuid, temp_keys_dir, mock_getpass):
    """Test creating a linked vault when no vaults exist."""
    _, keys_dir = temp_keys_dir
    
    # We need to mock two different UUID calls
    main_uuid = MagicMock()
    main_uuid.hex = "main123456789" * 2
    
    linked_uuid = MagicMock()
    linked_uuid.hex = "linked987654321" * 2
    
    # Setup the sequence of return values
    mock_uuid.side_effect = [main_uuid, linked_uuid]
    
    # Mock EncryptionService to create actual meta files
    with patch("core.encryption.service.EncryptionService") as mock_enc:
        instance = mock_enc.return_value
        instance.create_meta_test_file.return_value = None
        
        # Make constructor create metadata files
        def create_metadata(passphrase, meta_path):
            meta_path = Path(meta_path)
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            
            if "main123456" in str(meta_path):
                meta_data = {
                    "salt": "test_salt",
                    "version": 1,
                    "linked": False
                }
            else:
                meta_data = {
                    "salt": "test_salt", 
                    "version": 1,
                    "linked": True,
                    "main_vault": "main123456"
                }
            
            meta_path.write_text(json.dumps(meta_data))
            return instance
        
        mock_enc.side_effect = create_metadata
        
        # Run the function under test  
        vault_id = create_vault(linked=True)
        
        # Verify results
        assert vault_id == "main123456", f"Expected 'main123456', got '{vault_id}'"
        
        # Check both vault directories and metadata files
        main_vault_dir = keys_dir / "main123456"
        linked_vault_dir = keys_dir / "linked98765"
        
        assert main_vault_dir.exists(), f"Main vault dir not found at {main_vault_dir}" 
        assert (main_vault_dir / "vaultic_meta.json").exists(), "Main vault metadata missing"
        
        assert linked_vault_dir.exists(), f"Linked vault dir not found at {linked_vault_dir}"
        assert (linked_vault_dir / "vaultic_meta.json").exists(), "Linked vault metadata missing"


@patch("core.vault.creator.uuid4")
def test_create_linked_vault_with_existing_vault(mock_uuid, temp_keys_dir, mock_getpass):
    """Test creating a linked vault when a vault already exists."""
    _, keys_dir = temp_keys_dir
    
    # Create existing vault
    existing_id = "existing123"
    existing_dir = keys_dir / existing_id
    existing_dir.mkdir(parents=True, exist_ok=True)
    
    # Create metadata for existing vault
    existing_meta = {
        "salt": "test_salt",
        "version": 1,
        "linked": False,
        "pepper_hash": "pepper123"
    }
    (existing_dir / "vaultic_meta.json").write_text(json.dumps(existing_meta))
    
    # Create test file
    (existing_dir / ".meta-test").write_bytes(b"test data")
    
    # Mock UUID for the new linked vault
    new_uuid = MagicMock()
    new_uuid.hex = "newlinked123456" * 2
    mock_uuid.return_value = new_uuid
    
    # Mock the prompt to select existing vault
    with patch("typer.prompt") as mock_prompt:
        mock_prompt.return_value = 1  # Select first vault
        
        # Mock EncryptionService
        with patch("core.encryption.service.EncryptionService") as mock_enc:
            instance = mock_enc.return_value
            instance.create_meta_test_file.return_value = None
            instance.verify_passphrase.return_value = None
            
            # Make constructor create metadata
            def create_metadata(passphrase, meta_path):
                meta_path = Path(meta_path)
                meta_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Create metadata for new linked vault
                if "newlinked12" in str(meta_path):
                    meta_data = {
                        "salt": "test_salt",
                        "version": 1, 
                        "linked": True,
                        "main_vault": existing_id,
                        "pepper_hash": "pepper123"
                    }
                    meta_path.write_text(json.dumps(meta_data))
                
                return instance
            
            mock_enc.side_effect = create_metadata
            
            # Run the function under test
            vault_id = create_vault(linked=True)
            
            # Verify results
            assert vault_id == "newlinked12", f"Expected 'newlinked12', got '{vault_id}'"
            
            # Check linked vault directory and metadata
            linked_dir = keys_dir / vault_id
            assert linked_dir.exists(), f"Linked vault dir not found at {linked_dir}"
            assert (linked_dir / "vaultic_meta.json").exists(), "Linked vault metadata missing"