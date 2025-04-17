import os
import tempfile
import json
from pathlib import Path

from core.encryption.service import EncryptionService

def test_pepper_hash_consistency_check():
    """Test the consistency check for pepper hash."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        
        # First, save the current environment pepper if it exists
        original_pepper = os.environ.get("VAULTIC_PEPPER")
        
        try:
            # Create service with initial pepper
            os.environ["VAULTIC_PEPPER"] = "initial_pepper"
            service1 = EncryptionService("test", meta)
            
            # Ensure pepper_hash is added to metadata
            meta_data = json.loads(meta.read_text())
            assert "pepper_hash" in meta_data, "Pepper hash not found in metadata"
            
            # Manually clear the pepper_hash to simulate old metadata format
            meta_data.pop("pepper_hash", None)
            with open(meta, 'w') as f:
                json.dump(meta_data, f)
            
            # Load again with same pepper, should add pepper_hash
            service2 = EncryptionService("test", meta)
            meta_data2 = json.loads(meta.read_text())
            assert "pepper_hash" in meta_data2, "Pepper hash not added to existing metadata"
            
        finally:
            # Restore original environment
            if original_pepper is not None:
                os.environ["VAULTIC_PEPPER"] = original_pepper
            else:
                del os.environ["VAULTIC_PEPPER"]