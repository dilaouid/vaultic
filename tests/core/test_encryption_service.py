import os
import json
import tempfile
from pathlib import Path
import pytest

from core.encryption.service import EncryptionService

def create_sample_file(path: Path, content: bytes = b"Vaultic Test Content"):
    path.write_bytes(content)
    return content

def test_encrypt_decrypt_cycle():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        plain = tmp / "plain.txt"
        enc = tmp / "plain.txt.enc"
        dec = tmp / "plain_decrypted.txt"

        content = create_sample_file(plain, b"Test content")
        service = EncryptionService(passphrase="vaultic", meta_path=meta)
        service.encrypt_file(plain, enc)
        service.decrypt_file(enc, dec)

        assert dec.read_bytes() == content
        assert (tmp / "plain.txt.enc.hmac").exists()


def test_hmac_detection_on_tampering():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        plain = tmp / "plain.txt"
        enc = tmp / "plain.txt.enc"
        dec = tmp / "plain_decrypted.txt"

        create_sample_file(plain)
        service = EncryptionService("test123", meta)
        service.encrypt_file(plain, enc)

        enc.write_bytes(b"tampered data")

        with pytest.raises(ValueError, match="magic header"):
            service.decrypt_file(enc, dec)


def test_missing_hmac_file_raises_error():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        plain = tmp / "plain.txt"
        enc = tmp / "plain.txt.enc"
        dec = tmp / "plain_decrypted.txt"

        create_sample_file(plain)
        service = EncryptionService("test123", meta)
        service.encrypt_file(plain, enc)

        enc.with_suffix(".enc.hmac").unlink()

        with pytest.raises(ValueError, match="Missing HMAC"):
            service.decrypt_file(enc, dec)


def test_salt_is_created_and_loaded():
    with tempfile.TemporaryDirectory() as tmp_dir:
        meta = Path(tmp_dir) / "vaultic_meta.json"
        EncryptionService("checksalt", meta)

        assert meta.exists()
        meta_content = meta.read_text()
        assert "salt" in meta_content


def test_passphrase_validation_correct_vs_wrong():
    with tempfile.TemporaryDirectory() as tmp_dir:
        meta = Path(tmp_dir) / "vaultic_meta.json"
        EncryptionService("correct", meta).create_meta_test_file()

        # Correct
        EncryptionService("correct", meta).verify_passphrase()

        # Wrong
        with pytest.raises(ValueError, match="Invalid passphrase"):
            EncryptionService("wrong", meta).verify_passphrase()


def test_compression_is_effective():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        file = tmp / "redundant.txt"
        encrypted = tmp / "redundant.txt.enc"

        repeated_content = b"X" * 1000
        create_sample_file(file, repeated_content)

        service = EncryptionService("compress", meta)
        service.encrypt_file(file, encrypted)

        assert encrypted.stat().st_size < len(repeated_content)


def test_multiple_encryptions_produce_different_outputs():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        f1 = tmp / "a.txt"
        f2 = tmp / "b.txt"
        e1 = tmp / "a.txt.enc"
        e2 = tmp / "b.txt.enc"

        content = b"Same content for both"
        create_sample_file(f1, content)
        create_sample_file(f2, content)

        service = EncryptionService("randomness", meta)
        service.encrypt_file(f1, e1)
        service.encrypt_file(f2, e2)

        assert e1.read_bytes() != e2.read_bytes()

def test_hmac_detection_if_tag_modified():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        plain = tmp / "plain.txt"
        enc = tmp / "plain.txt.enc"
        dec = tmp / "plain_decrypted.txt"

        create_sample_file(plain)
        service = EncryptionService("test123", meta)
        service.encrypt_file(plain, enc)

        hmac_path = enc.with_suffix(enc.suffix + ".hmac")
        hmac_path.write_bytes(b"bad hmac data")

        with pytest.raises(ValueError, match="HMAC mismatch"):
            service.decrypt_file(enc, dec)

def create_sample_file(path: Path, content: bytes = b"Vaultic Test Content"):
    path.write_bytes(content)
    return content

def test_pepper_is_used_in_key_derivation(monkeypatch):
    """Test that pepper affects key derivation."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        plain = tmp / "plain.txt"
        enc1 = tmp / "enc1.txt.enc"
        enc2 = tmp / "enc2.txt.enc"
        
        # Set a known pepper
        monkeypatch.setenv("VAULTIC_PEPPER", "test_pepper_value")
        
        # Create file and encrypt with first pepper
        content = create_sample_file(plain)
        service1 = EncryptionService(passphrase="same_passphrase", meta_path=meta)
        service1.encrypt_file(plain, enc1)
        
        # Change pepper and encrypt same file
        monkeypatch.setenv("VAULTIC_PEPPER", "different_pepper_value")
        # Need to create a new meta file since the pepper hash is stored
        meta2 = tmp / "meta2.json"
        service2 = EncryptionService(passphrase="same_passphrase", meta_path=meta2)
        service2.encrypt_file(plain, enc2)
        
        # The encrypted contents should be different due to different peppers
        assert enc1.read_bytes() != enc2.read_bytes()

def test_pepper_hash_is_stored_in_metadata():
    """Test that pepper hash is stored in metadata."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        
        service = EncryptionService(passphrase="test", meta_path=meta)
        
        # Check if pepper_hash is in metadata
        meta_content = json.loads(meta.read_text())
        assert "pepper_hash" in meta_content
        assert isinstance(meta_content["pepper_hash"], str)
        assert len(meta_content["pepper_hash"]) > 0

def test_same_passphrase_different_salts():
    """Test that different salts produce different encryption results."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta1 = tmp / "meta1.json"
        meta2 = tmp / "meta2.json"
        plain = tmp / "plain.txt"
        enc1 = tmp / "enc1.txt.enc"
        enc2 = tmp / "enc2.txt.enc"
        
        # Create test file
        content = create_sample_file(plain)
        
        # Create two encryption services with different metadata files
        # This will generate different salts
        service1 = EncryptionService(passphrase="same_pass", meta_path=meta1)
        service2 = EncryptionService(passphrase="same_pass", meta_path=meta2)
        
        # Encrypt same file with both services
        service1.encrypt_file(plain, enc1)
        service2.encrypt_file(plain, enc2)
        
        # The outputs should be different due to different salts
        assert enc1.read_bytes() != enc2.read_bytes()
        
        # Both should be decryptable with their respective services
        dec1 = tmp / "dec1.txt"
        dec2 = tmp / "dec2.txt"
        service1.decrypt_file(enc1, dec1)
        service2.decrypt_file(enc2, dec2)
        
        assert dec1.read_bytes() == content
        assert dec2.read_bytes() == content

def test_secure_clear_passphrase():
    """Test that the passphrase is cleared from memory after initialization."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        meta = Path(tmp_dir) / "meta.json"
        
        service = EncryptionService(passphrase="test_pass", meta_path=meta)
        
        # The passphrase attribute should not exist or be None after initialization
        assert not hasattr(service, 'passphrase') or service.passphrase is None

def test_metadata_version_field():
    """Test that metadata contains the version field."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        meta = Path(tmp_dir) / "meta.json"
        
        EncryptionService(passphrase="test", meta_path=meta)
        
        # Check metadata content
        meta_content = json.loads(meta.read_text())
        assert "version" in meta_content
        assert meta_content["version"] == 1  # Current version

def test_encryption_with_special_characters_in_passphrase():
    """Test encryption/decryption with special characters in passphrase."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        plain = tmp / "plain.txt"
        enc = tmp / "plain.txt.enc"
        dec = tmp / "plain_decrypted.txt"
        
        content = create_sample_file(plain)
        # Use passphrase with special characters
        service = EncryptionService(passphrase="!@#$%^&*()_+", meta_path=meta)
        service.encrypt_file(plain, enc)
        service.decrypt_file(enc, dec)
        
        assert dec.read_bytes() == content

def test_large_file_encryption():
    """Test encryption/decryption of a larger file."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        large = tmp / "large.bin"
        enc = tmp / "large.bin.enc"
        dec = tmp / "large_decrypted.bin"
        
        # Create a 1MB file with random data
        large_content = os.urandom(1024 * 1024)
        large.write_bytes(large_content)
        
        service = EncryptionService(passphrase="test", meta_path=meta)
        service.encrypt_file(large, enc)
        service.decrypt_file(enc, dec)
        
        assert dec.read_bytes() == large_content

def test_binary_file_encryption():
    """Test encryption/decryption of binary data with null bytes."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        binary = tmp / "binary.bin"
        enc = tmp / "binary.bin.enc"
        dec = tmp / "binary_decrypted.bin"
        
        # Create binary data with null bytes
        binary_content = b"\x00\x01\x02\x03\x00\xff\xfe\xfd"
        binary.write_bytes(binary_content)
        
        service = EncryptionService(passphrase="test", meta_path=meta)
        service.encrypt_file(binary, enc)
        service.decrypt_file(enc, dec)
        
        assert dec.read_bytes() == binary_content

def test_very_long_passphrase():
    """Test encryption/decryption with a very long passphrase."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        meta = tmp / "meta.json"
        plain = tmp / "plain.txt"
        enc = tmp / "plain.txt.enc"
        dec = tmp / "plain_decrypted.txt"
        
        content = create_sample_file(plain)
        # Use a very long passphrase (1000 characters)
        long_passphrase = "x" * 1000
        service = EncryptionService(passphrase=long_passphrase, meta_path=meta)
        service.encrypt_file(plain, enc)
        service.decrypt_file(enc, dec)
        
        assert dec.read_bytes() == content