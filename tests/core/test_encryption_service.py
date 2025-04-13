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