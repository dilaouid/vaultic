import tempfile
from pathlib import Path
from core.encryption.service import EncryptionService


def test_encryption_and_decryption_file():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)

        key_path = tmp / "vaultic.key"
        input_file = tmp / "plain.txt"
        encrypted_file = tmp / "plain.txt.enc"
        decrypted_file = tmp / "plain_restored.txt"

        # Write sample file
        content = b"This is Vaultic content"
        input_file.write_bytes(content)

        # Initialize service and encrypt/decrypt
        service = EncryptionService(key_path=str(key_path))
        service.encrypt_file(str(input_file), str(encrypted_file))
        service.decrypt_file(str(encrypted_file), str(decrypted_file))

        # Assertions
        assert encrypted_file.exists()
        assert decrypted_file.exists()
        assert decrypted_file.read_bytes() == content


def test_generate_key_length():
    key = EncryptionService.generate_key()
    assert isinstance(key, bytes)
    assert len(key) == 44  # 32 bytes base64 encoded
