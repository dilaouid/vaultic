import os
import tempfile
from pathlib import Path
from typer.testing import CliRunner
from cli.main import app
from core.encryption.service import EncryptionService

runner = CliRunner()

def create_sample_file(path: Path, content: bytes = b"Hello Vaultic"):
    path.write_bytes(content)
    return content


from core.config import Config

def test_restore_file_success(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)

        key_path = tmp / "vaultic.key"
        input_file = tmp / "test.txt"
        encrypted_file = tmp / "test.txt.enc"
        restored_file = tmp / "restored.txt"

        # Patch the config directly
        monkeypatch.setattr(Config, "KEY_PATH", str(key_path))

        # Encrypt manually
        enc = EncryptionService(key_path=str(key_path))
        content = create_sample_file(input_file)
        enc.encrypt_file(str(input_file), str(encrypted_file))

        # Run the CLI (which now uses the patched Config.KEY_PATH)
        result = runner.invoke(app, [
            "restore", "file",
            str(encrypted_file),
            "--output-path", str(restored_file)
        ])

        # Assertions
        assert result.exit_code == 0
        assert restored_file.exists()
        assert restored_file.read_bytes() == content
        assert "✅" in result.output


def test_restore_file_fails_if_missing():
    result = runner.invoke(app, ["restore", "file", "nonexistent.txt.enc"])
    assert result.exit_code != 0
    assert "❌" in result.output
    assert "not found" in result.output


def test_restore_file_refuses_unencrypted_file():
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / "file.txt"
        path.write_text("Not encrypted")
        result = runner.invoke(app, ["restore", "file", str(path)])
        assert result.exit_code != 0
        assert "❌" in result.output
        assert "expected .enc extension" in result.output