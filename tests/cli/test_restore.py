import tempfile
from pathlib import Path
from typer.testing import CliRunner
from cli.main import app
from core.encryption.service import EncryptionService
from core.config import Config

runner = CliRunner()

def create_sample_file(path: Path, content: bytes = b"Hello Vaultic"):
    path.write_bytes(content)
    return content

def test_restore_file_success(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)

        meta_path = tmp / "vaultic_meta.json"
        input_file = tmp / "test.txt"
        encrypted_file = tmp / "test.txt.enc"
        restored_file = tmp / "restored.txt"

        monkeypatch.setattr(Config, "META_PATH", str(meta_path))

        enc = EncryptionService(passphrase="strongpass", meta_path=meta_path)
        content = create_sample_file(input_file)
        enc.encrypt_file(str(input_file), str(encrypted_file))

        result = runner.invoke(app, [
            "restore", "file",
            str(encrypted_file),
            "--output-path", str(restored_file),
            "--meta-path", str(meta_path)
        ], input="strongpass\n")

        assert result.exit_code == 0
        assert restored_file.exists()
        assert restored_file.read_bytes() == content
        assert "✅" in result.output

def test_restore_file_fails_if_missing():
    result = runner.invoke(app, ["restore", "file", "nonexistent.txt.enc"], input="fakepass\n")
    assert result.exit_code != 0
    assert "❌" in result.output
    assert "not found" in result.output

def test_restore_file_refuses_unencrypted_file():
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / "file.txt"
        path.write_text("Not encrypted")
        result = runner.invoke(app, ["restore", "file", str(path)], input="fakepass\n")
        assert result.exit_code != 0
        assert "❌" in result.output
        assert "expected .enc extension" in result.output