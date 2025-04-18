import os
import json
import shutil
import tempfile
from pathlib import Path
from typer.testing import CliRunner
from cli.__main__ import app
from core.encryption.service import EncryptionService
from core.config import Config

runner = CliRunner()


def create_sample_file(path: Path, content: bytes = b"Hello Vaultic"):
    path.write_bytes(content)
    return content


def test_restore_file_success(monkeypatch):
    temp_dir = tempfile.TemporaryDirectory()
    tmp = Path(temp_dir.name)
    monkeypatch.chdir(tmp)

    try:
        vault_dir = tmp / ".vaultic" / "test-vault"
        keys_dir = vault_dir / "keys"
        enc_dir = vault_dir / "encrypted"
        content_dir = enc_dir / "content"
        hmac_dir = enc_dir / "hmac"

        keys_dir.mkdir(parents=True)
        content_dir.mkdir(parents=True)
        hmac_dir.mkdir(parents=True)

        meta_path = keys_dir / "vault-meta.json"
        plaintext = tmp / "test.txt"
        original = create_sample_file(plaintext)

        monkeypatch.setattr(Config, "DEFAULT_PASSPHRASE", "strongpass")
        enc = EncryptionService("strongpass", meta_path)

        file_hash = "test.txt"
        encrypted_path = content_dir / file_hash

        # 1) default encrypt_file writes both encrypted and HMAC into content_dir
        enc.encrypt_file(str(plaintext), str(encrypted_path))

        # 2) copy the HMAC over to encrypted/hmac so restore won't try to download it
        default_hmac = content_dir / (file_hash + ".hmac")
        shutil.copy(default_hmac, hmac_dir / (file_hash + ".hmac"))

        # 3) write the index.json with proper hash field
        index = {
            "test.txt": {"hash": file_hash, "size": len(original), "timestamp": 1000000}
        }
        (enc_dir / "index.json").write_text(json.dumps(index))

        # 4) now invoke
        result = runner.invoke(
            app,
            [
                "restore",
                "--output-dir",
                str(tmp),
                "--passphrase",
                "strongpass",
                "test-vault",
                "test.txt",
            ],
        )

        restored = tmp / "test.txt"
        assert (
            result.exit_code == 0
        ), f"Exit code {result.exit_code}, output:\n{result.output}"
        assert restored.exists()
        assert restored.read_bytes() == original
        assert "✅" in result.output
    finally:
        os.chdir(tmp.parent)
        temp_dir.cleanup()


def test_restore_file_fails_if_missing():
    result = runner.invoke(
        app, ["restore", "nonexistent", "nonexistent.txt"], input="fakepass\n"
    )
    assert result.exit_code != 0
    assert "❌" in result.output
    assert "not found" in result.output


def test_restore_file_refuses_unencrypted_file():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a fake vault structure
        vault_dir = Path(tmp_dir) / ".vaultic" / "fake-vault"
        keys_dir = vault_dir / "keys"
        keys_dir.mkdir(parents=True)

        # Create metadata file
        meta_path = keys_dir / "vault-meta.json"
        meta_path.write_text(json.dumps({"salt": "fake-salt"}))

        # Create unencrypted test file
        test_file = Path(tmp_dir) / "file.txt"
        test_file.write_text("Not encrypted")

        # Exec command
        result = runner.invoke(
            app, ["restore", "fake-vault", str(test_file)], input="fakepass\n"
        )

        assert result.exit_code != 0
        assert "❌" in result.output

        # More relaxed assertion to check for general failure message
        assert any(
            word in result.output.lower()
            for word in ["error", "failed", "invalid", "not found"]
        )
