import tempfile
from pathlib import Path
from typer.testing import CliRunner
from cli.main import app
from core.indexing.indexer import save_index

runner = CliRunner()

def test_list_index_outputs_table():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)

        # Simulated index
        index_data = {
            "files": [
                {
                    "relative_path": "docs/readme.md",
                    "encrypted_path": "/tmp/encrypted/docs/readme.md.enc",
                    "hash": "abcdef1234567890"
                },
                {
                    "relative_path": "src/app.py",
                    "encrypted_path": "/tmp/encrypted/src/app.py.enc",
                    "hash": "123456abcdef0987"
                }
            ]
        }

        index_path = tmp / "index.json"
        save_index(index_data, index_path)

        result = runner.invoke(app, [
            "list",
            "--index-path", str(index_path)
        ])

        assert result.exit_code == 0
        assert "docs/readme.md" in result.output
        assert "src/app.py" in result.output
        assert "abcdef" in result.output


def test_list_index_fails_when_missing():
    result = runner.invoke(app, [
        "list",
        "--index-path", "nonexistent.json"
    ])
    assert result.exit_code != 0
    assert "❌" in result.output

def test_list_index_json_output():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)

        index_data = {
            "files": [
                {
                    "relative_path": "vault/data.json",
                    "encrypted_path": "/tmp/encrypted/vault/data.json.enc",
                    "hash": "deadbeef12345678"
                }
            ]
        }

        index_path = tmp / "index.json"
        save_index(index_data, index_path)

        result = runner.invoke(app, [
            "list",
            "--index-path", str(index_path),
            "--json"
        ])

        assert result.exit_code == 0
        assert "vault/data.json" in result.output
        assert "deadbeef" in result.output
        assert result.output.strip().startswith("{")  # JSON
