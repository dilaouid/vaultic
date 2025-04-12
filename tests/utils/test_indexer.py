import tempfile
from pathlib import Path
from core.indexing.indexer import generate_index

def test_generate_index_structure_and_paths():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)

        # Create test files
        source = tmp / "source"
        encrypted = tmp / "encrypted"
        source.mkdir()
        encrypted.mkdir()

        # Simulate files and subfolders
        (source / "file1.txt").write_text("hello")
        (source / "file2.md").write_text("vaultic")
        subfolder = source / "sub"
        subfolder.mkdir()
        (subfolder / "nested.txt").write_text("sub content")

        index = generate_index(source, encrypted)

        # Check global structure
        assert "files" in index
        assert len(index["files"]) == 3

        # Check fields
        for f in index["files"]:
            assert "relative_path" in f
            assert "encrypted_path" in f
            assert "hash" in f

            relative = Path(f["relative_path"])
            encrypted_path = Path(f["encrypted_path"])

            assert (source / relative).exists()
            assert encrypted_path.is_absolute()