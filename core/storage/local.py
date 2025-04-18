from pathlib import Path
from rich import print


class LocalStorage:
    def upload_file(self, source: Path, destination: str):
        # simulate a fake upload
        print(f"[grey]↪ Simulated upload: {destination}[/grey]")
