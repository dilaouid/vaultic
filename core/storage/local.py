from pathlib import Path
from core.utils import console

class LocalStorage:
    def upload_file(self, source: Path, destination: str):
        # simulate a fake upload
        console.print(f"[grey]↪ Simulated upload: {destination}[/grey]")