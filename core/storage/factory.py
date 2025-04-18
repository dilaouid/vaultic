from core.storage.local import LocalStorage


def get_provider(name: str):
    if name == "local":
        return LocalStorage()
    raise ValueError(f"Unknown provider: {name}")
