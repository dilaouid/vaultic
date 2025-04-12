from core.config import Config
from core.storage.mock import MockLocalProvider

def get_provider(name: str):
    """
    Return the correct storage provider based on name.

    Args:
        name (str): Name of the provider (e.g. "mock", "google_drive", "backblaze")

    Returns:
        StorageProvider: Provider instance
    """
    name = name.lower()

    if name == "mock":
        return MockLocalProvider()

    # Later:
    # if name == "google_drive":
    #     return GoogleDriveProvider(...)
    # if name == "backblaze":
    #     return BackblazeProvider(...)

    raise ValueError(f"Unknown provider: {name}")