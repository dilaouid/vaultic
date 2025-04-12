import pytest
from dotenv import load_dotenv
from pathlib import Path

@pytest.fixture(autouse=True, scope="session")
def load_test_env():
    """
    Automatically load environment variables from `.env.test` for all test sessions.
    """
    env_path = Path(".env.test")
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=True)
        print("📦 Test environment loaded from .env.test")
    else:
        print("⚠️  No .env.test file found. Using default environment.")