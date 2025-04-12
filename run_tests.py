import os
import sys

def ensure_env():
    env_path = ".env.test"
    if os.path.exists(env_path):
        print(f"📦 Loading test env from {env_path}")
        os.environ.update({k: v for k, v in [line.strip().split('=') for line in open(env_path) if '=' in line]})
    else:
        print("⚠️ No .env.test file found. Continuing without custom env.")

if __name__ == "__main__":
    ensure_env()
    import pytest
    sys.exit(pytest.main(["-v", *sys.argv[1:]]))