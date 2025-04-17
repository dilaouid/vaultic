import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    VAULTIC_MAX_FILES_PER_MIN = int(os.getenv("VAULTIC_MAX_FILES_PER_MIN", "100"))
    PROVIDER = os.getenv("PROVIDER", "google_drive")
    BACKUP_DIR = os.getenv("VAULTIC_BACKUP_DIR", "./data/")
    INDEX_FILE = os.getenv("VAULTIC_INDEX_FILE", "./data/.vaultic/index.json")
    LOG_FILE = os.getenv("VAULTIC_LOG_FILE", "./data/.vaultic/backup.log")
    META_PATH = os.getenv("VAULTIC_META_PATH", ".vaultic/keys/vaultic_meta.json")
    GUI_TEMP_LIFETIME_SECONDS = os.getenv("GUI_TEMP_LIFETIME_SECONDS")
    VAULTIC_MAX_FILE_MB= int(os.getenv("VAULTIC_MAX_FILE_MB", "500"))
    OVERWRITE_EXISTING = os.getenv("VAULTIC_OVERWRITE", "ask")
    KEY_PATH = os.getenv("KEY_PATH", ".vaultic/keys/vaultic_key.pem")
    DEFAULT_PASSPHRASE = os.getenv("VAULTIC_DEFAULT_PASSPHRASE", "changeme")

    # Provider-specific configs
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_DRIVE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_DRIVE_CLIENT_SECRET")
    GOOGLE_REFRESH_TOKEN = os.getenv("GOOGLE_DRIVE_REFRESH_TOKEN")
    GOOGLE_FOLDER_ID = os.getenv("GOOGLE_DRIVE_FOLDER_ID")

    B2_ACCOUNT_ID = os.getenv("B2_ACCOUNT_ID")
    B2_APPLICATION_KEY = os.getenv("B2_APPLICATION_KEY")
    B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME")

    # 🔥 Mandatory pepper for encryption
    VAULTIC_PEPPER = os.getenv("VAULTIC_PEPPER")
    if not VAULTIC_PEPPER:
        raise RuntimeError("❌ VAULTIC_PEPPER is missing in environment (.env). Cannot continue.")