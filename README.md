## 🧾 Vaultic – Encrypted Incremental Backups to the Cloud

### 🔐 What is Vaultic?

Vaultic is a Python-powered CLI (and soon GUI, *I hope*) tool to **encrypt**, **version**, and **backup** your files to the cloud — securely and incrementally.

Built for developers, freelancers, and privacy-focused users who want to store files in **Google Drive or Backblaze B2**, or any supported provider (for now, there's only those two, I personnaly recommand you using **Backblaze B2** for obvious reasons), with **zero trust** in the storage layer.

---

### 📦 Features

- 🔐 AES and RSA encryption
- ☁️ Upload to Google Drive or Backblaze B2
- 📁 Incremental backup (saves only changes)
- 💾 Local key generation and management
- ✅ CLI and GUI (cross-platform)
- 🧪 Fully testable core logic
- 🧰 Easy to extend with new cloud providers

---

### ⚙️ Installation

```bash
git clone https://github.com/dilaouid/vaultic.git
cd vaultic
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

### 🚀 First-time setup

1. Configure your `.env` file (see `.env.example`)
2. Run the init script:

```bash
python scripts/init_env.py
```

This will generate a `.pem` encryption key. **Store it securely** — without it, your backups are lost forever. Like, really. Unless you can remember it, and you're kinda smart.

---

### 💻 Usage (CLI)

```bash
python cli/main.py backup file ./my-secret.txt
```

More commands:
```bash
vaultic backup dir ./Documents
vaultic restore file ./my-secret.txt.enc
vaultic list
```

Use `--provider` to override the default provider (set in `.env`).

---

### 📁 Configuration (.env)

```env
PROVIDER=google_drive

VAULTIC_BACKUP_DIR=./data/
VAULTIC_INDEX_FILE=./data/.vaultic/index.json
VAULTIC_LOG_FILE=./data/.vaultic/backup.log
VAULTIC_ENCRYPTION_KEY_PATH=~/.vaultic_key.pem

GOOGLE_DRIVE_CLIENT_ID=...
GOOGLE_DRIVE_CLIENT_SECRET=...
GOOGLE_DRIVE_REFRESH_TOKEN=...

B2_ACCOUNT_ID=...
B2_APPLICATION_KEY=...
B2_BUCKET_NAME=...
```

---

### 🔧 Roadmap

- [ ] CLI with encryption + cloud upload
- [x] Key generation and persistence
- [ ] GUI (Tkinter or Tauri)
- [ ] Automatic scheduling
- [ ] Multi-provider sync
- [ ] Versioning and differential backup

---

### 🛡 Security Notice

Vaultic encrypts your files **locally**, before anything is sent to the cloud.  
Vaultic never sends your key or decrypted data over the network.
