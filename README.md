## 🧾 Vaultic – Encrypted Incremental Backups to the Cloud

### 🔐 What is Vaultic?

Vaultic is a Python-powered CLI (and soon GUI, *I hope*) tool to **encrypt**, **version**, and **backup** your files to the cloud — securely and incrementally.

Built for developers, freelancers, and privacy-focused users who want to store files in **Google Drive or Backblaze B2**, or any supported provider (for now, there's only those two, I personnaly recommand you using **Backblaze B2** for obvious reasons), with **zero trust** in the storage layer.

---

### 📦 Features

- 🔐 AES encryption + RSA for key management
- ☁️ Upload to Google Drive or Backblaze B2
- 📁 Incremental backup (saves only changes)
- 💾 Local key generation and management
- 🖥 GUI for browsing encrypted folders
- 🧪 Fully testable core logic
- 🧰 Easy to extend with new cloud providers

---

### Encrypted Folder Navigation

The Vaultic GUI acts as a secure viewer into your encrypted backup directories.
You can browse folders, view decrypted filenames, and even open files (like images or documents) on-the-fly, decrypted temporarily in memory or in a secure temp folder.

Your data stays fully encrypted on disk

No clear-text files are stored unless explicitly exported

Works seamlessly with nested folders, previews, and quick restores

Imagine an encrypted vault that opens up like a regular file explorer — that's Vaultic's GUI philosophy.

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
- [ ] Encrypted folder browser in GUI
- [ ] Encrypted file preview in GUI
- [ ] Automatic scheduling
- [ ] Multi-provider sync
- [ ] Scheduling
- [ ] Versioning and differential backup

---

### 🛡 Security Notice

Vaultic encrypts your files **locally**, before anything is sent to the cloud.
All decryption is handled on demand, and only temporarily in memory or isolated disk space.
Vaultic never uploads, stores, or syncs your key or decrypted data.

If you lose your key, your files are lost. Forever.
(Yes, really.)