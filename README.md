## 🧾 Vaultic – Secure Encrypted Vaults with Cloud Backup

### 🔐 What is Vaultic?

Vaultic is a Python-powered CLI tool to create **encrypted vaults**, manage **secure file storage**, and **back up** your sensitive data to the cloud — with zero-knowledge encryption.

Built for developers, freelancers, and privacy-focused users who want to store files in **Google Drive or Backblaze B2**, or any supported cloud provider, with **zero trust** in the storage layer.

---

### 📦 Features

- 🔒 Vault-based file management with AES-256 encryption
- 🔑 Passphrase-based security with no key files to manage
- 🛡️ Zero-knowledge architecture - only you can decrypt your data
- 📁 Automatic watch mode to encrypt files as they're added
- ☁️ Cloud backup to Google Drive or Backblaze B2
- 🔄 Integrity verification with HMAC signatures
- 🧪 Fully testable core logic
- 🧰 Easy to extend with new cloud providers

---

### Encrypted Vault System

Vaultic works with the concept of encrypted vaults:

- **Create vaults** for different projects, clients, or data types
- **Drop files** into a vault to have them automatically encrypted and backed up
- **Browse encrypted files** by name without revealing content
- **Restore files** when needed with your secure passphrase

Your data stays fully encrypted both locally and in the cloud:

- Files are encrypted with AES-256 before leaving your device
- Filenames and metadata are also encrypted
- No plaintext indexes or data are stored on disk
- Data can only be decrypted with your passphrase

---

### ⚙️ Installation

```bash
git clone https://github.com/dilaouid/vaultic.git
cd vaultic
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

### 🚀 Getting Started

1. Configure your `.env` file (see `.env.example`)
2. Create your first vault:

```bash
python vaultic.py create -n projects
```

3. Enter a strong passphrase when prompted - this is your only key to decrypt your files!

4. Start watching the vault for automatic encryption:

```bash
python vaultic.py watch
```

5. Now simply drop files into `.vaultic/projects/` and they'll be automatically encrypted and backed up.

---

### 💻 Core Commands

```bash
# Create a new vault
python vaultic.py create -n <vault-name>

# Watch a vault for automatic encryption
python vaultic.py watch [vault-id]

# List all vaults
python vaultic.py list vaults

# List files in a vault
python vaultic.py list files <vault-id>

# Restore a file from a vault
python vaultic.py restore <vault-id> <file-path> --output-dir ./restored
```

Use `--help` with any command for more options.

---

### 📁 Configuration (.env)

```env
# Default cloud provider
PROVIDER=backblaze

# Security settings
VAULTIC_DEFAULT_PASSPHRASE=secure-default-passphrase
VAULTIC_OVERWRITE_EXISTING=ask  # yes, no, ask

# Google Drive config
GOOGLE_DRIVE_CLIENT_ID=...
GOOGLE_DRIVE_CLIENT_SECRET=...
GOOGLE_DRIVE_REFRESH_TOKEN=...
GOOGLE_DRIVE_FOLDER_ID=...

# Backblaze B2 config
B2_ACCOUNT_ID=...
B2_APPLICATION_KEY=...
B2_BUCKET_NAME=...
```

---

### 🔧 Roadmap

- [x] Vault-based file management
- [x] AES-256 encryption with HMAC integrity checking
- [x] Automatic watch mode
- [x] Encrypted index for file tracking
- [ ] Improved cloud provider integrations
- [ ] GUI for browsing encrypted folders
- [ ] Version history and differential backups
- [ ] Multi-provider synchronization
- [ ] Scheduled backup jobs

---

### 🛡 Security Notice

Vaultic employs a zero-knowledge architecture:

- Files are encrypted with AES-256 **before** leaving your device
- Your passphrase is used to derive cryptographic keys via PBKDF2
- File metadata and names are also encrypted
- HMAC signatures ensure file integrity
- All encryption/decryption happens locally

**Important**: Your passphrase is used to protect all your data. If you forget it, your files are permanently lost. There is no recovery mechanism by design.