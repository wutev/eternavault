# Eterna

A personal fortress for digital privacy. Securely store your journal entries, passwords, 2FA codes, and encrypted files - all protected by strong encryption.

## Features

- **Secure Journal** - Private encrypted journal entries with version history
- **Password Manager** - Store and organize passwords with strength analysis
- **2FA Authenticator** - Generate TOTP codes, scan QR codes
- **Encrypted Files** - Securely store sensitive documents
- **Private Section** - Extra-protected notes with separate password
- **System Tray** - Quick access and background operation
- **Auto Updates** - Stay up to date automatically
- **Offline First** - All data stored locally, no cloud required
- **Audit Logging** - Track security events

## Installation

### From Release
Download the latest installer from the [Releases](../../releases) page.

### From Source
```bash
git clone https://github.com/wutev/eterna.git
cd eterna
npm install
npm start
```

## Building

```bash
# Build Windows installer
npm run build

# Build portable version
npm run build:portable
```

## Development

```bash
# Run linter
npm run lint

# Run tests
npm test
```

## Security

- **Encryption:** AES-256-GCM (authenticated encryption)
- **Key Derivation:** PBKDF2 with 600,000 iterations
- **Process Isolation:** Context isolation enabled, no node in renderer
- **Rate Limiting:** Brute-force protection on all authentication
- **Audit Logging:** Encrypted security event tracking
- **Local Only:** Data never leaves your device
- **No Telemetry:** Zero tracking or analytics

## License

MIT
