# EternaVault Security Implementation

## Overview

EternaVault now implements **military-grade encryption** to protect all your sensitive data, including passwords, 2FA codes, journal entries, and files.

---

## Security Features Implemented

### 1. **AES-256-GCM Encryption**
- All vault data is encrypted using AES-256-GCM (Galois/Counter Mode)
- Provides both confidentiality and authenticity (AEAD - Authenticated Encryption with Associated Data)
- Industry standard used by governments and financial institutions
- Each encryption operation uses a unique random IV (Initialization Vector)

### 2. **PBKDF2 Key Derivation**
- Master password is never stored or used directly for encryption
- Cryptographic key is derived using PBKDF2-SHA256
- **600,000 iterations** (2x Bitwarden standard)
- Unique random 32-byte salt per vault
- Protects against rainbow table and brute-force attacks

### 3. **Secure Session Management**
- Encryption key stored only in memory during unlocked sessions
- Key automatically cleared when:
  - Vault is locked manually
  - Application closes
  - System restarts
- No persistent storage of decrypted data

### 4. **Master Password Protection**
- Minimum 8 characters required
- Password strength validation
- SHA-256 hash verification (not used for encryption)
- Secure password change functionality

### 5. **Electron Security Best Practices**
- ✅ `nodeIntegration: false` - Renderer process has no Node.js access
- ✅ `contextIsolation: true` - Isolated JavaScript contexts
- ✅ `sandbox: true` - Process sandboxing (if enabled)
- ✅ Preload script with `contextBridge` - Controlled IPC surface
- ✅ Content Security Policy (CSP) - Prevents XSS attacks
- ✅ IPC input validation - All inputs sanitized

---

## How It Works

### First Time Setup

```javascript
// 1. User creates master password
const result = await window.vault.initialize('MySecurePassword123!');

// 2. System generates:
//    - Random 32-byte salt
//    - Derives encryption key using PBKDF2 (600,000 iterations)
//    - Creates empty encrypted vault
//    - Stores salt and password hash (NOT the actual password)
```

### Unlocking the Vault

```javascript
// 1. User enters master password
const result = await window.vault.unlock('MySecurePassword123!');

// 2. System:
//    - Verifies password hash
//    - Derives encryption key from password + stored salt
//    - Stores key in memory (session only)
//    - Vault remains unlocked until locked or app closes
```

### Storing Data

```javascript
// All data is automatically encrypted before storage
await window.storage.set('passwords', {
  gmail: { username: 'user@gmail.com', password: 'secret123' },
  github: { username: 'developer', password: 'hunter2' }
});

// On disk, this is stored as:
// {
//   "data": "a1b2c3d4e5f6...",  // Encrypted hex string
//   "iv": "1a2b3c4d...",         // Random IV
//   "tag": "9z8y7x6w...",        // Authentication tag
//   "version": "1.0",
//   "algorithm": "aes-256-gcm"
// }
```

### Retrieving Data

```javascript
// Data is automatically decrypted when retrieved
const result = await window.storage.get('passwords');
console.log(result.value); // { gmail: {...}, github: {...} }
```

### Locking the Vault

```javascript
// Manually lock
await window.vault.lock();

// Or automatically locked when:
// - User clicks "Lock" button
// - App closes
// - System restarts
```

---

## API Reference

### Vault Management

```javascript
// Check if vault has been initialized
const { initialized } = await window.vault.isInitialized();

// Initialize new vault with master password
const { success, strength } = await window.vault.initialize(masterPassword);

// Unlock vault
const { success, error } = await window.vault.unlock(masterPassword);

// Lock vault (clears session key from memory)
await window.vault.lock();

// Check if vault is currently unlocked
const { unlocked } = await window.vault.isUnlocked();
```

### Master Password Management

```javascript
// Change master password (re-encrypts all data)
const result = await window.vault.changeMasterPassword(
  'OldPassword123!',
  'NewPassword456!'
);

// Validate password strength
const { valid, strength, feedback } = await window.vault.validatePassword('TestPass123');
// strength: 'very-weak' | 'weak' | 'medium' | 'strong' | 'very-strong'

// Generate cryptographically secure random password
const { password } = await window.vault.generatePassword(32, {
  includeUppercase: true,
  includeLowercase: true,
  includeNumbers: true,
  includeSymbols: true
});
```

### Encrypted Storage

```javascript
// Store encrypted data
await window.storage.set(key, value);

// Retrieve decrypted data
const { success, value } = await window.storage.get(key);

// Delete data
await window.storage.delete(key);
```

---

## Security Considerations

### ✅ What's Protected

- **All vault data** is encrypted at rest
- **Master password** is never stored (only hash for verification)
- **Encryption key** exists only in memory during unlocked sessions
- **Data in transit** between processes uses Electron IPC (sandboxed)
- **Password strength** is enforced
- **CSRF/XSS attacks** are mitigated by CSP

### ⚠️ What You Should Know

1. **Master Password is Critical**
   - If forgotten, **data cannot be recovered** (this is by design)
   - No backdoor or recovery mechanism exists
   - Choose a strong, memorable password

2. **Memory Security**
   - Encryption key exists in RAM while unlocked
   - Advanced attackers with physical access could potentially dump memory
   - Lock vault when not in use
   - Enable auto-lock timeout in settings

3. **File System Security**
   - Encrypted data files are stored at: `%APPDATA%/eternavault/vault-data.json`
   - Files are encrypted, but ensure disk encryption (BitLocker) for defense-in-depth
   - Backup encrypted vault files regularly

4. **Secure Deletion**
   - Deleted data is removed from vault but may persist in file system slack space
   - For highly sensitive data, use secure erase tools or full disk encryption

---

## Threat Model

### Protected Against

| Attack Vector | Protection |
|---------------|------------|
| File theft | AES-256-GCM encryption |
| Brute force | PBKDF2 with 600k iterations |
| Rainbow tables | Unique random salt per vault |
| XSS attacks | Content Security Policy |
| IPC injection | Context isolation + validation |
| Memory scraping (offline) | Data encrypted at rest |
| Weak passwords | Strength validation |
| Data tampering | GCM authentication tag |

### NOT Protected Against

| Attack Vector | Mitigation |
|---------------|------------|
| Keyloggers | Use secure input methods, keep OS updated |
| Screen capture | Lock vault when not in use |
| Memory dump (while unlocked) | Auto-lock timeout, lock when idle |
| Physical access (unlocked) | Lock vault manually, enable screen lock |
| Compromised system | Keep OS/antivirus updated, avoid malware |
| Clipboard sniffing | Clear clipboard after use |

---

## Cryptographic Details

### Encryption Algorithm
- **Algorithm**: AES-256-GCM
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 128 bits (16 bytes) - randomly generated per operation
- **Tag Size**: 128 bits (16 bytes) - for authentication
- **Mode**: GCM (Galois/Counter Mode) - AEAD

### Key Derivation
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 600,000 (2x Bitwarden standard)
- **Salt Size**: 256 bits (32 bytes) - randomly generated per vault
- **Output Key Size**: 256 bits (32 bytes)

### Random Number Generation
- Uses Node.js `crypto.randomBytes()` backed by OS CSPRNG
- **Windows**: `CryptGenRandom` (BCrypt)
- **Linux**: `/dev/urandom`
- **macOS**: `/dev/random`

### Password Hashing (for verification only)
- **Algorithm**: SHA-256
- **Purpose**: Verify master password correctness
- **NOT used for encryption** (PBKDF2 key used instead)

---

## Compliance & Standards

This implementation follows:
- ✅ **OWASP Cryptographic Storage Cheat Sheet**
- ✅ **NIST SP 800-132** (Key Derivation)
- ✅ **NIST SP 800-38D** (AES-GCM)
- ✅ **Electron Security Guidelines**
- ✅ **FIPS 197** (AES)

---

## Migration from Unencrypted Storage

If you have existing data in localStorage or unencrypted storage:

```javascript
// 1. Export old data
const oldData = localStorage.getItem('pm-data');
const oldPasswords = JSON.parse(oldData);

// 2. Initialize new encrypted vault
await window.vault.initialize('YourMasterPassword');
await window.vault.unlock('YourMasterPassword');

// 3. Migrate data to encrypted storage
await window.storage.set('passwords', oldPasswords.passwords);

// 4. Clear old unencrypted data
localStorage.removeItem('pm-data');
```

---

## Audit & Testing

### Encryption Module Tests

Run the following to verify encryption:

```javascript
const encryption = require('./encryption');

// Test key derivation
const { key, salt } = encryption.deriveKey('TestPassword123!');
console.log('Key length:', key.length); // Should be 32

// Test encryption/decryption
const testData = { secret: 'Hello World' };
const { encrypted, iv, tag } = encryption.encrypt(testData, key);
const decrypted = encryption.decrypt(encrypted, iv, tag, key);
console.log('Match:', JSON.stringify(testData) === JSON.stringify(decrypted));
```

### Security Checklist

- [x] nodeIntegration disabled
- [x] contextIsolation enabled
- [x] Preload script with contextBridge
- [x] CSP implemented
- [x] AES-256-GCM encryption
- [x] PBKDF2 key derivation (600k iterations)
- [x] Random salt generation
- [x] Session key in memory only
- [x] Password strength validation
- [x] IPC input validation
- [x] No plaintext password storage
- [x] Authentication tags for tampering detection

---

## Support & Reporting

If you discover a security vulnerability:
- **DO NOT** open a public issue
- Email: [Insert security contact]
- PGP Key: [Insert if available]

For general security questions, see documentation or open a regular issue.

---

**Last Updated**: 2026-01-16
**Version**: 1.0
**Encryption Module Version**: 1.0
