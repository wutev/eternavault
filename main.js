const { app, BrowserWindow, ipcMain, shell, Tray, Menu, nativeImage } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const encryption = require('./encryption');
const { SecureSessionKey, clearString } = require('./secure-memory');
const AuditLog = require('./audit-log');

// Set app name for Windows task manager and dialogs
app.setName('Eterna');

// Set Windows App User Model ID for notifications
if (process.platform === 'win32') {
  app.setAppUserModelId('com.eterna.app');
}

// Window and tray references
let mainWindow = null;
let tray = null;
let isQuitting = false;

// Single instance lock - only allow one instance of Eterna to run
const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  // Another instance is already running, quit this one
  app.quit();
} else {
  // Handle second instance attempt - focus the existing window
  app.on('second-instance', (_event, _commandLine, _workingDirectory) => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

// Configure auto-updater
autoUpdater.autoDownload = false;
autoUpdater.autoInstallOnAppQuit = true;

// ============ CONFIGURATION CONSTANTS ============
const CONFIG = {
  // Lockout settings
  LOCKOUT_MAX_ATTEMPTS: 5,           // Attempts before lockout triggers
  LOCKOUT_TIMEOUTS: [                // Progressive timeout durations in ms
    30 * 1000,                       // 30 seconds
    60 * 1000,                       // 1 minute
    2 * 60 * 1000,                   // 2 minutes
    5 * 60 * 1000,                   // 5 minutes
    15 * 60 * 1000,                  // 15 minutes
    30 * 60 * 1000,                  // 30 minutes
    60 * 60 * 1000,                  // 1 hour
    2 * 60 * 60 * 1000,              // 2 hours
    6 * 60 * 60 * 1000,              // 6 hours
    24 * 60 * 60 * 1000              // 24 hours
  ],
  LOCKOUT_MAX_LOCKOUTS: 10,          // After this many lockouts, permanent lock

  // Rate limiting
  ENCRYPTION_RATE_LIMIT: 100,        // Operations per minute
  STORAGE_RATE_LIMIT: 1000,          // Operations per minute
  PASSWORD_CHANGE_RATE_LIMIT: 5,     // Per 5 minutes
  PRIVATE_UNLOCK_RATE_LIMIT: 5,      // Per 5 minutes

  // Session
  SESSION_TIMEOUT_MS: 30 * 60 * 1000, // 30 minutes

  // Backup
  MAX_BACKUP_SIZE: 500 * 1024 * 1024, // 500 MB

  // Password limits (prevent DoS via huge passwords causing PBKDF2 slowdown)
  MAX_PASSWORD_LENGTH: 1024          // 1KB max password length
};

const dataPath = path.join(app.getPath('userData'), 'vault-data.json');
const configPath = path.join(app.getPath('userData'), 'vault-config.json');
const auditLogPath = path.join(app.getPath('userData'), 'audit-log.json');
const lockoutStatePath = path.join(app.getPath('userData'), 'lockout-state.json');

// Session storage (in-memory, cleared on app restart)
const secureSessionKey = new SecureSessionKey(); // Secure session key manager
let isVaultUnlocked = false;

/**
 * Check if session key needs rotation (auto-lock for security)
 * @returns {boolean} True if vault should be locked
 */
function checkSessionKeyRotation() {
  if (isVaultUnlocked && secureSessionKey.exists() && secureSessionKey.needsRotation()) {
    // Auto-lock vault for security - user must re-authenticate
    auditLog.logLock('Session timeout - key rotation required');
    auditLog.clearEncryptionKey();
    secureSessionKey.clear();
    isVaultUnlocked = false;
    // Notify renderer to show lock screen
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('lock-vault');
    }
    return true;
  }
  return false;
}

// Audit logging
const auditLog = new AuditLog(auditLogPath);

// Pending audit events queue (for events that occur before vault unlock)
const pendingAuditEvents = [];

/**
 * Queue an audit event for logging after vault unlock
 * @param {string} event - Event type
 * @param {object} details - Event details
 * @param {string} severity - Event severity
 */
function queueAuditEvent(event, details = {}, severity = 'info') {
  pendingAuditEvents.push({
    event,
    details: { ...details, queuedAt: Date.now() },
    severity,
    timestamp: new Date().toISOString()
  });
  // Limit queue size to prevent memory issues
  if (pendingAuditEvents.length > 100) {
    pendingAuditEvents.shift();
  }
}

/**
 * Flush pending audit events to the log (call after unlock)
 */
function flushPendingAuditEvents() {
  while (pendingAuditEvents.length > 0) {
    const event = pendingAuditEvents.shift();
    auditLog.log(event.event, { ...event.details, originalTimestamp: event.timestamp }, event.severity);
  }
}

// Rate limiting for IPC handlers
class RateLimiter {
  constructor(maxAttempts, windowMs) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.attempts = new Map(); // key -> { count, resetTime }
    this.lastCleanup = Date.now();
    this.cleanupInterval = 60000; // Cleanup every minute
  }

  tryAcquire(key) {
    const now = Date.now();

    // Periodically cleanup expired entries to prevent memory leak
    if (now - this.lastCleanup > this.cleanupInterval) {
      this.cleanup();
      this.lastCleanup = now;
    }

    const record = this.attempts.get(key);

    if (!record || now > record.resetTime) {
      // New window - delete old record first to allow GC
      this.attempts.delete(key);
      this.attempts.set(key, { count: 1, resetTime: now + this.windowMs });
      return { allowed: true };
    }

    if (record.count >= this.maxAttempts) {
      // Rate limited
      const remainingMs = record.resetTime - now;
      return {
        allowed: false,
        remainingSeconds: Math.ceil(remainingMs / 1000)
      };
    }

    // Increment count
    record.count++;
    return { allowed: true };
  }

  reset(key) {
    this.attempts.delete(key);
  }

  /**
   * Clean up expired rate limit entries to prevent memory leak
   */
  cleanup() {
    const now = Date.now();
    for (const [key, record] of this.attempts.entries()) {
      if (now > record.resetTime) {
        this.attempts.delete(key);
      }
    }
  }
}

// Rate limiters for different operations (using CONFIG values)
const encryptionRateLimiter = new RateLimiter(CONFIG.ENCRYPTION_RATE_LIMIT, 60000);
const storageRateLimiter = new RateLimiter(CONFIG.STORAGE_RATE_LIMIT, 60000);
const passwordChangeRateLimiter = new RateLimiter(CONFIG.PASSWORD_CHANGE_RATE_LIMIT, 300000);
const privateUnlockRateLimiter = new RateLimiter(CONFIG.PRIVATE_UNLOCK_RATE_LIMIT, 300000);

/**
 * Timing-safe comparison for password hashes
 * Prevents timing attacks by always comparing in constant time
 * @param {string} a - First hash
 * @param {string} b - Second hash
 * @returns {boolean} True if equal
 */
function timingSafeHashCompare(a, b) {
  // Convert to strings to ensure type safety without early return timing leak
  const strA = typeof a === 'string' ? a : '';
  const strB = typeof b === 'string' ? b : '';
  const typesValid = typeof a === 'string' && typeof b === 'string';

  const bufA = Buffer.from(strA, 'utf8');
  const bufB = Buffer.from(strB, 'utf8');
  // Pad shorter buffer to match length for constant-time comparison
  const maxLen = Math.max(bufA.length, bufB.length, 1); // At least 1 byte
  const paddedA = Buffer.alloc(maxLen, 0);
  const paddedB = Buffer.alloc(maxLen, 0);
  bufA.copy(paddedA);
  bufB.copy(paddedB);
  // Always do the comparison to prevent timing attacks
  const isEqual = crypto.timingSafeEqual(paddedA, paddedB);
  // Return false if types invalid or lengths differ
  return typesValid && isEqual && bufA.length === bufB.length;
}

// Progressive lockout system with persistent state
const rateLimiter = {
  failedAttempts: 0,
  lockoutCount: 0,
  lockoutUntil: null,
  permanentlyLocked: false,
  totalFailedAttempts: 0, // Lifetime counter for forensics

  /**
   * Load lockout state from persistent storage
   */
  loadState() {
    try {
      if (fs.existsSync(lockoutStatePath)) {
        const state = JSON.parse(fs.readFileSync(lockoutStatePath, 'utf8'));
        this.failedAttempts = state.failedAttempts || 0;
        this.lockoutCount = state.lockoutCount || 0;
        this.lockoutUntil = state.lockoutUntil || null;
        this.permanentlyLocked = state.permanentlyLocked || false;
        this.totalFailedAttempts = state.totalFailedAttempts || 0;
      }
    } catch (err) {
      console.error('[LOCKOUT] Failed to load state:', err.message);
    }
  },

  /**
   * Save lockout state to persistent storage
   */
  saveState() {
    try {
      const state = {
        failedAttempts: this.failedAttempts,
        lockoutCount: this.lockoutCount,
        lockoutUntil: this.lockoutUntil,
        permanentlyLocked: this.permanentlyLocked,
        totalFailedAttempts: this.totalFailedAttempts,
        updatedAt: new Date().toISOString()
      };
      fs.writeFileSync(lockoutStatePath, JSON.stringify(state, null, 2));
    } catch (err) {
      console.error('[LOCKOUT] Failed to save state:', err.message);
    }
  },

  /**
   * Check if vault is locked (temporary or permanent)
   */
  isLocked() {
    // Permanent lock - requires vault reset
    if (this.permanentlyLocked) {
      return true;
    }

    // Temporary lockout
    if (this.lockoutUntil && Date.now() < this.lockoutUntil) {
      return true;
    }

    // Lockout expired
    if (this.lockoutUntil && Date.now() >= this.lockoutUntil) {
      this.failedAttempts = 0;
      this.lockoutUntil = null;
      this.saveState();
    }
    return false;
  },

  /**
   * Check if permanently locked
   */
  isPermanentlyLocked() {
    return this.permanentlyLocked;
  },

  /**
   * Record a failed authentication attempt
   */
  recordFailure() {
    this.failedAttempts++;
    this.totalFailedAttempts++;

    if (this.failedAttempts >= CONFIG.LOCKOUT_MAX_ATTEMPTS) {
      // Check if we've reached max lockouts - permanent lock
      if (this.lockoutCount >= CONFIG.LOCKOUT_MAX_LOCKOUTS) {
        this.permanentlyLocked = true;
        this.saveState();
        return;
      }

      // Get timeout duration from progressive array
      const timeoutIndex = Math.min(this.lockoutCount, CONFIG.LOCKOUT_TIMEOUTS.length - 1);
      const lockoutDuration = CONFIG.LOCKOUT_TIMEOUTS[timeoutIndex];

      this.lockoutUntil = Date.now() + lockoutDuration;
      this.lockoutCount++;
      this.failedAttempts = 0; // Reset attempt counter for next round
    }

    this.saveState();
  },

  /**
   * Reset lockout state on successful authentication
   */
  reset() {
    this.failedAttempts = 0;
    this.lockoutCount = 0;
    this.lockoutUntil = null;
    // Note: permanentlyLocked and totalFailedAttempts are NOT reset on success
    // Permanent lock can only be cleared by vault reset
    this.saveState();
  },

  /**
   * Full reset (called during vault reset)
   */
  fullReset() {
    this.failedAttempts = 0;
    this.lockoutCount = 0;
    this.lockoutUntil = null;
    this.permanentlyLocked = false;
    this.totalFailedAttempts = 0;

    // Delete the lockout state file
    try {
      if (fs.existsSync(lockoutStatePath)) {
        fs.unlinkSync(lockoutStatePath);
      }
    } catch (err) {
      console.error('[LOCKOUT] Failed to delete state file:', err.message);
    }
  },

  /**
   * Get remaining lockout time in seconds
   */
  getRemainingTime() {
    if (this.permanentlyLocked) return Infinity;
    if (!this.lockoutUntil) return 0;
    const remaining = this.lockoutUntil - Date.now();
    return Math.max(0, Math.ceil(remaining / 1000));
  },

  /**
   * Get current lockout level for UI display
   */
  getLockoutLevel() {
    return {
      currentAttempts: this.failedAttempts,
      maxAttempts: CONFIG.LOCKOUT_MAX_ATTEMPTS,
      lockoutCount: this.lockoutCount,
      maxLockouts: CONFIG.LOCKOUT_MAX_LOCKOUTS,
      remainingLockouts: CONFIG.LOCKOUT_MAX_LOCKOUTS - this.lockoutCount,
      permanentlyLocked: this.permanentlyLocked,
      totalFailedAttempts: this.totalFailedAttempts
    };
  },

  /**
   * Get human-readable next lockout duration
   */
  getNextLockoutDuration() {
    const nextIndex = Math.min(this.lockoutCount, CONFIG.LOCKOUT_TIMEOUTS.length - 1);
    const durationMs = CONFIG.LOCKOUT_TIMEOUTS[nextIndex];
    return formatDuration(durationMs);
  }
};

/**
 * Format duration in ms to human-readable string
 */
function formatDuration(ms) {
  // Handle edge cases
  if (!Number.isFinite(ms) || ms < 0) {
    return 'permanently';
  }

  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) {
    return days === 1 ? '1 day' : `${days} days`;
  } else if (hours > 0) {
    return hours === 1 ? '1 hour' : `${hours} hours`;
  } else if (minutes > 0) {
    return minutes === 1 ? '1 minute' : `${minutes} minutes`;
  } else {
    return seconds === 1 ? '1 second' : `${seconds} seconds`;
  }
}

function createTray() {
  const trayIconPath = path.join(__dirname, 'tray-icon.png');
  const iconPath = path.join(__dirname, 'icon.png');

  let trayIcon;
  if (fs.existsSync(trayIconPath)) {
    trayIcon = nativeImage.createFromPath(trayIconPath);
  } else if (fs.existsSync(iconPath)) {
    trayIcon = nativeImage.createFromPath(iconPath);
    trayIcon = trayIcon.resize({ width: 16, height: 16 });
  } else {
    trayIcon = nativeImage.createFromDataURL('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAARklEQVQ4T2NkoBAwUqifYdQABkrDgGwX/Scl4pFdQMgLyC4gJgwINoCYQEZ2ATFhgOwCYsIA2QXEhAGyC4gJA2QXEBcGAE/gDBE5mC2dAAAAAElFTkSuQmCC');
  }

  tray = new Tray(trayIcon);

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show Eterna',
      click: () => {
        mainWindow?.show();
        mainWindow?.focus();
      }
    },
    {
      label: 'Lock Vault',
      click: () => {
        mainWindow?.webContents.send('lock-vault');
      }
    },
    { type: 'separator' },
    {
      label: 'Check for Updates',
      click: () => {
        autoUpdater.checkForUpdates();
      }
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setToolTip('Eterna');
  tray.setContextMenu(contextMenu);

  tray.on('click', () => {
    mainWindow?.show();
    mainWindow?.focus();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    title: 'Eterna',
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    frame: false,
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    backgroundColor: '#0a0a14',
    show: false
  });

  // Set stricter CSP headers
  mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self'; " +
          "script-src 'self' 'unsafe-inline'; " +
          "style-src 'self' 'unsafe-inline'; " +
          "img-src 'self' data: blob:; " +
          "media-src 'self' data: blob:; " +
          "object-src 'none'; " +
          "base-uri 'self'; " +
          "form-action 'self'; " +
          "frame-ancestors 'none'; " +
          "upgrade-insecure-requests"
        ]
      }
    });
  });

  mainWindow.loadFile('index.html');

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('maximize', () => {
    mainWindow?.webContents.send('window-maximized', true);
  });

  mainWindow.on('unmaximize', () => {
    mainWindow?.webContents.send('window-maximized', false);
  });

  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow?.hide();
      return false;
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ============ AUTO-UPDATER EVENTS ============
autoUpdater.on('checking-for-update', () => {
  mainWindow?.webContents.send('update-status', { status: 'checking' });
});

autoUpdater.on('update-available', (info) => {
  mainWindow?.webContents.send('update-status', {
    status: 'available',
    version: info.version,
    releaseNotes: info.releaseNotes
  });
});

autoUpdater.on('update-not-available', () => {
  mainWindow?.webContents.send('update-status', { status: 'not-available' });
});

autoUpdater.on('download-progress', (progress) => {
  mainWindow?.webContents.send('update-status', {
    status: 'downloading',
    percent: Math.round(progress.percent),
    transferred: progress.transferred,
    total: progress.total
  });
});

autoUpdater.on('update-downloaded', (info) => {
  mainWindow?.webContents.send('update-status', {
    status: 'downloaded',
    version: info.version
  });
});

autoUpdater.on('error', (err) => {
  mainWindow?.webContents.send('update-status', {
    status: 'error',
    message: err.message
  });
});

// ============ IPC HANDLERS ============
ipcMain.handle('window:minimize', () => {
  mainWindow?.minimize();
});

ipcMain.handle('window:maximize', () => {
  if (mainWindow?.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow?.maximize();
  }
});

ipcMain.handle('window:close', () => {
  mainWindow?.hide();
});

ipcMain.handle('window:isMaximized', () => {
  return mainWindow?.isMaximized() || false;
});

ipcMain.handle('app:getVersion', () => {
  return app.getVersion();
});

ipcMain.handle('app:openExternal', (event, url) => {
  // Validate URL to prevent dangerous protocols
  try {
    const parsedUrl = new URL(url);
    // Whitelist safe protocols - explicitly block file://, javascript:, data:, etc.
    const allowedProtocols = ['http:', 'https:'];

    if (!allowedProtocols.includes(parsedUrl.protocol)) {
      console.warn('Blocked attempt to open URL with disallowed protocol:', parsedUrl.protocol);
      return { success: false, error: 'Only http and https URLs are allowed' };
    }

    shell.openExternal(url);
    return { success: true };
  } catch (_err) {
    console.warn('Invalid URL provided to openExternal:', url);
    return { success: false, error: 'Invalid URL' };
  }
});

ipcMain.handle('app:quit', () => {
  isQuitting = true;
  app.quit();
});

// Update handlers
ipcMain.handle('update:check', () => {
  autoUpdater.checkForUpdates();
});

ipcMain.handle('update:download', () => {
  autoUpdater.downloadUpdate();
});

ipcMain.handle('update:install', () => {
  isQuitting = true;
  autoUpdater.quitAndInstall();
});

// ============ VAULT SETUP & AUTHENTICATION ============

/**
 * Check if vault is initialized (has master password set)
 */
ipcMain.handle('vault:isInitialized', async () => {
  try {
    return { initialized: fs.existsSync(configPath) };
  } catch (err) {
    return { initialized: false, error: err.message };
  }
});

/**
 * Initialize vault with master password
 */
ipcMain.handle('vault:initialize', async (event, masterPassword) => {
  try {
    // Validate password exists
    if (!masterPassword || masterPassword.length === 0) {
      return { success: false, error: 'Password required' };
    }

    // Prevent DoS via huge passwords causing PBKDF2 slowdown
    if (masterPassword.length > CONFIG.MAX_PASSWORD_LENGTH) {
      return { success: false, error: `Password too long (max ${CONFIG.MAX_PASSWORD_LENGTH} characters)` };
    }

    // Generate salt for key derivation
    const salt = crypto.randomBytes(encryption.constants.SALT_LENGTH);

    // Get current iterations count for storage
    const iterations = encryption.constants.PBKDF2_ITERATIONS;

    // Hash master password for verification (NOT for encryption)
    const passwordHash = encryption.hashPassword(masterPassword, salt, iterations);

    // Store config (salt, password hash, and iterations for future compatibility)
    const config = {
      version: '1.0',
      salt: salt.toString('hex'),
      passwordHash,
      iterations, // Store iterations for backward compatibility
      createdAt: new Date().toISOString()
    };

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

    // Create empty encrypted vault
    const emptyVault = {};
    const { key } = encryption.deriveKey(masterPassword, salt, iterations);
    const { encrypted, iv, tag } = encryption.encrypt(emptyVault, key);

    const vaultData = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm',
      iterations // Store iterations for backward compatibility
    };

    fs.writeFileSync(dataPath, JSON.stringify(vaultData, null, 2));

    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Unlock vault with master password
 */
ipcMain.handle('vault:unlock', async (event, masterPassword) => {
  try {
    // Check for permanent lock first
    if (rateLimiter.isPermanentlyLocked()) {
      // Queue event - will be logged after next successful unlock (or lost if vault reset)
      queueAuditEvent('vault.permanent_lock_attempt', {
        totalFailedAttempts: rateLimiter.totalFailedAttempts,
        timestamp: Date.now()
      }, 'critical');
      return {
        success: false,
        error: 'Vault is permanently locked due to too many failed attempts. You must reset the vault to continue.',
        permanentlyLocked: true,
        lockoutLevel: rateLimiter.getLockoutLevel()
      };
    }

    // Check temporary lockout
    if (rateLimiter.isLocked()) {
      const remainingSeconds = rateLimiter.getRemainingTime();
      const lockoutLevel = rateLimiter.getLockoutLevel();
      // Queue rate limit event for logging after unlock
      queueAuditEvent('vault.rate_limit', {
        remainingSeconds,
        lockoutCount: rateLimiter.lockoutCount,
        timestamp: Date.now()
      }, 'critical');
      return {
        success: false,
        error: `Too many failed attempts. Try again in ${formatDuration(remainingSeconds * 1000)}.`,
        locked: true,
        remainingSeconds,
        lockoutLevel,
        nextLockoutDuration: rateLimiter.getNextLockoutDuration()
      };
    }

    // Check if vault is initialized
    if (!fs.existsSync(configPath)) {
      return { success: false, error: 'Vault not initialized' };
    }

    // Prevent DoS via huge passwords causing PBKDF2 slowdown
    if (masterPassword && masterPassword.length > CONFIG.MAX_PASSWORD_LENGTH) {
      return { success: false, error: 'Invalid master password' };
    }

    // Load config with error handling for corrupted files
    let config;
    try {
      config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch (parseErr) {
      if (parseErr instanceof SyntaxError) {
        return { success: false, error: 'Vault configuration is corrupted. Please reset the vault.' };
      }
      throw parseErr;
    }

    // Validate config has required fields
    if (!config.salt || !config.passwordHash) {
      return { success: false, error: 'Vault configuration is incomplete. Please reset the vault.' };
    }

    // Use stored iterations for backward compatibility (default to current if not stored)
    const storedIterations = config.iterations || encryption.constants.PBKDF2_ITERATIONS;

    // Verify master password (timing-safe comparison)
    const passwordHash = encryption.hashPassword(masterPassword, config.salt, storedIterations);
    if (!timingSafeHashCompare(passwordHash, config.passwordHash)) {
      rateLimiter.recordFailure();
      // Queue failed attempt for logging after successful unlock
      queueAuditEvent('vault.unlock.failed', {
        failedAttempts: rateLimiter.failedAttempts,
        lockoutCount: rateLimiter.lockoutCount,
        timestamp: Date.now()
      }, rateLimiter.failedAttempts >= 5 ? 'critical' : 'warning');
      // Clear master password from memory on failure
      clearString(masterPassword);
      return { success: false, error: 'Invalid master password' };
    }

    // Derive session key using stored iterations
    const salt = Buffer.from(config.salt, 'hex');
    const { key } = encryption.deriveKey(masterPassword, salt, storedIterations);

    // Store session key securely
    secureSessionKey.set(key);
    isVaultUnlocked = true;

    // Set audit log encryption key
    auditLog.setEncryptionKey(key);

    // Flush any pending audit events (failed attempts, rate limits, etc.)
    flushPendingAuditEvents();

    // Reset rate limiter on successful unlock
    rateLimiter.reset();

    // Log successful unlock
    auditLog.logUnlock(true, rateLimiter.failedAttempts);

    // Clear master password from memory
    clearString(masterPassword);

    return { success: true };
  } catch (err) {
    rateLimiter.recordFailure();
    // Queue failed unlock for logging after successful unlock
    queueAuditEvent('vault.unlock.failed', {
      failedAttempts: rateLimiter.failedAttempts,
      lockoutCount: rateLimiter.lockoutCount,
      errorType: err.message?.includes('Decryption') ? 'decryption_error' : 'vault_error',
      timestamp: Date.now()
    }, rateLimiter.failedAttempts >= 5 ? 'critical' : 'warning');
    // Clear master password even on failure
    clearString(masterPassword);
    // Provide more specific error for debugging (without exposing sensitive details)
    const errorType = err.message?.includes('Decryption') ? 'incorrect password' : 'vault error';
    return { success: false, error: `Failed to unlock vault: ${errorType}` };
  }
});

/**
 * Lock vault (clear session key)
 */
ipcMain.handle('vault:lock', async () => {
  // Log lock event before clearing
  auditLog.logLock();

  // Clear audit log encryption key
  auditLog.clearEncryptionKey();

  // Securely clear session key from memory
  secureSessionKey.clear();
  isVaultUnlocked = false;
  return { success: true };
});

/**
 * Check if vault is unlocked
 */
ipcMain.handle('vault:isUnlocked', async () => {
  return { unlocked: isVaultUnlocked };
});

/**
 * Get current lockout status
 */
ipcMain.handle('vault:getLockoutStatus', async () => {
  return {
    isLocked: rateLimiter.isLocked(),
    isPermanentlyLocked: rateLimiter.isPermanentlyLocked(),
    remainingSeconds: rateLimiter.getRemainingTime(),
    lockoutLevel: rateLimiter.getLockoutLevel(),
    nextLockoutDuration: rateLimiter.getNextLockoutDuration()
  };
});

/**
 * Completely reset vault (delete all data and config)
 */
ipcMain.handle('vault:reset', async () => {
  try {
    // Clear session
    secureSessionKey.clear();
    isVaultUnlocked = false;
    auditLog.clearEncryptionKey();

    // Reset lockout state (clears permanent lock)
    rateLimiter.fullReset();

    // Delete vault files (with error handling for each file)
    const deleteFile = (filePath) => {
      try {
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      } catch (unlinkErr) {
        console.error(`Failed to delete ${filePath}:`, unlinkErr.message);
        // Continue with other files even if one fails
      }
    };

    deleteFile(configPath);
    deleteFile(dataPath);
    deleteFile(auditLogPath);

    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Change master password
 */
ipcMain.handle('vault:changeMasterPassword', async (event, currentPassword, newPassword) => {
  // Check rate limiting
  const rateCheck = passwordChangeRateLimiter.tryAcquire('password-change');
  if (!rateCheck.allowed) {
    auditLog.log('PASSWORD_CHANGE_RATE_LIMITED', { remainingSeconds: rateCheck.remainingSeconds });
    return {
      success: false,
      error: 'Too many password change attempts',
      locked: true,
      remainingSeconds: rateCheck.remainingSeconds
    };
  }

  try {
    // Verify current password
    if (!fs.existsSync(configPath)) {
      clearString(currentPassword);
      clearString(newPassword);
      return { success: false, error: 'Vault not initialized' };
    }

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    // Use stored iterations for verification (backward compatibility)
    const oldIterations = config.iterations || encryption.constants.PBKDF2_ITERATIONS;
    const currentPasswordHash = encryption.hashPassword(currentPassword, config.salt, oldIterations);

    // Timing-safe comparison
    if (!timingSafeHashCompare(currentPasswordHash, config.passwordHash)) {
      clearString(currentPassword);
      clearString(newPassword);
      return { success: false, error: 'Current password is incorrect' };
    }

    // Accept any new password - no validation
    if (!newPassword || newPassword.length === 0) {
      clearString(currentPassword);
      clearString(newPassword);
      return { success: false, error: 'New password required' };
    }

    // Decrypt vault with old password using stored iterations
    const oldSalt = Buffer.from(config.salt, 'hex');
    const { key: oldKey } = encryption.deriveKey(currentPassword, oldSalt, oldIterations);

    const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    const vaultData = encryption.decrypt(
      encryptedVault.data,
      encryptedVault.iv,
      encryptedVault.tag,
      oldKey
    );

    // Re-encrypt with new password using current iterations (upgrade security)
    const newIterations = encryption.constants.PBKDF2_ITERATIONS;
    const newSalt = crypto.randomBytes(encryption.constants.SALT_LENGTH);
    const { key: newKey } = encryption.deriveKey(newPassword, newSalt, newIterations);
    const { encrypted, iv, tag } = encryption.encrypt(vaultData, newKey);

    // Update config with new iterations (security upgrade on password change)
    config.salt = newSalt.toString('hex');
    config.passwordHash = encryption.hashPassword(newPassword, newSalt, newIterations);
    config.iterations = newIterations;
    config.updatedAt = new Date().toISOString();

    // Save everything with new iterations
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    fs.writeFileSync(dataPath, JSON.stringify({ data: encrypted, iv, tag, version: '1.0', algorithm: 'aes-256-gcm', iterations: newIterations }, null, 2));

    // Update session key securely
    secureSessionKey.set(newKey);

    // Update audit log encryption key
    auditLog.setEncryptionKey(newKey);

    // Log password change
    auditLog.logPasswordChange();

    // Reset rate limiter on success
    passwordChangeRateLimiter.reset('password-change');

    // Clear passwords from memory
    clearString(currentPassword);
    clearString(newPassword);

    return { success: true };
  } catch (err) {
    // Clear passwords even on failure
    clearString(currentPassword);
    clearString(newPassword);
    return { success: false, error: err.message };
  }
});

/**
 * Validate password strength
 */
ipcMain.handle('vault:validatePassword', async (event, password) => {
  try {
    const validation = encryption.validatePasswordStrength(password);
    return { ...validation, success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

/**
 * Generate secure password
 */
ipcMain.handle('vault:generatePassword', async (event, length = 32, options = {}) => {
  try {
    const password = encryption.generateSecurePassword(length, options);
    return { success: true, password };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ============ ENCRYPTED STORAGE HANDLERS ============

/**
 * Get value from encrypted vault
 */
ipcMain.handle('storage:get', async (event, key) => {
  try {
    // Check for session timeout
    if (checkSessionKeyRotation()) {
      return { success: false, error: 'Session expired', locked: true };
    }

    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    // Load and decrypt vault (TOCTOU-safe: use try-catch instead of existsSync)
    let vaultData = {};
    try {
      const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
      vaultData = encryption.decrypt(
        encryptedVault.data,
        encryptedVault.iv,
        encryptedVault.tag,
        secureSessionKey.get()
      );
    } catch (readErr) {
      // File doesn't exist or is unreadable - return null
      if (readErr.code === 'ENOENT') {
        return { success: true, value: null };
      }
      throw readErr;
    }

    return { success: true, value: vaultData[key] || null };
  } catch (err) {
    return { success: false, error: 'Failed to retrieve data', details: err.message };
  }
});

/**
 * Set value in encrypted vault
 */
ipcMain.handle('storage:set', async (event, key, value) => {
  try {
    // Check for session timeout
    if (checkSessionKeyRotation()) {
      return { success: false, error: 'Session expired', locked: true };
    }

    // Rate limiting
    const rateLimitResult = storageRateLimiter.tryAcquire('storage:set');
    if (!rateLimitResult.allowed) {
      return {
        success: false,
        error: 'Rate limit exceeded',
        locked: true,
        remainingSeconds: rateLimitResult.remainingSeconds
      };
    }

    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const currentKey = secureSessionKey.get();

    // Load and decrypt current vault (TOCTOU-safe)
    let vaultData = {};
    try {
      const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
      vaultData = encryption.decrypt(
        encryptedVault.data,
        encryptedVault.iv,
        encryptedVault.tag,
        currentKey
      );
    } catch (readErr) {
      // File doesn't exist - start with empty vault
      if (readErr.code !== 'ENOENT') {
        throw readErr;
      }
    }

    // Update value
    vaultData[key] = value;

    // Re-encrypt and save
    const { encrypted, iv, tag } = encryption.encrypt(vaultData, secureSessionKey.get());
    const encryptedVault = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm',
      updatedAt: new Date().toISOString()
    };

    fs.writeFileSync(dataPath, JSON.stringify(encryptedVault, null, 2));

    return { success: true };
  } catch (err) {
    return { success: false, error: 'Failed to save data', details: err.message };
  }
});

/**
 * Delete value from encrypted vault
 */
ipcMain.handle('storage:delete', async (event, key) => {
  try {
    // Check session rotation first
    if (checkSessionKeyRotation()) {
      return { success: false, error: 'Session expired - vault locked' };
    }
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    // Load and decrypt vault (TOCTOU-safe)
    let vaultData;
    try {
      const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
      vaultData = encryption.decrypt(
        encryptedVault.data,
        encryptedVault.iv,
        encryptedVault.tag,
        secureSessionKey.get()
      );
    } catch (readErr) {
      // File doesn't exist - nothing to delete
      if (readErr.code === 'ENOENT') {
        return { success: true };
      }
      throw readErr;
    }

    // Delete key
    delete vaultData[key];

    // Re-encrypt and save
    const { encrypted, iv, tag } = encryption.encrypt(vaultData, secureSessionKey.get());
    const newEncryptedVault = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm',
      updatedAt: new Date().toISOString()
    };

    fs.writeFileSync(dataPath, JSON.stringify(newEncryptedVault, null, 2));

    return { success: true };
  } catch (err) {
    return { success: false, error: 'Failed to delete data', details: err.message };
  }
});

// ============ FILE ENCRYPTION HANDLERS ============

/**
 * Encrypt file data
 */
ipcMain.handle('vault:encryptFile', async (event, fileData) => {
  try {
    // Rate limiting
    const rateLimitResult = encryptionRateLimiter.tryAcquire('vault:encryptFile');
    if (!rateLimitResult.allowed) {
      return {
        success: false,
        error: 'Rate limit exceeded. Please wait before encrypting more files.',
        remainingSeconds: rateLimitResult.remainingSeconds
      };
    }

    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const { encrypted, iv, tag } = encryption.encrypt(fileData, secureSessionKey.get());

    return {
      success: true,
      encrypted: {
        data: encrypted,
        iv,
        tag
      }
    };
  } catch (err) {
    return { success: false, error: 'Failed to encrypt file', details: err.message };
  }
});

/**
 * Decrypt file data
 */
ipcMain.handle('vault:decryptFile', async (event, encryptedFile) => {
  try {
    // Rate limiting
    const rateLimitResult = encryptionRateLimiter.tryAcquire('vault:decryptFile');
    if (!rateLimitResult.allowed) {
      return {
        success: false,
        error: 'Rate limit exceeded. Please wait before decrypting more files.',
        remainingSeconds: rateLimitResult.remainingSeconds
      };
    }

    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const decrypted = encryption.decrypt(
      encryptedFile.data,
      encryptedFile.iv,
      encryptedFile.tag,
      secureSessionKey.get()
    );

    return { success: true, data: decrypted };
  } catch (err) {
    return { success: false, error: 'Failed to decrypt file', details: err.message };
  }
});

// ============ EXPORT/IMPORT HANDLERS ============

/**
 * Export encrypted backup
 */
ipcMain.handle('vault:exportBackup', async (event, password) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    // Check vault file size before export to prevent memory exhaustion
    try {
      const stats = fs.statSync(dataPath);
      if (stats.size > CONFIG.MAX_BACKUP_SIZE) {
        const maxSizeMB = Math.round(CONFIG.MAX_BACKUP_SIZE / (1024 * 1024));
        return { success: false, error: `Vault too large to export. Maximum size is ${maxSizeMB} MB.` };
      }
    } catch (statErr) {
      if (statErr.code !== 'ENOENT') {
        return { success: false, error: 'Failed to check vault size' };
      }
    }

    // Load current vault data
    const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    const vaultData = encryption.decrypt(
      encryptedVault.data,
      encryptedVault.iv,
      encryptedVault.tag,
      secureSessionKey.get()
    );

    // Encrypt backup with separate password if provided
    if (password) {
      // Use same iteration count as vault for consistent security
      const iterations = encryption.constants.PBKDF2_ITERATIONS;
      const { key, salt } = encryption.deriveKey(password, null, iterations);
      const { encrypted, iv, tag } = encryption.encrypt(vaultData, key);

      // Calculate checksum for integrity verification (use consistent buffer-based hashing)
      const checksumData = Buffer.concat([
        Buffer.from(encrypted, 'hex'),
        Buffer.from(iv, 'hex'),
        Buffer.from(tag, 'hex')
      ]);
      const checksum = crypto.createHash('sha256').update(checksumData).digest('hex');

      return {
        success: true,
        backup: {
          encrypted: true,
          data: encrypted,
          iv,
          tag,
          salt: salt.toString('hex'),
          version: '1.0',
          checksum,
          createdAt: new Date().toISOString(),
          appVersion: app.getVersion()
        }
      };
    }

    // Return unencrypted backup (store data as JSON string for consistent checksum)
    const dataString = JSON.stringify(vaultData);
    const checksum = crypto.createHash('sha256').update(dataString).digest('hex');

    return {
      success: true,
      backup: {
        encrypted: false,
        data: dataString,  // Store as string to ensure checksum consistency
        version: '1.0',
        checksum,
        createdAt: new Date().toISOString(),
        appVersion: app.getVersion()
      }
    };
  } catch (err) {
    return { success: false, error: 'Failed to export backup', details: err.message };
  }
});

/**
 * Import encrypted backup
 */
ipcMain.handle('vault:importBackup', async (event, backup, password) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    // Validate backup structure
    if (!backup || typeof backup !== 'object') {
      return { success: false, error: 'Invalid backup: not an object' };
    }
    if (!backup.version || typeof backup.version !== 'string') {
      return { success: false, error: 'Invalid backup: missing or invalid version' };
    }
    if (typeof backup.encrypted !== 'boolean') {
      return { success: false, error: 'Invalid backup: missing encryption flag' };
    }
    if (backup.data === undefined || backup.data === null) {
      return { success: false, error: 'Invalid backup: missing data' };
    }
    // Encrypted backups must have iv, tag, and salt
    if (backup.encrypted) {
      if (!backup.iv || !backup.tag || !backup.salt) {
        return { success: false, error: 'Invalid backup: encrypted backup missing required fields (iv, tag, salt)' };
      }
    }

    // Verify checksum if present
    if (backup.checksum) {
      let calculatedChecksum;
      if (backup.encrypted) {
        // Validate hex format before Buffer.from (must be even-length hex strings)
        const hexRegex = /^[0-9a-f]+$/i;
        if (!backup.data || !hexRegex.test(backup.data) || backup.data.length % 2 !== 0) {
          return { success: false, error: 'Invalid backup: corrupted encrypted data' };
        }
        if (!backup.iv || !hexRegex.test(backup.iv) || backup.iv.length !== 32) {
          return { success: false, error: 'Invalid backup: corrupted IV' };
        }
        if (!backup.tag || !hexRegex.test(backup.tag) || backup.tag.length !== 32) {
          return { success: false, error: 'Invalid backup: corrupted authentication tag' };
        }
        // Use buffer-based hashing to match export calculation
        const checksumData = Buffer.concat([
          Buffer.from(backup.data, 'hex'),
          Buffer.from(backup.iv, 'hex'),
          Buffer.from(backup.tag, 'hex')
        ]);
        calculatedChecksum = crypto.createHash('sha256').update(checksumData).digest('hex');
      } else {
        // For unencrypted, data is stored as string
        const dataString = typeof backup.data === 'string' ? backup.data : JSON.stringify(backup.data);
        calculatedChecksum = crypto.createHash('sha256').update(dataString).digest('hex');
      }

      if (calculatedChecksum !== backup.checksum) {
        return { success: false, error: 'Backup integrity check failed. File may be corrupted or tampered.' };
      }
    }

    let importedData;

    if (backup.encrypted) {
      // Decrypt with provided password
      if (!password) {
        return { success: false, error: 'Password required for encrypted backup' };
      }

      // Validate salt format
      if (!backup.salt || !/^[0-9a-f]{64}$/i.test(backup.salt)) {
        return { success: false, error: 'Invalid backup: corrupted salt' };
      }

      const salt = Buffer.from(backup.salt, 'hex');
      const { key } = encryption.deriveKey(password, salt);

      try {
        importedData = encryption.decrypt(
          backup.data,
          backup.iv,
          backup.tag,
          key
        );
      } catch (_err) {
        return { success: false, error: 'Failed to decrypt backup. Incorrect password or corrupted data.' };
      }
    } else {
      // Unencrypted backup (data is stored as JSON string)
      try {
        importedData = typeof backup.data === 'string' ? JSON.parse(backup.data) : backup.data;
      } catch (_parseErr) {
        return { success: false, error: 'Invalid backup: malformed JSON data' };
      }
    }

    // Validate imported data has expected structure
    if (!importedData || typeof importedData !== 'object') {
      return { success: false, error: 'Invalid backup: data must be an object' };
    }

    // Re-encrypt with current vault key and save
    const { encrypted, iv, tag } = encryption.encrypt(importedData, secureSessionKey.get());
    const vaultData = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm',
      updatedAt: new Date().toISOString()
    };

    fs.writeFileSync(dataPath, JSON.stringify(vaultData, null, 2));

    return { success: true };
  } catch (err) {
    return { success: false, error: 'Failed to import backup', details: err.message };
  }
});

// ============ PRIVATE SECTION ============

/**
 * Set private section password
 */
ipcMain.handle('vault:setPrivatePassword', async (event, password) => {
  if (!isVaultUnlocked || !secureSessionKey.exists()) {
    return { success: false, error: 'Vault is locked' };
  }

  try {
    // Generate salt and hash the private section password with current iterations
    const privateSalt = crypto.randomBytes(encryption.constants.SALT_LENGTH);
    const privateIterations = encryption.constants.PBKDF2_ITERATIONS;
    const hash = encryption.hashPassword(password, privateSalt, privateIterations);

    // Load and decrypt current vault
    let vaultData = {};
    if (fs.existsSync(dataPath)) {
      const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
      vaultData = encryption.decrypt(
        encryptedVault.data,
        encryptedVault.iv,
        encryptedVault.tag,
        secureSessionKey.get()
      );
    }

    // Get current data or create new structure
    const currentData = vaultData['eterna-v2'] ? JSON.parse(vaultData['eterna-v2']) : {};

    // Store the hash, salt, and iterations in the data
    currentData.privatePasswordHash = hash;
    currentData.privatePasswordSalt = privateSalt.toString('hex');
    currentData.privatePasswordIterations = privateIterations;

    // Update vault data
    vaultData['eterna-v2'] = JSON.stringify(currentData);

    // Re-encrypt and save
    const { encrypted, iv, tag } = encryption.encrypt(vaultData, secureSessionKey.get());
    const encryptedVaultData = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm',
      updatedAt: new Date().toISOString()
    };

    fs.writeFileSync(dataPath, JSON.stringify(encryptedVaultData, null, 2));

    // Clear password from memory
    clearString(password);
    return { success: true };
  } catch (err) {
    clearString(password);
    return { success: false, error: 'Failed to set private password', details: err.message };
  }
});

/**
 * Unlock private section
 */
ipcMain.handle('vault:unlockPrivate', async (event, password) => {
  if (!isVaultUnlocked || !secureSessionKey.exists()) {
    return { success: false, error: 'Vault is locked' };
  }

  // Check rate limiting
  const rateCheck = privateUnlockRateLimiter.tryAcquire('private-unlock');
  if (!rateCheck.allowed) {
    auditLog.log('PRIVATE_UNLOCK_RATE_LIMITED', { remainingSeconds: rateCheck.remainingSeconds });
    return {
      success: false,
      error: 'Too many failed attempts',
      locked: true,
      remainingSeconds: rateCheck.remainingSeconds
    };
  }

  try {
    // Load and decrypt vault
    const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    const vaultData = encryption.decrypt(
      encryptedVault.data,
      encryptedVault.iv,
      encryptedVault.tag,
      secureSessionKey.get()
    );

    // Get current data
    const currentData = vaultData['eterna-v2'] ? JSON.parse(vaultData['eterna-v2']) : {};

    // Check if private password is set
    if (!currentData.privatePasswordHash || !currentData.privatePasswordSalt) {
      return { success: false, error: 'Private section not set up' };
    }

    // Validate salt format before use
    if (!/^[0-9a-f]{64}$/i.test(currentData.privatePasswordSalt)) {
      // Log corruption to audit for forensics
      auditLog.log('security.corruption_detected', {
        component: 'privatePasswordSalt',
        timestamp: Date.now()
      }, 'critical');
      return { success: false, error: 'Corrupted private password data' };
    }

    // Hash the provided password with stored salt and iterations (timing-safe comparison)
    const storedIterations = currentData.privatePasswordIterations ?? encryption.constants.PBKDF2_ITERATIONS;
    const hash = encryption.hashPassword(password, currentData.privatePasswordSalt, storedIterations);
    if (timingSafeHashCompare(hash, currentData.privatePasswordHash)) {
      // Reset rate limiter on success
      privateUnlockRateLimiter.reset('private-unlock');
      clearString(password);
      return { success: true };
    }

    // Failed attempt already counted by tryAcquire at handler start
    clearString(password);
    return { success: false, error: 'Incorrect password' };
  } catch (err) {
    return { success: false, error: 'Failed to unlock private section', details: err.message };
  }
});

/**
 * Reset private section
 */
ipcMain.handle('vault:resetPrivate', async (_event) => {
  if (!isVaultUnlocked || !secureSessionKey.exists()) {
    return { success: false, error: 'Vault is locked' };
  }

  try {
    // Load and decrypt current vault
    let vaultData = {};
    if (fs.existsSync(dataPath)) {
      const encryptedVault = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
      vaultData = encryption.decrypt(
        encryptedVault.data,
        encryptedVault.iv,
        encryptedVault.tag,
        secureSessionKey.get()
      );
    }

    // Get current data
    const currentData = vaultData['eterna-v2'] ? JSON.parse(vaultData['eterna-v2']) : {};

    // Remove all private password data for complete cleanup
    delete currentData.privatePasswordHash;
    delete currentData.privatePasswordSalt;
    delete currentData.privatePasswordIterations;

    // Update vault data
    vaultData['eterna-v2'] = JSON.stringify(currentData);

    // Re-encrypt and save
    const { encrypted, iv, tag } = encryption.encrypt(vaultData, secureSessionKey.get());
    const encryptedVaultData = {
      data: encrypted,
      iv,
      tag,
      version: '1.0',
      algorithm: 'aes-256-gcm',
      updatedAt: new Date().toISOString()
    };

    fs.writeFileSync(dataPath, JSON.stringify(encryptedVaultData, null, 2));

    return { success: true };
  } catch (err) {
    return { success: false, error: 'Failed to reset private section', details: err.message };
  }
});

// ============ AUDIT LOG HANDLERS ============

/**
 * Get audit log entries
 */
ipcMain.handle('audit:getEntries', async (_event, filters = {}) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const entries = auditLog.getEntries(filters);
    return { success: true, entries };
  } catch (err) {
    return { success: false, error: 'Failed to retrieve audit log', details: err.message };
  }
});

/**
 * Clear audit log
 */
ipcMain.handle('audit:clear', async (_event) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const success = auditLog.clear();
    return { success };
  } catch (err) {
    return { success: false, error: 'Failed to clear audit log', details: err.message };
  }
});

/**
 * Export audit log
 */
ipcMain.handle('audit:export', async (_event) => {
  try {
    if (!isVaultUnlocked || !secureSessionKey.exists()) {
      return { success: false, error: 'Vault is locked' };
    }

    const jsonData = auditLog.export();
    return { success: true, data: jsonData };
  } catch (err) {
    return { success: false, error: 'Failed to export audit log', details: err.message };
  }
});

// ============ CODE INTEGRITY CHECKING ============

/**
 * Verify integrity of critical application files
 */
function verifyCodeIntegrity() {
  const integrityPath = path.join(app.getPath('userData'), 'integrity.json');
  const criticalFiles = ['index.html', 'main.js', 'preload.js', 'encryption.js'];

  try {
    const currentHashes = {};

    // Calculate current file hashes
    for (const file of criticalFiles) {
      const filePath = path.join(__dirname, file);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath);
        currentHashes[file] = crypto.createHash('sha256').update(content).digest('hex');
      }
    }

    // Check if integrity file exists
    if (fs.existsSync(integrityPath)) {
      const storedHashes = JSON.parse(fs.readFileSync(integrityPath, 'utf8'));

      // Verify hashes match
      for (const file of criticalFiles) {
        if (storedHashes[file] && currentHashes[file] !== storedHashes[file]) {
          console.warn(`[SECURITY WARNING] File integrity check failed for: ${file}`);
          console.warn('File may have been tampered with or updated.');
          // Log integrity failure
          auditLog.logIntegrityFailure(file);
          // In production, you might want to exit the app here
          // For development, we just warn
        }
      }
    } else {
      // First run - store hashes
      fs.writeFileSync(integrityPath, JSON.stringify(currentHashes, null, 2));
      // Baseline file hashes stored silently on first run
    }
  } catch (err) {
    console.error('[INTEGRITY] Failed to verify code integrity:', err);
  }
}

// ============ APP LIFECYCLE ============
app.whenReady().then(() => {
  // Load persistent lockout state
  rateLimiter.loadState();

  // Verify code integrity on startup
  verifyCodeIntegrity();

  createWindow();
  createTray();

  // Don't auto-check for updates on startup
  // Users can manually check via Settings if they want

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    } else {
      mainWindow?.show();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform === 'darwin') {
    // On macOS, keep the app running
  }
});

app.on('before-quit', () => {
  isQuitting = true;
});
