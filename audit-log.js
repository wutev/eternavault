const fs = require('fs');
const crypto = require('crypto');
const encryption = require('./encryption');

/**
 * Audit Logging System
 * Tracks security-relevant events in an encrypted log file
 */

class AuditLog {
  constructor(logPath, encryptionKey = null) {
    this.logPath = logPath;
    this.encryptionKey = encryptionKey;
    this.maxEntries = 1000; // Keep last 1000 entries
  }

  /**
   * Sets the encryption key for log encryption
   * @param {Buffer} key - Encryption key
   */
  setEncryptionKey(key) {
    this.encryptionKey = key;
  }

  /**
   * Clears the encryption key
   */
  clearEncryptionKey() {
    this.encryptionKey = null;
  }

  /**
   * Reads and decrypts the audit log
   * @returns {Array} Array of log entries
   */
  read() {
    try {
      if (!fs.existsSync(this.logPath)) {
        return [];
      }

      const encryptedLog = JSON.parse(fs.readFileSync(this.logPath, 'utf8'));

      if (!this.encryptionKey) {
        // If no key, return empty (log is encrypted)
        return [];
      }

      const decrypted = encryption.decrypt(
        encryptedLog.data,
        encryptedLog.iv,
        encryptedLog.tag,
        this.encryptionKey
      );

      // Parse and validate the decrypted data
      // Note: encryption.decrypt() may auto-parse JSON, so check if already parsed
      let parsed;
      if (typeof decrypted === 'string') {
        parsed = JSON.parse(decrypted);
      } else {
        parsed = decrypted;
      }

      if (!Array.isArray(parsed)) {
        console.warn('[AUDIT] Log data is not an array, returning empty');
        return [];
      }
      return parsed;
    } catch (err) {
      // Distinguish between decryption and parsing errors for debugging
      if (err.message.includes('Decryption failed')) {
        console.error('[AUDIT] Failed to decrypt log - key may be wrong');
      } else if (err instanceof SyntaxError) {
        console.error('[AUDIT] Corrupted log data - invalid JSON');
      } else {
        console.error('[AUDIT] Failed to read log:', err.message);
      }
      return [];
    }
  }

  /**
   * Writes encrypted audit log
   * @param {Array} entries - Log entries
   */
  write(entries) {
    try {
      if (!this.encryptionKey) {
        console.warn('[AUDIT] Cannot write log without encryption key');
        return false;
      }

      // Validate entries is an array
      if (!Array.isArray(entries)) {
        entries = [];
      }

      // Limit to max entries
      if (entries.length > this.maxEntries) {
        entries = entries.slice(-this.maxEntries);
      }

      // Age-based cleanup: remove entries older than 90 days
      const MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000; // 90 days
      const cutoffTime = Date.now() - MAX_AGE_MS;
      entries = entries.filter(entry => {
        const entryTime = new Date(entry.timestamp).getTime();
        return !isNaN(entryTime) && entryTime >= cutoffTime;
      });

      const { encrypted, iv, tag } = encryption.encrypt(
        JSON.stringify(entries),
        this.encryptionKey
      );

      const encryptedLog = {
        data: encrypted,
        iv,
        tag,
        version: '1.0',
        updatedAt: new Date().toISOString()
      };

      fs.writeFileSync(this.logPath, JSON.stringify(encryptedLog, null, 2));
      return true;
    } catch (err) {
      console.error('[AUDIT] Failed to write log:', err.message);
      return false;
    }
  }

  /**
   * Logs an event
   * @param {string} event - Event type
   * @param {object} details - Event details
   * @param {string} severity - Event severity (info, warning, critical)
   */
  log(event, details = {}, severity = 'info') {
    try {
      const entries = this.read();

      const entry = {
        id: crypto.randomBytes(8).toString('hex'),
        timestamp: new Date().toISOString(),
        event,
        severity,
        details,
        ip: details.ip || null,
        userAgent: details.userAgent || null
      };

      // Remove sensitive data from details before logging
      if (entry.details && typeof entry.details === 'object') {
        if (entry.details.password) delete entry.details.password;
        if (entry.details.masterPassword) delete entry.details.masterPassword;
      }

      entries.push(entry);
      this.write(entries);

      // Only log event type to console (no sensitive details) in development
      if (process.env.NODE_ENV === 'development') {
        const severityPrefix = {
          info: '[INFO]',
          warning: '[WARN]',
          critical: '[CRIT]'
        }[severity] || '[LOG]';
        // Only log event name, never details (could contain sensitive info)
        console.log(`${severityPrefix} [AUDIT] ${event}`);
      }
    } catch (err) {
      // Don't log error details either - could leak sensitive information
      console.error('[AUDIT] Failed to log event');
    }
  }

  /**
   * Logs vault unlock
   */
  logUnlock(success = true, failedAttempts = 0) {
    this.log('vault.unlock', {
      success,
      failedAttempts,
      timestamp: Date.now()
    }, success ? 'info' : 'warning');
  }

  /**
   * Logs vault lock
   * @param {string} reason - Optional reason for lock
   */
  logLock(reason = null) {
    this.log('vault.lock', {
      reason,
      timestamp: Date.now()
    }, 'info');
  }

  /**
   * Logs failed unlock attempt
   */
  logFailedUnlock(failedAttempts) {
    this.log('vault.unlock.failed', {
      failedAttempts,
      timestamp: Date.now()
    }, failedAttempts >= 5 ? 'critical' : 'warning');
  }

  /**
   * Logs rate limit triggered
   */
  logRateLimitTriggered(remainingSeconds) {
    this.log('vault.rate_limit', {
      remainingSeconds,
      timestamp: Date.now()
    }, 'critical');
  }

  /**
   * Logs password copy to clipboard
   */
  logPasswordCopy(itemType, itemName) {
    this.log('password.copy', {
      itemType,
      itemName,
      timestamp: Date.now()
    }, 'info');
  }

  /**
   * Logs password view
   */
  logPasswordView(itemType, itemName) {
    this.log('password.view', {
      itemType,
      itemName,
      timestamp: Date.now()
    }, 'info');
  }

  /**
   * Logs item creation
   */
  logItemCreate(itemType, itemName) {
    this.log('item.create', {
      itemType,
      itemName,
      timestamp: Date.now()
    }, 'info');
  }

  /**
   * Logs item deletion
   */
  logItemDelete(itemType, itemName) {
    this.log('item.delete', {
      itemType,
      itemName,
      timestamp: Date.now()
    }, 'info');
  }

  /**
   * Logs file upload
   */
  logFileUpload(fileName, fileSize) {
    this.log('file.upload', {
      fileName,
      fileSize,
      timestamp: Date.now()
    }, 'info');
  }

  /**
   * Logs file download
   */
  logFileDownload(fileName) {
    this.log('file.download', {
      fileName,
      timestamp: Date.now()
    }, 'info');
  }

  /**
   * Logs export
   */
  logExport(encrypted) {
    this.log('vault.export', {
      encrypted,
      timestamp: Date.now()
    }, 'warning');
  }

  /**
   * Logs import
   */
  logImport(encrypted, itemCount) {
    this.log('vault.import', {
      encrypted,
      itemCount,
      timestamp: Date.now()
    }, 'warning');
  }

  /**
   * Logs master password change
   */
  logPasswordChange() {
    this.log('vault.password_change', {
      timestamp: Date.now()
    }, 'critical');
  }

  /**
   * Logs integrity check failure
   */
  logIntegrityFailure(fileName) {
    this.log('security.integrity_failure', {
      fileName,
      timestamp: Date.now()
    }, 'critical');
  }

  /**
   * Gets log entries with filtering
   * @param {object} filters - Filter options
   * @returns {Array} Filtered entries
   */
  getEntries(filters = {}) {
    const entries = this.read();

    let filtered = entries;

    if (filters.severity) {
      filtered = filtered.filter(e => e.severity === filters.severity);
    }

    if (filters.event) {
      filtered = filtered.filter(e => e.event.includes(filters.event));
    }

    if (filters.since) {
      const sinceDate = new Date(filters.since);
      filtered = filtered.filter(e => new Date(e.timestamp) >= sinceDate);
    }

    if (filters.limit) {
      filtered = filtered.slice(-filters.limit);
    }

    return filtered.reverse(); // Most recent first
  }

  /**
   * Clears all log entries
   */
  clear() {
    try {
      this.write([]);
      this.log('audit.cleared', { timestamp: Date.now() }, 'warning');
      return true;
    } catch (err) {
      console.error('[AUDIT] Failed to clear log:', err.message);
      return false;
    }
  }

  /**
   * Exports log as JSON
   * @returns {string} JSON string of all entries
   */
  export() {
    const entries = this.read();
    return JSON.stringify(entries, null, 2);
  }
}

module.exports = AuditLog;
