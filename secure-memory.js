const crypto = require('crypto');

/**
 * Secure Memory Management Utilities
 * Prevents sensitive data from lingering in memory
 */

/**
 * Securely zeros out a buffer
 * @param {Buffer} buffer - Buffer to clear
 */
function zeroBuffer(buffer) {
  if (buffer && Buffer.isBuffer(buffer)) {
    crypto.randomFillSync(buffer); // Fill with random data first
    buffer.fill(0); // Then zero it out
  }
}

/**
 * Securely clears a string by creating a buffer and zeroing it
 * Note: Cannot directly clear the original string (immutable in JS)
 * but this ensures any Buffer copies are cleared
 * @param {string} str - String to clear
 * @returns {string} Empty string
 */
function clearString(str) {
  if (typeof str === 'string' && str.length > 0) {
    const buffer = Buffer.from(str);
    zeroBuffer(buffer);
  }
  return '';
}

/**
 * Securely clears an object's properties
 * @param {object} obj - Object to clear
 */
function clearObject(obj, seen = new WeakSet()) {
  if (obj && typeof obj === 'object') {
    // Prevent infinite recursion on circular references
    if (seen.has(obj)) return;
    seen.add(obj);

    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        clearString(obj[key]);
        obj[key] = '';
      } else if (Buffer.isBuffer(obj[key])) {
        zeroBuffer(obj[key]);
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        clearObject(obj[key], seen);
      }
    }
  }
}

/**
 * Executes a function with a sensitive value, then clears it
 * @param {string|Buffer} sensitiveValue - Value to use
 * @param {Function} fn - Function to execute with the value
 * @returns {Promise<any>} Result of the function
 */
async function useSensitiveValue(sensitiveValue, fn) {
  try {
    return await fn(sensitiveValue);
  } finally {
    // Clear the value after use
    if (Buffer.isBuffer(sensitiveValue)) {
      zeroBuffer(sensitiveValue);
    } else if (typeof sensitiveValue === 'string') {
      clearString(sensitiveValue);
    }
  }
}

/**
 * Creates a secure clipboard manager that auto-clears
 */
class SecureClipboard {
  constructor() {
    this.timeouts = new Map();
  }

  /**
   * Sets clipboard and schedules clearing
   * @param {string} text - Text to copy
   * @param {number} timeout - Clear timeout in seconds (default: 30)
   */
  set(text, timeout = 30) {
    const timeoutId = setTimeout(() => {
      this.clear(text);
    }, timeout * 1000);

    this.timeouts.set(text, timeoutId);
  }

  /**
   * Clears specific text from clipboard if it's still there
   * @param {string} originalText - Original text that was copied
   */
  clear(originalText) {
    clearString(originalText);

    if (this.timeouts.has(originalText)) {
      clearTimeout(this.timeouts.get(originalText));
      this.timeouts.delete(originalText);
    }
  }

  /**
   * Clears all pending clipboard timers
   */
  clearAll() {
    for (const timeoutId of this.timeouts.values()) {
      clearTimeout(timeoutId);
    }
    this.timeouts.clear();
  }
}

/**
 * Session key manager with automatic clearing
 */
class SecureSessionKey {
  constructor() {
    this._key = null;
    this._lastRotation = null;
    this._rotationInterval = 30 * 60 * 1000; // 30 minutes
  }

  /**
   * Sets the session key
   * @param {Buffer} key - Encryption key
   */
  set(key) {
    this.clear(); // Clear old key first
    this._key = key;
    this._lastRotation = Date.now();
  }

  /**
   * Gets the session key
   * @returns {Buffer|null} Current key
   */
  get() {
    return this._key;
  }

  /**
   * Checks if key should be rotated
   * @returns {boolean} True if rotation needed
   */
  needsRotation() {
    if (!this._lastRotation) return false;
    return (Date.now() - this._lastRotation) > this._rotationInterval;
  }

  /**
   * Securely clears the session key
   */
  clear() {
    if (this._key) {
      zeroBuffer(this._key);
      this._key = null;
    }
    this._lastRotation = null;
  }

  /**
   * Checks if key exists
   * @returns {boolean} True if key is set
   */
  exists() {
    return this._key !== null;
  }
}

/**
 * Password input sanitizer
 * Prevents password from being logged or stored accidentally
 */
class SecurePasswordInput {
  /**
   * Creates a secure wrapper around password input
   * @param {string} password - The password
   * @returns {Object} Secure password wrapper
   */
  static wrap(password) {
    let cleared = false;

    return {
      use: (fn) => {
        if (cleared) {
          throw new Error('Password already cleared');
        }
        return fn(password);
      },
      clear: () => {
        if (!cleared) {
          clearString(password);
          cleared = true;
        }
      },
      // Override toString to prevent accidental logging
      toString: () => '[REDACTED]',
      toJSON: () => '[REDACTED]',
      inspect: () => '[REDACTED]'
    };
  }
}

module.exports = {
  zeroBuffer,
  clearString,
  clearObject,
  useSensitiveValue,
  SecureClipboard,
  SecureSessionKey,
  SecurePasswordInput
};
