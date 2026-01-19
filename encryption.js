const crypto = require('crypto');

/**
 * Eterna Encryption Module
 * Provides AES-256-GCM encryption for sensitive data storage
 */

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits
const SALT_LENGTH = 32;
const TAG_LENGTH = 16; // eslint-disable-line no-unused-vars -- kept for documentation
const PBKDF2_ITERATIONS = 600000; // 2x Bitwarden standard, ~6x OWASP minimum for stronger protection

/**
 * Derives a cryptographic key from a master password using PBKDF2
 * @param {string} masterPassword - The user's master password
 * @param {Buffer} salt - Salt for key derivation (generate if not provided)
 * @param {number} iterations - Number of PBKDF2 iterations (for backward compatibility with old vaults)
 * @returns {Object} { key: Buffer, salt: Buffer, iterations: number }
 */
function deriveKey(masterPassword, salt = null, iterations = null) {
  // Accept any password - no validation
  if (!masterPassword) {
    throw new Error('Master password required');
  }

  // Generate salt if not provided
  if (!salt) {
    salt = crypto.randomBytes(SALT_LENGTH);
  }

  // Use provided iterations or default to current standard
  const iterCount = iterations || PBKDF2_ITERATIONS;

  // Derive key using PBKDF2 with SHA-256
  const key = crypto.pbkdf2Sync(
    masterPassword,
    salt,
    iterCount,
    KEY_LENGTH,
    'sha256'
  );

  return { key, salt, iterations: iterCount };
}

/**
 * Encrypts data using AES-256-GCM
 * @param {string|object} data - Data to encrypt (will be JSON stringified)
 * @param {Buffer} key - Encryption key
 * @returns {Object} { encrypted: string, iv: string, tag: string }
 */
function encrypt(data, key) {
  if (!key || key.length !== KEY_LENGTH) {
    throw new Error('Invalid encryption key');
  }

  // Validate data is not null/undefined
  if (data === null || data === undefined) {
    throw new Error('Cannot encrypt null or undefined data');
  }

  // Convert data to JSON string if it's an object
  const plaintext = typeof data === 'string' ? data : JSON.stringify(data);

  // Check for empty data (could indicate accidental data loss)
  // Note: Empty data is allowed but unusual - caller should validate if needed

  // Generate random IV
  const iv = crypto.randomBytes(IV_LENGTH);

  // Create cipher
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  // Encrypt data
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Get authentication tag
  const tag = cipher.getAuthTag();

  return {
    encrypted,
    iv: iv.toString('hex'),
    tag: tag.toString('hex')
  };
}

/**
 * Decrypts data encrypted with AES-256-GCM
 * @param {string} encryptedData - Hex-encoded encrypted data
 * @param {string} ivHex - Hex-encoded IV
 * @param {string} tagHex - Hex-encoded authentication tag
 * @param {Buffer} key - Decryption key
 * @returns {string|object} Decrypted data (parsed from JSON if possible)
 */
function decrypt(encryptedData, ivHex, tagHex, key) {
  if (!key || key.length !== KEY_LENGTH) {
    throw new Error('Invalid decryption key');
  }

  // Validate IV hex format (must be 32 hex chars = 16 bytes)
  if (!ivHex || !/^[0-9a-f]{32}$/i.test(ivHex)) {
    throw new Error('Invalid IV format');
  }

  // Validate tag hex format (must be 32 hex chars = 16 bytes)
  if (!tagHex || !/^[0-9a-f]{32}$/i.test(tagHex)) {
    throw new Error('Invalid authentication tag format');
  }

  // Validate encrypted data is valid hex
  if (!encryptedData || !/^[0-9a-f]+$/i.test(encryptedData)) {
    throw new Error('Invalid encrypted data format');
  }

  try {
    // Convert hex strings to buffers
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');

    // Create decipher
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    // Decrypt data
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    // Try to parse as JSON, otherwise return as string
    try {
      return JSON.parse(decrypted);
    } catch (_e) {
      return decrypted;
    }
  } catch (_err) {
    throw new Error('Decryption failed: Invalid key or corrupted data');
  }
}

/**
 * Encrypts an entire vault data object
 * @param {object} vaultData - The entire vault data object
 * @param {string} masterPassword - User's master password
 * @returns {Object} { encryptedVault: object, salt: string }
 */
function encryptVault(vaultData, masterPassword) {
  // Derive key from master password
  const { key, salt } = deriveKey(masterPassword);

  // Encrypt the entire vault data
  const { encrypted, iv, tag } = encrypt(vaultData, key);

  return {
    encryptedVault: {
      data: encrypted,
      iv,
      tag,
      version: '1.0', // For future migration compatibility
      algorithm: ALGORITHM,
      iterations: PBKDF2_ITERATIONS
    },
    salt: salt.toString('hex')
  };
}

/**
 * Decrypts an entire vault data object
 * @param {object} encryptedVault - Encrypted vault object
 * @param {string} saltHex - Hex-encoded salt
 * @param {string} masterPassword - User's master password
 * @returns {object} Decrypted vault data
 */
function decryptVault(encryptedVault, saltHex, masterPassword) {
  // Derive key from master password and stored salt
  // Use stored iterations for backward compatibility with older vaults
  const salt = Buffer.from(saltHex, 'hex');
  const storedIterations = encryptedVault.iterations ?? PBKDF2_ITERATIONS;
  const { key } = deriveKey(masterPassword, salt, storedIterations);

  // Decrypt the vault
  const decrypted = decrypt(
    encryptedVault.data,
    encryptedVault.iv,
    encryptedVault.tag,
    key
  );

  return decrypted;
}

/**
 * Generates a cryptographically secure random password
 * @param {number} length - Password length (default: 32)
 * @param {object} options - Character set options
 * @returns {string} Generated password
 */
function generateSecurePassword(length = 32, options = {}) {
  const {
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSymbols = true
  } = options;

  let charset = '';
  if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (includeNumbers) charset += '0123456789';
  if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

  if (charset.length === 0) {
    throw new Error('At least one character type must be included');
  }

  let password = '';
  const charsetLength = charset.length;

  // Use rejection sampling to avoid modulo bias
  // Calculate the largest multiple of charsetLength that fits in a byte
  const maxValidValue = Math.floor(256 / charsetLength) * charsetLength;

  let i = 0;
  while (password.length < length) {
    // Generate more random bytes if needed
    const randomBytes = crypto.randomBytes(Math.max(length - password.length, 32));

    for (let j = 0; j < randomBytes.length && password.length < length; j++) {
      const randomValue = randomBytes[j];
      // Reject values that would cause bias
      if (randomValue < maxValidValue) {
        password += charset[randomValue % charsetLength];
      }
    }
    i++;
    // Safety limit to prevent infinite loop (extremely unlikely)
    if (i > 100) {
      // If we hit the limit, throw error instead of returning short password
      throw new Error('Password generation failed - unable to generate enough random bytes');
    }
  }

  return password;
}

/**
 * Validates master password strength
 * @param {string} password - Password to validate
 * @returns {Object} { valid: boolean, strength: string, feedback: string[] }
 */
function validatePasswordStrength(password) {
  const feedback = [];
  let strength = 'weak';

  if (!password || password.length < 8) {
    feedback.push('Password must be at least 8 characters long');
    return { valid: false, strength: 'very-weak', feedback };
  }

  if (password.length < 12) {
    feedback.push('Consider using at least 12 characters for better security');
    strength = 'weak';
  }

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSymbols = /[^A-Za-z0-9]/.test(password);

  const varietyScore = [hasUppercase, hasLowercase, hasNumbers, hasSymbols].filter(Boolean).length;

  if (!hasUppercase || !hasLowercase) {
    feedback.push('Use both uppercase and lowercase letters');
  }
  if (!hasNumbers) {
    feedback.push('Include numbers');
  }
  if (!hasSymbols) {
    feedback.push('Include special characters');
  }

  // Determine strength
  if (password.length >= 16 && varietyScore >= 3) {
    strength = 'very-strong';
  } else if (password.length >= 12 && varietyScore >= 3) {
    strength = 'strong';
  } else if (password.length >= 10 && varietyScore >= 2) {
    strength = 'medium';
  }

  return {
    valid: password.length >= 8,
    strength,
    feedback: feedback.length > 0 ? feedback : ['Password strength: ' + strength]
  };
}

/**
 * Hash a password for verification using PBKDF2
 * Uses same iterations as key derivation for consistent security
 * @param {string} password - Password to hash
 * @param {Buffer|string} salt - Salt for hashing (required for security)
 * @param {number} iterations - Optional iterations override for backward compatibility
 * @returns {string} Hex-encoded hash
 */
function hashPassword(password, salt, iterations = null) {
  if (!salt) {
    throw new Error('Salt is required for secure password hashing');
  }

  // Convert salt to Buffer if it's a hex string, with validation
  let saltBuffer;
  if (typeof salt === 'string') {
    // Validate hex format (must be 64 hex chars = 32 bytes)
    if (!/^[0-9a-f]{64}$/i.test(salt)) {
      throw new Error('Invalid salt format: must be 64 hex characters');
    }
    saltBuffer = Buffer.from(salt, 'hex');
  } else if (Buffer.isBuffer(salt)) {
    if (salt.length !== SALT_LENGTH) {
      throw new Error(`Invalid salt length: expected ${SALT_LENGTH} bytes`);
    }
    saltBuffer = salt;
  } else {
    throw new Error('Salt must be a hex string or Buffer');
  }

  // Use same iterations as key derivation for consistent security
  const iterCount = iterations || PBKDF2_ITERATIONS;
  const hash = crypto.pbkdf2Sync(
    password,
    saltBuffer,
    iterCount,
    32,
    'sha256'
  );

  return hash.toString('hex');
}

module.exports = {
  deriveKey,
  encrypt,
  decrypt,
  encryptVault,
  decryptVault,
  generateSecurePassword,
  validatePasswordStrength,
  hashPassword,
  constants: {
    ALGORITHM,
    KEY_LENGTH,
    IV_LENGTH,
    SALT_LENGTH,
    PBKDF2_ITERATIONS
  }
};
