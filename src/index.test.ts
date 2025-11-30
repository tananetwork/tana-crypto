/**
 * @tananetwork/crypto - Unit Tests
 *
 * Tests for all pure cryptographic utilities.
 * Run with: bun test
 */

import { describe, test, expect } from 'bun:test'
import {
  // Constants
  PREFIX_KEY,
  PREFIX_SIGNATURE,
  // Prefix utilities
  stripPrefix,
  addSignaturePrefix,
  addKeyPrefix,
  // Conversion utilities
  hexToBytes,
  bytesToHex,
  // Hashing
  sha256,
  sha256Hex,
  // Message formatting
  createTransactionMessage,
  createAuthMessage,
  // Signing & verification
  generateKeypair,
  signMessage,
  verifySignature,
  verifySignatureSimple,
  verifyTransactionSignature,
  verifyAuthSignature,
} from './index'

// ============================================================================
// PREFIX UTILITIES
// ============================================================================

describe('stripPrefix', () => {
  test('removes ed25519_ prefix from keys', () => {
    const input = 'ed25519_abc123def456'
    expect(stripPrefix(input)).toBe('abc123def456')
  })

  test('removes ed25519_sig_ prefix from signatures', () => {
    const input = 'ed25519_sig_abc123def456'
    expect(stripPrefix(input)).toBe('abc123def456')
  })

  test('returns unchanged if no prefix present', () => {
    const input = 'abc123def456'
    expect(stripPrefix(input)).toBe('abc123def456')
  })

  test('handles empty string', () => {
    expect(stripPrefix('')).toBe('')
  })

  test('handles prefix-only string', () => {
    expect(stripPrefix('ed25519_')).toBe('')
    expect(stripPrefix('ed25519_sig_')).toBe('')
  })

  test('prioritizes longer sig_ prefix over key prefix', () => {
    // If someone accidentally double-prefixed, sig_ should be stripped first
    const input = 'ed25519_sig_test'
    expect(stripPrefix(input)).toBe('test')
  })
})

describe('addKeyPrefix', () => {
  test('adds prefix to bare hex', () => {
    expect(addKeyPrefix('abc123')).toBe('ed25519_abc123')
  })

  test('does not double-prefix if already present', () => {
    expect(addKeyPrefix('ed25519_abc123')).toBe('ed25519_abc123')
  })

  test('strips sig prefix and adds key prefix', () => {
    // Converts signature prefix to key prefix
    expect(addKeyPrefix('ed25519_sig_abc123')).toBe('ed25519_abc123')
  })

  test('handles empty string', () => {
    expect(addKeyPrefix('')).toBe('ed25519_')
  })
})

describe('addSignaturePrefix', () => {
  test('adds prefix to bare hex', () => {
    expect(addSignaturePrefix('abc123')).toBe('ed25519_sig_abc123')
  })

  test('does not double-prefix if already present', () => {
    expect(addSignaturePrefix('ed25519_sig_abc123')).toBe('ed25519_sig_abc123')
  })

  test('converts key prefix to signature prefix', () => {
    expect(addSignaturePrefix('ed25519_abc123')).toBe('ed25519_sig_abc123')
  })
})

// ============================================================================
// CONVERSION UTILITIES
// ============================================================================

describe('hexToBytes', () => {
  test('converts valid hex to bytes', () => {
    const bytes = hexToBytes('deadbeef')
    expect(bytes).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  test('handles uppercase hex', () => {
    const bytes = hexToBytes('DEADBEEF')
    expect(bytes).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  test('handles mixed case hex', () => {
    const bytes = hexToBytes('DeAdBeEf')
    expect(bytes).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  test('strips key prefix before conversion', () => {
    const bytes = hexToBytes('ed25519_deadbeef')
    expect(bytes).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  test('strips signature prefix before conversion', () => {
    const bytes = hexToBytes('ed25519_sig_deadbeef')
    expect(bytes).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  test('throws on invalid hex characters', () => {
    expect(() => hexToBytes('xyz123')).toThrow('non-hexadecimal')
  })

  test('throws on odd-length hex string', () => {
    expect(() => hexToBytes('abc')).toThrow('odd length')
  })

  test('handles empty string', () => {
    const bytes = hexToBytes('')
    expect(bytes).toEqual(new Uint8Array([]))
  })

  test('converts 32-byte key correctly', () => {
    const hex = 'a'.repeat(64) // 32 bytes = 64 hex chars
    const bytes = hexToBytes(hex)
    expect(bytes.length).toBe(32)
    expect(bytes.every(b => b === 0xaa)).toBe(true)
  })

  test('converts 64-byte signature correctly', () => {
    const hex = 'b'.repeat(128) // 64 bytes = 128 hex chars
    const bytes = hexToBytes(hex)
    expect(bytes.length).toBe(64)
    expect(bytes.every(b => b === 0xbb)).toBe(true)
  })
})

describe('bytesToHex', () => {
  test('converts bytes to hex', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
    expect(bytesToHex(bytes)).toBe('deadbeef')
  })

  test('handles empty array', () => {
    expect(bytesToHex(new Uint8Array([]))).toBe('')
  })

  test('pads single-digit hex values with zero', () => {
    const bytes = new Uint8Array([0x01, 0x02, 0x0f])
    expect(bytesToHex(bytes)).toBe('01020f')
  })

  test('round-trips with hexToBytes', () => {
    const original = 'cafebabe12345678'
    const bytes = hexToBytes(original)
    const result = bytesToHex(bytes)
    expect(result).toBe(original)
  })
})

// ============================================================================
// HASHING
// ============================================================================

describe('sha256', () => {
  test('hashes string deterministically', () => {
    const hash1 = sha256('hello')
    const hash2 = sha256('hello')
    expect(hash1).toEqual(hash2)
  })

  test('different inputs produce different hashes', () => {
    const hash1 = sha256('hello')
    const hash2 = sha256('world')
    expect(hash1).not.toEqual(hash2)
  })

  test('produces 32-byte output', () => {
    const hash = sha256('test')
    expect(hash.length).toBe(32)
  })

  test('matches known SHA-256 value', () => {
    // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    const hash = sha256('hello')
    expect(hash.toString('hex')).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
  })

  test('handles empty string', () => {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const hash = sha256('')
    expect(hash.toString('hex')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })
})

describe('sha256Hex', () => {
  test('returns hex string', () => {
    const hash = sha256Hex('hello')
    expect(typeof hash).toBe('string')
    expect(hash.length).toBe(64) // 32 bytes = 64 hex chars
  })

  test('matches sha256 output as hex', () => {
    const bufferHash = sha256('test').toString('hex')
    const hexHash = sha256Hex('test')
    expect(hexHash).toBe(bufferHash)
  })
})

// ============================================================================
// CANONICAL MESSAGE FORMATTING
// ============================================================================

describe('createTransactionMessage', () => {
  test('creates deterministic JSON with required fields', () => {
    const tx = {
      type: 'transfer',
      from: 'user-123',
      to: 'user-456',
      timestamp: 1700000000000,
      nonce: 1,
    }

    const message = createTransactionMessage(tx)
    const parsed = JSON.parse(message)

    expect(parsed.type).toBe('transfer')
    expect(parsed.from).toBe('user-123')
    expect(parsed.to).toBe('user-456')
    expect(parsed.timestamp).toBe(1700000000000)
    expect(parsed.nonce).toBe(1)
  })

  test('includes optional fields when provided', () => {
    const tx = {
      type: 'transfer',
      from: 'user-123',
      to: 'user-456',
      timestamp: 1700000000000,
      nonce: 1,
      amount: '100.50',
      currencyCode: 'USD',
    }

    const message = createTransactionMessage(tx)
    const parsed = JSON.parse(message)

    expect(parsed.amount).toBe('100.50')
    expect(parsed.currencyCode).toBe('USD')
  })

  test('excludes null/undefined optional fields', () => {
    const tx = {
      type: 'transfer',
      from: 'user-123',
      to: 'user-456',
      timestamp: 1700000000000,
      nonce: 1,
      amount: null,
      currencyCode: undefined,
    }

    const message = createTransactionMessage(tx)
    const parsed = JSON.parse(message)

    expect('amount' in parsed).toBe(false)
    expect('currencyCode' in parsed).toBe(false)
  })

  test('same input always produces same output (deterministic)', () => {
    const tx = {
      type: 'deposit',
      from: 'sovereign',
      to: 'user-789',
      timestamp: 1700000000000,
      nonce: 42,
      amount: '1000.00',
      currencyCode: 'USD',
    }

    const message1 = createTransactionMessage(tx)
    const message2 = createTransactionMessage(tx)

    expect(message1).toBe(message2)
  })

  test('includes contract fields for contract_call', () => {
    const tx = {
      type: 'contract_call',
      from: 'user-123',
      to: 'contract-abc',
      timestamp: 1700000000000,
      nonce: 5,
      contractId: 'contract-abc',
      contractInput: { action: 'mint', amount: 100 },
    }

    const message = createTransactionMessage(tx)
    const parsed = JSON.parse(message)

    expect(parsed.contractId).toBe('contract-abc')
    expect(parsed.contractInput).toEqual({ action: 'mint', amount: 100 })
  })
})

describe('createAuthMessage', () => {
  test('creates deterministic JSON for auth', () => {
    const auth = {
      sessionId: 'sess-123',
      challenge: 'challenge-abc',
      userId: 'user-456',
      username: '@alice',
      timestamp: 1700000000000,
    }

    const message = createAuthMessage(auth)
    const parsed = JSON.parse(message)

    expect(parsed.sessionId).toBe('sess-123')
    expect(parsed.challenge).toBe('challenge-abc')
    expect(parsed.userId).toBe('user-456')
    expect(parsed.username).toBe('@alice')
    expect(parsed.timestamp).toBe(1700000000000)
  })

  test('same input always produces same output', () => {
    const auth = {
      sessionId: 'sess-xyz',
      challenge: 'random-challenge',
      userId: 'user-999',
      username: '@bob',
      timestamp: 1700000000000,
    }

    const message1 = createAuthMessage(auth)
    const message2 = createAuthMessage(auth)

    expect(message1).toBe(message2)
  })
})

// ============================================================================
// KEYPAIR GENERATION
// ============================================================================

describe('generateKeypair', () => {
  test('generates keypair with correct prefixes', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    expect(publicKey.startsWith(PREFIX_KEY)).toBe(true)
    expect(privateKey.startsWith(PREFIX_KEY)).toBe(true)
  })

  test('generates 32-byte keys (64 hex chars after prefix)', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    const pubHex = stripPrefix(publicKey)
    const privHex = stripPrefix(privateKey)

    expect(pubHex.length).toBe(64)  // 32 bytes = 64 hex chars
    expect(privHex.length).toBe(64)
  })

  test('generates unique keypairs each time', async () => {
    const keypair1 = await generateKeypair()
    const keypair2 = await generateKeypair()

    expect(keypair1.publicKey).not.toBe(keypair2.publicKey)
    expect(keypair1.privateKey).not.toBe(keypair2.privateKey)
  })

  test('public and private keys are different', async () => {
    const { publicKey, privateKey } = await generateKeypair()
    expect(publicKey).not.toBe(privateKey)
  })
})

// ============================================================================
// SIGNING & VERIFICATION
// ============================================================================

describe('signMessage', () => {
  test('produces signature with correct prefix', async () => {
    const { privateKey } = await generateKeypair()
    const signature = await signMessage('hello', privateKey)

    expect(signature.startsWith(PREFIX_SIGNATURE)).toBe(true)
  })

  test('produces 64-byte signature (128 hex chars after prefix)', async () => {
    const { privateKey } = await generateKeypair()
    const signature = await signMessage('test message', privateKey)

    const sigHex = stripPrefix(signature)
    expect(sigHex.length).toBe(128) // 64 bytes = 128 hex chars
  })

  test('same message + key produces same signature (deterministic)', async () => {
    const { privateKey } = await generateKeypair()

    const sig1 = await signMessage('deterministic test', privateKey)
    const sig2 = await signMessage('deterministic test', privateKey)

    expect(sig1).toBe(sig2)
  })

  test('different messages produce different signatures', async () => {
    const { privateKey } = await generateKeypair()

    const sig1 = await signMessage('message one', privateKey)
    const sig2 = await signMessage('message two', privateKey)

    expect(sig1).not.toBe(sig2)
  })
})

describe('verifySignature', () => {
  test('valid signature returns { valid: true }', async () => {
    const { publicKey, privateKey } = await generateKeypair()
    const message = 'Hello, blockchain!'
    const signature = await signMessage(message, privateKey)

    const result = await verifySignature(message, signature, publicKey)

    expect(result.valid).toBe(true)
    expect(result.error).toBeUndefined()
  })

  test('wrong public key returns { valid: false } with error', async () => {
    const keypair1 = await generateKeypair()
    const keypair2 = await generateKeypair()

    const message = 'test'
    const signature = await signMessage(message, keypair1.privateKey)

    // Verify with WRONG public key
    const result = await verifySignature(message, signature, keypair2.publicKey)

    expect(result.valid).toBe(false)
    expect(result.error).toContain('verification failed')
  })

  test('tampered message returns { valid: false }', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    const originalMessage = 'Send $100 to Alice'
    const signature = await signMessage(originalMessage, privateKey)

    // Attacker tries to change the amount
    const tamperedMessage = 'Send $10000 to Alice'
    const result = await verifySignature(tamperedMessage, signature, publicKey)

    expect(result.valid).toBe(false)
  })

  test('invalid signature format returns error', async () => {
    const { publicKey } = await generateKeypair()

    const result = await verifySignature('test', 'not-valid-hex!@#', publicKey)

    expect(result.valid).toBe(false)
    expect(result.error).toContain('Invalid signature format')
  })

  test('invalid public key format returns error', async () => {
    const { privateKey } = await generateKeypair()
    const signature = await signMessage('test', privateKey)

    const result = await verifySignature('test', signature, 'bad-key!@#')

    expect(result.valid).toBe(false)
    expect(result.error).toContain('Invalid public key format')
  })

  test('wrong signature length returns error', async () => {
    const { publicKey } = await generateKeypair()

    // 32 bytes instead of 64
    const shortSig = 'ed25519_sig_' + 'aa'.repeat(32)
    const result = await verifySignature('test', shortSig, publicKey)

    expect(result.valid).toBe(false)
    expect(result.error).toContain('Invalid signature length')
  })

  test('wrong public key length returns error', async () => {
    const { privateKey } = await generateKeypair()
    const signature = await signMessage('test', privateKey)

    // 16 bytes instead of 32
    const shortKey = 'ed25519_' + 'bb'.repeat(16)
    const result = await verifySignature('test', signature, shortKey)

    expect(result.valid).toBe(false)
    expect(result.error).toContain('Invalid public key length')
  })
})

describe('verifySignatureSimple', () => {
  test('returns true for valid signature', async () => {
    const { publicKey, privateKey } = await generateKeypair()
    const message = 'simple test'
    const signature = await signMessage(message, privateKey)

    const isValid = await verifySignatureSimple(message, signature, publicKey)
    expect(isValid).toBe(true)
  })

  test('returns false for invalid signature', async () => {
    const keypair1 = await generateKeypair()
    const keypair2 = await generateKeypair()

    const signature = await signMessage('test', keypair1.privateKey)
    const isValid = await verifySignatureSimple('test', signature, keypair2.publicKey)

    expect(isValid).toBe(false)
  })
})

// ============================================================================
// HIGH-LEVEL VERIFICATION FUNCTIONS
// ============================================================================

describe('verifyTransactionSignature', () => {
  test('verifies valid transaction signature', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    const tx = {
      type: 'transfer' as const,
      from: 'user-123',
      to: 'user-456',
      timestamp: Date.now(),
      nonce: 1,
      amount: '50.00',
      currencyCode: 'USD',
    }

    // Sign the canonical message
    const message = createTransactionMessage(tx)
    const signature = await signMessage(message, privateKey)

    // Verify using the high-level function
    const result = await verifyTransactionSignature(tx, signature, publicKey)

    expect(result.valid).toBe(true)
  })

  test('rejects transaction with modified amount', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    const tx = {
      type: 'transfer' as const,
      from: 'user-123',
      to: 'user-456',
      timestamp: Date.now(),
      nonce: 1,
      amount: '50.00',
      currencyCode: 'USD',
    }

    const message = createTransactionMessage(tx)
    const signature = await signMessage(message, privateKey)

    // Attacker modifies the amount
    const tamperedTx = { ...tx, amount: '5000.00' }
    const result = await verifyTransactionSignature(tamperedTx, signature, publicKey)

    expect(result.valid).toBe(false)
  })

  test('rejects transaction with modified recipient', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    const tx = {
      type: 'transfer' as const,
      from: 'user-123',
      to: 'user-456',
      timestamp: Date.now(),
      nonce: 1,
      amount: '100.00',
      currencyCode: 'USD',
    }

    const message = createTransactionMessage(tx)
    const signature = await signMessage(message, privateKey)

    // Attacker changes the recipient
    const tamperedTx = { ...tx, to: 'attacker-wallet' }
    const result = await verifyTransactionSignature(tamperedTx, signature, publicKey)

    expect(result.valid).toBe(false)
  })
})

describe('verifyAuthSignature', () => {
  test('verifies valid auth signature', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    const auth = {
      sessionId: 'sess-abc123',
      challenge: 'random-challenge-xyz',
      userId: 'user-789',
      username: '@testuser',
      timestamp: Date.now(),
    }

    const message = createAuthMessage(auth)
    const signature = await signMessage(message, privateKey)

    const result = await verifyAuthSignature(auth, signature, publicKey)

    expect(result.valid).toBe(true)
  })

  test('rejects auth with modified session', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    const auth = {
      sessionId: 'sess-abc123',
      challenge: 'challenge',
      userId: 'user-789',
      username: '@alice',
      timestamp: Date.now(),
    }

    const message = createAuthMessage(auth)
    const signature = await signMessage(message, privateKey)

    // Attacker tries to hijack a different session
    const tamperedAuth = { ...auth, sessionId: 'sess-hijacked' }
    const result = await verifyAuthSignature(tamperedAuth, signature, publicKey)

    expect(result.valid).toBe(false)
  })
})

// ============================================================================
// EDGE CASES & SECURITY
// ============================================================================

describe('security edge cases', () => {
  test('empty message can be signed and verified', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    const signature = await signMessage('', privateKey)
    const result = await verifySignature('', signature, publicKey)

    expect(result.valid).toBe(true)
  })

  test('very long message can be signed and verified', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    const longMessage = 'x'.repeat(100000) // 100KB message
    const signature = await signMessage(longMessage, privateKey)
    const result = await verifySignature(longMessage, signature, publicKey)

    expect(result.valid).toBe(true)
  })

  test('unicode message can be signed and verified', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    const unicodeMessage = '你好世界 🌍 مرحبا العالم 🎉'
    const signature = await signMessage(unicodeMessage, privateKey)
    const result = await verifySignature(unicodeMessage, signature, publicKey)

    expect(result.valid).toBe(true)
  })

  test('newlines and special chars in message work correctly', async () => {
    const { publicKey, privateKey } = await generateKeypair()

    const specialMessage = 'line1\nline2\ttab\r\nwindows\0null'
    const signature = await signMessage(specialMessage, privateKey)
    const result = await verifySignature(specialMessage, signature, publicKey)

    expect(result.valid).toBe(true)
  })
})
