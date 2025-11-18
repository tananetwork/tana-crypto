/**
 * @tana/crypto
 *
 * Centralized cryptography utilities for Tana blockchain
 *
 * This package provides:
 * - Ed25519 signature generation and verification
 * - Standardized prefix handling for keys and signatures
 * - Canonical message formatting for blockchain transactions
 * - Comprehensive error handling and logging
 *
 * All blockchain services and mobile apps should use this package
 * to ensure consistent cryptographic operations.
 */

import * as ed from '@noble/ed25519'
import { createHash } from 'crypto'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Standard prefixes for Tana blockchain cryptography
 *
 * These prefixes help distinguish between different types of hex-encoded data:
 * - Keys use 'ed25519_' prefix
 * - Signatures use 'ed25519_sig_' prefix
 */
export const PREFIX_KEY = 'ed25519_' as const
export const PREFIX_SIGNATURE = 'ed25519_sig_' as const

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

export interface SignatureVerificationResult {
  valid: boolean
  error?: string
  details?: {
    signaturePrefix?: string
    publicKeyPrefix?: string
    messageHashHex?: string
  }
}

export interface TransactionMessage {
  type: string
  from: string
  to: string
  timestamp: number
  nonce: number
  amount?: string | null
  currencyCode?: string | null
  contractId?: string
  contractInput?: any
  metadata?: any
}

export interface AuthMessage {
  sessionId: string
  challenge: string
  userId: string
  username: string
  timestamp: number
}

// ============================================================================
// PREFIX UTILITIES
// ============================================================================

/**
 * Remove all known prefixes from a hex string
 *
 * Handles both 'ed25519_sig_' and 'ed25519_' prefixes in the correct order
 * (longer prefix first to avoid partial matches)
 *
 * @param hex - Hex string that may have a prefix
 * @returns Clean hex string without any prefix
 */
export function stripPrefix(hex: string): string {
  if (hex.startsWith(PREFIX_SIGNATURE)) {
    return hex.substring(PREFIX_SIGNATURE.length)
  }
  if (hex.startsWith(PREFIX_KEY)) {
    return hex.substring(PREFIX_KEY.length)
  }
  return hex
}

/**
 * Add the signature prefix to a hex string if not already present
 *
 * @param hex - Hex string (with or without prefix)
 * @returns Hex string with signature prefix
 */
export function addSignaturePrefix(hex: string): string {
  const clean = stripPrefix(hex)
  return `${PREFIX_SIGNATURE}${clean}`
}

/**
 * Add the key prefix to a hex string if not already present
 *
 * @param hex - Hex string (with or without prefix)
 * @returns Hex string with key prefix
 */
export function addKeyPrefix(hex: string): string {
  const clean = stripPrefix(hex)
  return `${PREFIX_KEY}${clean}`
}

// ============================================================================
// CONVERSION UTILITIES
// ============================================================================

/**
 * Convert hex string to Uint8Array
 * Automatically strips any prefixes
 *
 * @param hex - Hex string to convert
 * @returns Uint8Array of bytes
 * @throws Error if hex string is invalid
 */
export function hexToBytes(hex: string): Uint8Array {
  const clean = stripPrefix(hex)

  // Validate hex string
  if (!/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error(
      `Invalid hex string: contains non-hexadecimal characters. ` +
      `Input: "${hex.substring(0, 32)}${hex.length > 32 ? '...' : ''}"`
    )
  }

  if (clean.length % 2 !== 0) {
    throw new Error(
      `Invalid hex string: odd length (${clean.length} characters). ` +
      `Hex strings must have an even number of characters.`
    )
  }

  return Buffer.from(clean, 'hex')
}

/**
 * Convert Uint8Array to hex string
 * Does NOT add any prefix
 *
 * @param bytes - Bytes to convert
 * @returns Hex string without prefix
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}

// ============================================================================
// HASHING
// ============================================================================

/**
 * Hash a string or buffer with SHA-256
 *
 * @param data - String or buffer to hash
 * @returns SHA-256 hash as Buffer
 */
export function sha256(data: string | Buffer): Buffer {
  return createHash('sha256').update(data).digest()
}

/**
 * Hash a string with SHA-256 and return hex
 *
 * @param data - String to hash
 * @returns SHA-256 hash as hex string (no prefix)
 */
export function sha256Hex(data: string): string {
  return sha256(data).toString('hex')
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

/**
 * Verify an Ed25519 signature with detailed error reporting
 *
 * This function:
 * 1. Strips prefixes from signature and public key
 * 2. Validates hex format
 * 3. Hashes the message with SHA-256
 * 4. Verifies the signature using Ed25519
 * 5. Returns detailed error information on failure
 *
 * @param message - The original message that was signed
 * @param signatureHex - Ed25519 signature (with or without prefix)
 * @param publicKeyHex - Ed25519 public key (with or without prefix)
 * @param options - Optional logging configuration
 * @returns Verification result with error details
 */
export async function verifySignature(
  message: string,
  signatureHex: string,
  publicKeyHex: string,
  options: { debug?: boolean; label?: string } = {}
): Promise<SignatureVerificationResult> {
  const { debug = false, label = 'signature verification' } = options

  try {
    // Log input if debug mode
    if (debug) {
      console.log(`[crypto:${label}] Verifying signature`)
      console.log(`[crypto:${label}] Message length: ${message.length} characters`)
      console.log(`[crypto:${label}] Signature: ${signatureHex.substring(0, 32)}...`)
      console.log(`[crypto:${label}] Public key: ${publicKeyHex.substring(0, 32)}...`)
    }

    // Strip prefixes and validate
    const cleanSignature = stripPrefix(signatureHex)
    const cleanPublicKey = stripPrefix(publicKeyHex)

    // Log prefixes if debug mode
    if (debug && signatureHex !== cleanSignature) {
      const prefix = signatureHex.substring(0, signatureHex.length - cleanSignature.length)
      console.log(`[crypto:${label}] Stripped signature prefix: "${prefix}"`)
    }
    if (debug && publicKeyHex !== cleanPublicKey) {
      const prefix = publicKeyHex.substring(0, publicKeyHex.length - cleanPublicKey.length)
      console.log(`[crypto:${label}] Stripped public key prefix: "${prefix}"`)
    }

    // Convert to bytes (will throw if invalid hex)
    let signatureBytes: Uint8Array
    let publicKeyBytes: Uint8Array

    try {
      signatureBytes = hexToBytes(cleanSignature)
    } catch (error: any) {
      return {
        valid: false,
        error: 'Invalid signature format',
        details: {
          signaturePrefix: signatureHex.substring(0, 12),
          messageHashHex: error.message
        }
      }
    }

    try {
      publicKeyBytes = hexToBytes(cleanPublicKey)
    } catch (error: any) {
      return {
        valid: false,
        error: 'Invalid public key format',
        details: {
          publicKeyPrefix: publicKeyHex.substring(0, 12),
          messageHashHex: error.message
        }
      }
    }

    // Validate key sizes
    if (signatureBytes.length !== 64) {
      return {
        valid: false,
        error: `Invalid signature length: expected 64 bytes, got ${signatureBytes.length} bytes`,
        details: {
          signaturePrefix: signatureHex.substring(0, 12)
        }
      }
    }

    if (publicKeyBytes.length !== 32) {
      return {
        valid: false,
        error: `Invalid public key length: expected 32 bytes, got ${publicKeyBytes.length} bytes`,
        details: {
          publicKeyPrefix: publicKeyHex.substring(0, 12)
        }
      }
    }

    // Hash the message
    const messageHash = sha256(message)
    const messageHashHex = messageHash.toString('hex')

    if (debug) {
      console.log(`[crypto:${label}] Message hash: ${messageHashHex.substring(0, 16)}...`)
    }

    // Verify signature
    const isValid = await ed.verifyAsync(signatureBytes, messageHash, publicKeyBytes)

    if (debug) {
      console.log(`[crypto:${label}] Verification result: ${isValid ? 'VALID ✓' : 'INVALID ✗'}`)
    }

    if (!isValid) {
      return {
        valid: false,
        error: 'Signature verification failed - signature does not match message and public key',
        details: {
          signaturePrefix: signatureHex.substring(0, 12),
          publicKeyPrefix: publicKeyHex.substring(0, 12),
          messageHashHex: messageHashHex.substring(0, 16)
        }
      }
    }

    return { valid: true }

  } catch (error: any) {
    console.error(`[crypto:${label}] Unexpected error:`, error)
    return {
      valid: false,
      error: `Unexpected error during signature verification: ${error.message}`,
      details: {
        signaturePrefix: signatureHex?.substring(0, 12),
        publicKeyPrefix: publicKeyHex?.substring(0, 12)
      }
    }
  }
}

/**
 * Verify signature with simple boolean return
 * Uses verifySignature internally but only returns true/false
 *
 * @param message - The original message that was signed
 * @param signatureHex - Ed25519 signature (with or without prefix)
 * @param publicKeyHex - Ed25519 public key (with or without prefix)
 * @returns True if signature is valid, false otherwise
 */
export async function verifySignatureSimple(
  message: string,
  signatureHex: string,
  publicKeyHex: string
): Promise<boolean> {
  const result = await verifySignature(message, signatureHex, publicKeyHex)
  return result.valid
}

// ============================================================================
// CANONICAL MESSAGE FORMATTING
// ============================================================================

/**
 * Create canonical transaction message for signing/verification
 *
 * This creates a deterministic JSON string representation of a transaction
 * that can be signed and verified. The order of fields matters!
 *
 * @param tx - Transaction data
 * @returns Canonical JSON string
 */
export function createTransactionMessage(tx: TransactionMessage): string {
  // Create deterministic ordered object
  const canonical: any = {
    type: tx.type,
    from: tx.from,
    to: tx.to,
    timestamp: tx.timestamp,
    nonce: tx.nonce,
  }

  // Add optional fields in order
  if (tx.amount !== undefined && tx.amount !== null) {
    canonical.amount = tx.amount
  }
  if (tx.currencyCode !== undefined && tx.currencyCode !== null) {
    canonical.currencyCode = tx.currencyCode
  }
  if (tx.contractId !== undefined) {
    canonical.contractId = tx.contractId
  }
  if (tx.contractInput !== undefined) {
    canonical.contractInput = tx.contractInput
  }
  if (tx.metadata !== undefined) {
    canonical.metadata = tx.metadata
  }

  return JSON.stringify(canonical)
}

/**
 * Create canonical authentication message for QR code login
 *
 * @param auth - Authentication data
 * @returns Canonical JSON string
 */
export function createAuthMessage(auth: AuthMessage): string {
  const canonical = {
    sessionId: auth.sessionId,
    challenge: auth.challenge,
    userId: auth.userId,
    username: auth.username,
    timestamp: auth.timestamp,
  }

  return JSON.stringify(canonical)
}

// ============================================================================
// HIGH-LEVEL VERIFICATION FUNCTIONS
// ============================================================================

/**
 * Verify a transaction signature
 *
 * Recreates the canonical message and verifies the signature
 *
 * @param tx - Transaction data (must match what was signed)
 * @param signature - Ed25519 signature hex
 * @param publicKey - Ed25519 public key hex
 * @param options - Optional logging configuration
 * @returns Verification result
 */
export async function verifyTransactionSignature(
  tx: TransactionMessage,
  signature: string,
  publicKey: string,
  options: { debug?: boolean } = {}
): Promise<SignatureVerificationResult> {
  const message = createTransactionMessage(tx)

  return await verifySignature(message, signature, publicKey, {
    ...options,
    label: `transaction:${tx.type}`
  })
}

/**
 * Verify an authentication signature
 *
 * Recreates the canonical auth message and verifies the signature
 *
 * @param auth - Authentication data (must match what was signed)
 * @param signature - Ed25519 signature hex
 * @param publicKey - Ed25519 public key hex
 * @param options - Optional logging configuration
 * @returns Verification result
 */
export async function verifyAuthSignature(
  auth: AuthMessage,
  signature: string,
  publicKey: string,
  options: { debug?: boolean } = {}
): Promise<SignatureVerificationResult> {
  const message = createAuthMessage(auth)

  return await verifySignature(message, signature, publicKey, {
    ...options,
    label: `auth:${auth.sessionId}`
  })
}

// ============================================================================
// KEYPAIR GENERATION
// ============================================================================

/**
 * Generate a new Ed25519 keypair
 *
 * @returns Object with publicKey and privateKey as hex strings with prefixes
 */
export async function generateKeypair(): Promise<{ publicKey: string; privateKey: string }> {
  // Generate a random 32-byte private key using Web Crypto API
  // This is more portable than @noble/ed25519's utils.randomPrivateKey
  const privateKeyBytes = new Uint8Array(32)

  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    // Browser or Bun
    crypto.getRandomValues(privateKeyBytes)
  } else {
    // Node.js fallback
    const { randomBytes } = await import('crypto')
    const buffer = randomBytes(32)
    privateKeyBytes.set(buffer)
  }

  // Derive the public key from the private key
  const publicKeyBytes = await ed.getPublicKeyAsync(privateKeyBytes)

  // Convert to hex strings with prefixes
  const privateKey = addKeyPrefix(bytesToHex(privateKeyBytes))
  const publicKey = addKeyPrefix(bytesToHex(publicKeyBytes))

  return {
    publicKey,
    privateKey
  }
}

/**
 * Generate an Ed25519 signature for a message
 *
 * @param message - The message to sign
 * @param privateKeyHex - Ed25519 private key (with or without prefix)
 * @returns Ed25519 signature as hex string with prefix
 */
export async function signMessage(message: string, privateKeyHex: string): Promise<string> {
  // Strip prefix and convert to bytes
  const privateKeyBytes = hexToBytes(privateKeyHex)

  // Hash the message
  const messageHash = sha256(message)

  // Sign the message hash
  const signatureBytes = await ed.signAsync(messageHash, privateKeyBytes)

  // Return signature with prefix
  return addSignaturePrefix(bytesToHex(signatureBytes))
}

// ============================================================================
// SERVICE AUTH TOKENS (SAT)
// ============================================================================

// Re-export all SAT functionality
export {
  generateToken,
  verifyToken as verifySATToken,
  encodeToken,
  decodeToken,
  ServiceKeyRegistry,
  type ServiceAuthToken,
  type ServiceKey
} from './service-auth'

// Re-export middleware (only if hono is available)
export {
  serviceAuth,
  getAuthContext,
  requireService,
  requireNode,
  type ServiceAuthContext
} from './middleware'
