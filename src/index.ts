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
import { sha256 as sha256Noble } from '@noble/hashes/sha2.js'
import bs58 from 'bs58'

// Note: Using @noble/hashes instead of Node.js crypto for cross-platform compatibility
// This allows the package to work in both Node.js and React Native environments

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

/**
 * Address version bytes for network identification
 *
 * These version bytes are prepended to the address payload before Base58 encoding.
 * Different version bytes produce different leading characters in the final address:
 * - 0x41 (mainnet) produces addresses starting with various chars (good visual variety)
 * - 0x6F (testnet) produces addresses with different leading chars
 */
export const ADDRESS_VERSION_MAINNET = 0x41 as const
export const ADDRESS_VERSION_TESTNET = 0x6f as const

/**
 * Address hash size in bytes (8 bytes = 64 bits)
 *
 * This determines the collision resistance:
 * - 8 bytes = 2^64 address space
 * - Birthday attack threshold: ~2^32 = 4 billion addresses
 * - Safe for expected Tana user base
 */
export const ADDRESS_HASH_BYTES = 8 as const

/**
 * Checksum size in bytes
 *
 * 4-byte checksum catches typos with 1 in ~4 billion probability of missing an error.
 * Uses double SHA-256 (same as Bitcoin).
 */
export const ADDRESS_CHECKSUM_BYTES = 4 as const

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

export type NetworkType = 'mainnet' | 'testnet'

export interface AddressInfo {
  /** The address string (Base58Check encoded) */
  address: string
  /** The truncated hash of the public key (hex) */
  hash: string
  /** Network type */
  network: NetworkType
}

export interface AddressValidationResult {
  /** Whether the address is valid */
  valid: boolean
  /** Network type if valid */
  network?: NetworkType
  /** Error message if invalid */
  error?: string
  /** The decoded hash if valid (hex) */
  hash?: string
}

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
 * Uses @noble/hashes for cross-platform compatibility (Node.js + React Native)
 *
 * @param data - String or buffer to hash
 * @returns SHA-256 hash as Buffer
 */
export function sha256(data: string | Buffer | Uint8Array): Buffer {
  if (typeof data === 'string') {
    return Buffer.from(sha256Noble(new TextEncoder().encode(data)))
  }
  return Buffer.from(sha256Noble(data))
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
// ADDRESS ENCODING/DECODING
// ============================================================================

/**
 * Convert a public key to a Tana address
 *
 * The address format is:
 * 1. SHA-256 hash of public key (32 bytes)
 * 2. Truncate to first 8 bytes
 * 3. Prepend version byte (0x41 mainnet, 0x6F testnet)
 * 4. Append 4-byte checksum (double SHA-256)
 * 5. Base58 encode
 *
 * Result: 18-character address with good visual variety
 *
 * @param pubkey - Ed25519 public key (with or without 'ed25519_' prefix)
 * @param network - Network type ('mainnet' or 'testnet')
 * @returns AddressInfo with address string, hash, and network
 *
 * @example
 * const keypair = await generateKeypair()
 * const info = pubkeyToAddress(keypair.publicKey)
 * console.log(info.address) // "6RZ411u7FhSG2DkcKt"
 */
export function pubkeyToAddress(
  pubkey: string,
  network: NetworkType = 'mainnet'
): AddressInfo {
  // Strip prefix and convert to bytes
  const pubkeyBytes = hexToBytes(pubkey)

  if (pubkeyBytes.length !== 32) {
    throw new Error(
      `Invalid public key length: expected 32 bytes, got ${pubkeyBytes.length} bytes`
    )
  }

  // Hash the public key and take first 8 bytes
  const fullHash = sha256(Buffer.from(pubkeyBytes))
  const truncatedHash = fullHash.slice(0, ADDRESS_HASH_BYTES)

  // Get version byte based on network
  const version =
    network === 'mainnet' ? ADDRESS_VERSION_MAINNET : ADDRESS_VERSION_TESTNET

  // Create versioned payload: [version byte] + [8-byte hash]
  const versionedPayload = Buffer.concat([
    Buffer.from([version]),
    truncatedHash
  ])

  // Calculate checksum: first 4 bytes of double SHA-256
  const checksum = sha256(sha256(versionedPayload)).slice(
    0,
    ADDRESS_CHECKSUM_BYTES
  )

  // Encode as Base58: [version] + [hash] + [checksum]
  const address = bs58.encode(Buffer.concat([versionedPayload, checksum]))

  return {
    address,
    hash: truncatedHash.toString('hex'),
    network
  }
}

/**
 * Validate a Tana address and extract its components
 *
 * Checks:
 * 1. Valid Base58 encoding
 * 2. Correct length (13 bytes: 1 version + 8 hash + 4 checksum)
 * 3. Known version byte
 * 4. Valid checksum
 *
 * @param address - The address string to validate
 * @returns Validation result with network type and hash if valid
 *
 * @example
 * const result = validateAddress("6RZ411u7FhSG2DkcKt")
 * if (result.valid) {
 *   console.log(result.network) // "mainnet"
 *   console.log(result.hash)    // "abc123..."
 * }
 */
export function validateAddress(address: string): AddressValidationResult {
  try {
    // Decode from Base58
    let bytes: Buffer
    try {
      bytes = Buffer.from(bs58.decode(address))
    } catch {
      return { valid: false, error: 'Invalid Base58 encoding' }
    }

    // Check length: 1 (version) + 8 (hash) + 4 (checksum) = 13 bytes
    const expectedLength = 1 + ADDRESS_HASH_BYTES + ADDRESS_CHECKSUM_BYTES
    if (bytes.length !== expectedLength) {
      return {
        valid: false,
        error: `Invalid address length: expected ${expectedLength} bytes, got ${bytes.length} bytes`
      }
    }

    // Extract components
    const version = bytes[0]
    const hash = bytes.slice(1, 1 + ADDRESS_HASH_BYTES)
    const checksum = bytes.slice(1 + ADDRESS_HASH_BYTES)

    // Verify version byte
    let network: NetworkType
    if (version === ADDRESS_VERSION_MAINNET) {
      network = 'mainnet'
    } else if (version === ADDRESS_VERSION_TESTNET) {
      network = 'testnet'
    } else {
      return {
        valid: false,
        error: `Unknown version byte: 0x${version.toString(16)}`
      }
    }

    // Verify checksum
    const versionedPayload = bytes.slice(0, 1 + ADDRESS_HASH_BYTES)
    const expectedChecksum = sha256(sha256(versionedPayload)).slice(
      0,
      ADDRESS_CHECKSUM_BYTES
    )

    if (!checksum.equals(expectedChecksum)) {
      return { valid: false, error: 'Invalid checksum' }
    }

    return {
      valid: true,
      network,
      hash: hash.toString('hex')
    }
  } catch (error: any) {
    return {
      valid: false,
      error: `Unexpected error: ${error.message}`
    }
  }
}

/**
 * Check if a public key matches a given address
 *
 * This is used to verify that a claimed public key corresponds to an address.
 * For example, when a user signs a transaction, they include their public key.
 * The network verifies that hash(publicKey) == address.
 *
 * @param pubkey - Ed25519 public key (with or without prefix)
 * @param address - Tana address to verify against
 * @returns True if the pubkey hashes to the given address
 *
 * @example
 * // When processing a transaction
 * if (!verifyPubkeyMatchesAddress(tx.from, senderAddress)) {
 *   throw new Error("Public key doesn't match sender address")
 * }
 */
export function verifyPubkeyMatchesAddress(
  pubkey: string,
  address: string
): boolean {
  try {
    // Validate the address first
    const validation = validateAddress(address)
    if (!validation.valid) {
      return false
    }

    // Generate address from pubkey and compare
    const derived = pubkeyToAddress(pubkey, validation.network)
    return derived.address === address
  } catch {
    return false
  }
}

/**
 * Check if a string is a valid Tana address format
 *
 * Quick check without full validation - just checks structure.
 * Use validateAddress() for complete validation with checksum verification.
 *
 * @param str - String to check
 * @returns True if the string looks like a Tana address
 */
export function isAddress(str: string): boolean {
  // Quick structural check: should be ~18 chars of Base58
  if (typeof str !== 'string' || str.length < 15 || str.length > 20) {
    return false
  }

  // Check for valid Base58 characters only
  const base58Chars = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/
  return base58Chars.test(str)
}

/**
 * Check if a string is a public key (not an address)
 *
 * Helps distinguish between pubkeys and addresses when handling
 * data from cookies, JWTs, or API responses.
 *
 * @param str - String to check
 * @returns True if the string looks like an Ed25519 public key
 */
export function isPublicKey(str: string): boolean {
  if (typeof str !== 'string') return false

  // Check for ed25519_ prefix
  if (str.startsWith(PREFIX_KEY)) {
    const hex = str.substring(PREFIX_KEY.length)
    return hex.length === 64 && /^[0-9a-fA-F]+$/.test(hex)
  }

  // Raw 64-char hex
  return str.length === 64 && /^[0-9a-fA-F]+$/.test(str)
}

/**
 * Convert a public key or address to its address form
 *
 * Handles both pubkeys and addresses gracefully - if already an address,
 * returns it as-is. If a pubkey, converts to address.
 *
 * Useful when handling data from cookies/JWTs where you don't know
 * if you have an address or pubkey.
 *
 * @param pubkeyOrAddress - Either a public key or address
 * @param network - Network type (only used if input is pubkey)
 * @returns The address string
 *
 * @example
 * // From JWT/cookie - might be either format
 * const displayAddress = toAddress(userIdentifier)
 */
export function toAddress(
  pubkeyOrAddress: string,
  network: NetworkType = 'mainnet'
): string {
  // If it's already a valid address, return it
  if (isAddress(pubkeyOrAddress)) {
    const validation = validateAddress(pubkeyOrAddress)
    if (validation.valid) {
      return pubkeyOrAddress
    }
  }

  // Otherwise, treat as pubkey and convert
  return pubkeyToAddress(pubkeyOrAddress, network).address
}

/**
 * Format an address or pubkey for display
 *
 * Always returns an address format (18 chars).
 * If input is a pubkey, converts it.
 * If input is an address, validates and returns it.
 *
 * @param pubkeyOrAddress - Public key or address
 * @param network - Network type (defaults to mainnet)
 * @returns Formatted address string
 * @throws Error if input is invalid
 */
export function formatForDisplay(
  pubkeyOrAddress: string,
  network: NetworkType = 'mainnet'
): string {
  return toAddress(pubkeyOrAddress, network)
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

// Re-export SAT functionality (pure functions - no framework dependency)
export {
  generateToken,
  verifyToken as verifySATToken,
  encodeToken,
  decodeToken,
  ServiceKeyRegistry,
  type ServiceAuthToken,
  type ServiceKey
} from './service-auth'

// Note: Hono middleware (serviceAuth, requireService, etc.) was intentionally
// removed from this package. The crypto package should contain only pure
// functions without framework dependencies. Services that need auth middleware
// should implement it using the SAT verification functions exported above.
