/**
 * Service Auth Tokens (SAT)
 *
 * JWT-like authentication for inter-service communication using Ed25519 signatures.
 * Provides zero-trust authentication without shared secrets.
 */

import * as ed from '@noble/ed25519'
import { stripPrefix, sha256, bytesToHex } from './index'

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

export interface ServiceAuthToken {
  serviceId: 'ledger' | 't4' | 'mesh' | 'identity' | 'notifications'
  nodeId: string
  timestamp: number
  expiresAt: number
  payload?: Record<string, any>
  signature: string
}

export interface ServiceKey {
  serviceId: string
  nodeId: string
  publicKey: string
  privateKey?: string
}

// ============================================================================
// TOKEN GENERATION
// ============================================================================

/**
 * Create canonical message for token signing
 */
function createTokenMessage(token: Omit<ServiceAuthToken, 'signature'>): string {
  return JSON.stringify({
    serviceId: token.serviceId,
    nodeId: token.nodeId,
    timestamp: token.timestamp,
    expiresAt: token.expiresAt,
    payload: token.payload || {}
  })
}

/**
 * Generate a service auth token
 *
 * @param serviceId - The service creating the token
 * @param nodeId - The node ID of the service
 * @param privateKey - Ed25519 private key (hex with or without prefix)
 * @param payload - Optional payload data
 * @param ttl - Time-to-live in milliseconds (default: 1 hour)
 * @returns Service auth token with signature
 */
export function generateToken(
  serviceId: ServiceAuthToken['serviceId'],
  nodeId: string,
  privateKey: string,
  payload?: Record<string, any>,
  ttl: number = 3600000 // 1 hour
): ServiceAuthToken {
  const timestamp = Date.now()
  const expiresAt = timestamp + ttl

  const tokenData: Omit<ServiceAuthToken, 'signature'> = {
    serviceId,
    nodeId,
    timestamp,
    expiresAt,
    payload
  }

  // Create canonical message and sign
  const message = createTokenMessage(tokenData)
  const messageHash = sha256(message)

  const cleanKey = stripPrefix(privateKey)
  const privateKeyBytes = Buffer.from(cleanKey, 'hex')
  // Use synchronous ed.sign() - sha512Sync configured in index.ts
  const signatureBytes = ed.sign(messageHash, privateKeyBytes)

  return {
    ...tokenData,
    signature: `ed25519_${bytesToHex(signatureBytes)}`
  }
}

// ============================================================================
// TOKEN VERIFICATION
// ============================================================================

/**
 * Verify a service auth token
 *
 * @param token - The token to verify
 * @param publicKey - Ed25519 public key to verify against
 * @returns True if token is valid and not expired
 */
export async function verifyToken(
  token: ServiceAuthToken,
  publicKey: string
): Promise<boolean> {
  try {
    // Check expiry
    if (Date.now() > token.expiresAt) {
      console.warn('[SAT] Token expired')
      return false
    }

    // Check timestamp is not from the future (allow 1 minute clock skew)
    if (token.timestamp > Date.now() + 60000) {
      console.warn('[SAT] Token timestamp is in the future')
      return false
    }

    // Verify signature
    const tokenData: Omit<ServiceAuthToken, 'signature'> = {
      serviceId: token.serviceId,
      nodeId: token.nodeId,
      timestamp: token.timestamp,
      expiresAt: token.expiresAt,
      payload: token.payload
    }

    const message = createTokenMessage(tokenData)
    const messageHash = sha256(message)

    const cleanSignature = stripPrefix(token.signature)
    const cleanPublicKey = stripPrefix(publicKey)

    const signatureBytes = Buffer.from(cleanSignature, 'hex')
    const publicKeyBytes = Buffer.from(cleanPublicKey, 'hex')

    const valid = await ed.verifyAsync(signatureBytes, messageHash, publicKeyBytes)

    if (!valid) {
      console.warn('[SAT] Invalid signature')
    }

    return valid

  } catch (error: any) {
    console.error('[SAT] Verification error:', error.message)
    return false
  }
}

// ============================================================================
// TOKEN ENCODING
// ============================================================================

/**
 * Encode token to Authorization header format
 *
 * @param token - The service auth token
 * @returns Base64-encoded token string with "Bearer " prefix
 */
export function encodeToken(token: ServiceAuthToken): string {
  const tokenString = JSON.stringify(token)
  const base64 = Buffer.from(tokenString).toString('base64')
  return `Bearer ${base64}`
}

/**
 * Decode token from Authorization header
 *
 * @param authHeader - Authorization header value ("Bearer <base64>")
 * @returns Decoded service auth token, or null if invalid
 */
export function decodeToken(authHeader: string): ServiceAuthToken | null {
  try {
    if (!authHeader.startsWith('Bearer ')) {
      return null
    }

    const base64 = authHeader.substring(7)
    const tokenString = Buffer.from(base64, 'base64').toString('utf-8')
    const token = JSON.parse(tokenString) as ServiceAuthToken

    // Basic validation
    if (!token.serviceId || !token.nodeId || !token.signature) {
      return null
    }

    return token

  } catch (error) {
    return null
  }
}

// ============================================================================
// SERVICE KEY REGISTRY
// ============================================================================

/**
 * Service key registry for verification
 *
 * Allows services to verify tokens from other services without database queries
 */
export class ServiceKeyRegistry {
  private keys: Map<string, string> = new Map()

  /**
   * Register a service's public key
   */
  register(serviceId: string, nodeId: string, publicKey: string): void {
    const key = `${nodeId}:${serviceId}`
    this.keys.set(key, publicKey)
  }

  /**
   * Get public key for a service
   */
  get(serviceId: string, nodeId: string): string | null {
    const key = `${nodeId}:${serviceId}`
    return this.keys.get(key) || null
  }

  /**
   * Check if a service is registered
   */
  has(serviceId: string, nodeId: string): boolean {
    const key = `${nodeId}:${serviceId}`
    return this.keys.has(key)
  }

  /**
   * Remove a service from the registry
   */
  remove(serviceId: string, nodeId: string): void {
    const key = `${nodeId}:${serviceId}`
    this.keys.delete(key)
  }

  /**
   * Get all registered services
   */
  all(): Array<{ serviceId: string; nodeId: string; publicKey: string }> {
    const result: Array<{ serviceId: string; nodeId: string; publicKey: string }> = []

    for (const [key, publicKey] of this.keys.entries()) {
      const [nodeId, serviceId] = key.split(':')
      result.push({ serviceId, nodeId, publicKey })
    }

    return result
  }

  /**
   * Clear all keys
   */
  clear(): void {
    this.keys.clear()
  }
}
