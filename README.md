# @tana/crypto

Centralized cryptography utilities for the Tana blockchain ecosystem.

## Features

- ✅ **Ed25519 Signature Verification** - Secure signature validation using @noble/ed25519
- ✅ **Standardized Prefix Handling** - Automatic handling of `ed25519_` and `ed25519_sig_` prefixes
- ✅ **Canonical Message Formatting** - Deterministic JSON formatting for transactions and auth
- ✅ **Comprehensive Error Messages** - Detailed error reporting for debugging
- ✅ **Optional Debug Logging** - Toggle verbose logging for troubleshooting
- ✅ **Type-Safe API** - Full TypeScript support with detailed type definitions

## Installation

```bash
bun install
```

## Usage

### Basic Signature Verification

```typescript
import { verifySignature } from '@tana/crypto'

const result = await verifySignature(
  message,
  signatureHex,  // Can have 'ed25519_sig_' prefix or not
  publicKeyHex,  // Can have 'ed25519_' prefix or not
  { debug: true } // Enable detailed logging
)

if (result.valid) {
  console.log('✓ Signature is valid')
} else {
  console.error('✗ Signature verification failed:', result.error)
  console.error('Details:', result.details)
}
```

### Transaction Signature Verification

```typescript
import { verifyTransactionSignature } from '@tana/crypto'

const result = await verifyTransactionSignature(
  {
    type: 'user_creation',
    from: systemId,
    to: userId,
    timestamp: Date.now(),
    nonce: 0,
    contractInput: { username, displayName, publicKey }
  },
  signature,
  publicKey,
  { debug: true }
)
```

### Authentication Signature Verification

```typescript
import { verifyAuthSignature } from '@tana/crypto'

const result = await verifyAuthSignature(
  {
    sessionId,
    challenge,
    userId,
    username,
    timestamp: Date.now()
  },
  signature,
  publicKey
)
```

### Prefix Utilities

```typescript
import { stripPrefix, addSignaturePrefix, addKeyPrefix } from '@tana/crypto'

// Remove any prefix
const clean = stripPrefix('ed25519_sig_abc123') // 'abc123'

// Add signature prefix
const sig = addSignaturePrefix('abc123') // 'ed25519_sig_abc123'

// Add key prefix
const key = addKeyPrefix('def456') // 'ed25519_def456'
```

## Error Handling

The library provides detailed error information:

```typescript
{
  valid: false,
  error: "Invalid signature length: expected 64 bytes, got 32 bytes",
  details: {
    signaturePrefix: "ed25519_sig_",
    publicKeyPrefix: "ed25519_",
    messageHashHex: "a1b2c3d4..."
  }
}
```

## Debug Mode

Enable debug mode to see detailed verification steps:

```typescript
const result = await verifySignature(message, sig, pubkey, {
  debug: true,
  label: 'user-registration' // Optional label for logs
})
```

Output:
```
[crypto:user-registration] Verifying signature
[crypto:user-registration] Message length: 256 characters
[crypto:user-registration] Signature: ed25519_sig_3c40823b561b43ba...
[crypto:user-registration] Public key: ed25519_aac29f66fe2e9d32...
[crypto:user-registration] Stripped signature prefix: "ed25519_sig_"
[crypto:user-registration] Message hash: a1b2c3d4e5f6...
[crypto:user-registration] Verification result: VALID ✓
```

## Architecture

This package is used by:
- **Ledger Service** - Transaction signature verification
- **Identity Service** - QR authentication signature verification
- **Mobile App** - Message signing and verification
- **CLI Tools** - User creation and transaction signing

All services import from this single source of truth to ensure consistent cryptographic operations across the entire Tana blockchain ecosystem.
