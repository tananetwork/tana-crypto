import { describe, test, expect } from 'bun:test'
import {
  pubkeyToAddress,
  validateAddress,
  verifyPubkeyMatchesAddress,
  isAddress,
  isPublicKey,
  toAddress,
  formatForDisplay,
  generateKeypair,
  ADDRESS_VERSION_MAINNET,
  ADDRESS_VERSION_TESTNET,
  ADDRESS_HASH_BYTES,
  ADDRESS_CHECKSUM_BYTES
} from './index'

// Test public key (from sovereign account)
const TEST_PUBKEY = 'ed25519_59ec49da6fc8c1882e37000b9facf3999cfd3ba27c9b5185d00ab113745d0cdf'
const TEST_PUBKEY_RAW = '59ec49da6fc8c1882e37000b9facf3999cfd3ba27c9b5185d00ab113745d0cdf'

describe('Address Encoding', () => {
  test('pubkeyToAddress generates 18-char address from prefixed pubkey', () => {
    const result = pubkeyToAddress(TEST_PUBKEY)

    expect(result.address).toBeDefined()
    expect(result.address.length).toBeGreaterThanOrEqual(17)
    expect(result.address.length).toBeLessThanOrEqual(19)
    expect(result.network).toBe('mainnet')
    expect(result.hash.length).toBe(ADDRESS_HASH_BYTES * 2) // hex = 2 chars per byte
  })

  test('pubkeyToAddress works with raw hex pubkey (no prefix)', () => {
    const result = pubkeyToAddress(TEST_PUBKEY_RAW)

    expect(result.address).toBeDefined()
    expect(result.network).toBe('mainnet')
  })

  test('same pubkey always generates same address', () => {
    const result1 = pubkeyToAddress(TEST_PUBKEY)
    const result2 = pubkeyToAddress(TEST_PUBKEY)

    expect(result1.address).toBe(result2.address)
    expect(result1.hash).toBe(result2.hash)
  })

  test('prefixed and raw pubkey generate same address', () => {
    const withPrefix = pubkeyToAddress(TEST_PUBKEY)
    const withoutPrefix = pubkeyToAddress(TEST_PUBKEY_RAW)

    expect(withPrefix.address).toBe(withoutPrefix.address)
  })

  test('different networks generate different addresses', () => {
    const mainnet = pubkeyToAddress(TEST_PUBKEY, 'mainnet')
    const testnet = pubkeyToAddress(TEST_PUBKEY, 'testnet')

    expect(mainnet.address).not.toBe(testnet.address)
    expect(mainnet.hash).toBe(testnet.hash) // Same hash, different version byte
  })

  test('throws on invalid pubkey length', () => {
    expect(() => pubkeyToAddress('deadbeef')).toThrow('Invalid public key length')
  })
})

describe('Address Validation', () => {
  test('validates correctly encoded address', () => {
    const { address } = pubkeyToAddress(TEST_PUBKEY)
    const result = validateAddress(address)

    expect(result.valid).toBe(true)
    expect(result.network).toBe('mainnet')
    expect(result.hash).toBeDefined()
  })

  test('validates testnet address', () => {
    const { address } = pubkeyToAddress(TEST_PUBKEY, 'testnet')
    const result = validateAddress(address)

    expect(result.valid).toBe(true)
    expect(result.network).toBe('testnet')
  })

  test('rejects address with invalid checksum', () => {
    const { address } = pubkeyToAddress(TEST_PUBKEY)
    // Modify last character to break checksum
    const corrupted = address.slice(0, -1) + (address.slice(-1) === 'A' ? 'B' : 'A')

    const result = validateAddress(corrupted)
    expect(result.valid).toBe(false)
    expect(result.error).toContain('checksum')
  })

  test('rejects invalid Base58 characters', () => {
    const result = validateAddress('0OIl') // Contains invalid chars: 0, O, I, l

    expect(result.valid).toBe(false)
    expect(result.error).toContain('Base58')
  })

  test('rejects wrong length address', () => {
    const result = validateAddress('abc')

    expect(result.valid).toBe(false)
  })
})

describe('Address Verification', () => {
  test('verifies pubkey matches its address', () => {
    const { address } = pubkeyToAddress(TEST_PUBKEY)

    expect(verifyPubkeyMatchesAddress(TEST_PUBKEY, address)).toBe(true)
  })

  test('rejects wrong pubkey for address', async () => {
    const { address } = pubkeyToAddress(TEST_PUBKEY)
    const { publicKey: otherPubkey } = await generateKeypair()

    expect(verifyPubkeyMatchesAddress(otherPubkey, address)).toBe(false)
  })

  test('returns false for invalid address', () => {
    expect(verifyPubkeyMatchesAddress(TEST_PUBKEY, 'invalid')).toBe(false)
  })
})

describe('Type Detection', () => {
  test('isAddress detects valid address format', () => {
    const { address } = pubkeyToAddress(TEST_PUBKEY)

    expect(isAddress(address)).toBe(true)
  })

  test('isAddress rejects pubkey format', () => {
    expect(isAddress(TEST_PUBKEY)).toBe(false)
    expect(isAddress(TEST_PUBKEY_RAW)).toBe(false)
  })

  test('isPublicKey detects prefixed pubkey', () => {
    expect(isPublicKey(TEST_PUBKEY)).toBe(true)
  })

  test('isPublicKey detects raw hex pubkey', () => {
    expect(isPublicKey(TEST_PUBKEY_RAW)).toBe(true)
  })

  test('isPublicKey rejects address format', () => {
    const { address } = pubkeyToAddress(TEST_PUBKEY)
    expect(isPublicKey(address)).toBe(false)
  })

  test('isPublicKey rejects invalid strings', () => {
    expect(isPublicKey('invalid')).toBe(false)
    expect(isPublicKey('')).toBe(false)
    expect(isPublicKey('abc123')).toBe(false)
  })
})

describe('Conversion Helpers', () => {
  test('toAddress converts pubkey to address', () => {
    const result = toAddress(TEST_PUBKEY)
    const { address } = pubkeyToAddress(TEST_PUBKEY)

    expect(result).toBe(address)
  })

  test('toAddress passes through valid address', () => {
    const { address } = pubkeyToAddress(TEST_PUBKEY)
    const result = toAddress(address)

    expect(result).toBe(address)
  })

  test('formatForDisplay works with pubkey', () => {
    const result = formatForDisplay(TEST_PUBKEY)
    const { address } = pubkeyToAddress(TEST_PUBKEY)

    expect(result).toBe(address)
  })

  test('formatForDisplay works with address', () => {
    const { address } = pubkeyToAddress(TEST_PUBKEY)
    const result = formatForDisplay(address)

    expect(result).toBe(address)
  })
})

describe('Integration with generateKeypair', () => {
  test('freshly generated keypair produces valid address', async () => {
    const { publicKey } = await generateKeypair()
    const { address } = pubkeyToAddress(publicKey)

    expect(validateAddress(address).valid).toBe(true)
    expect(verifyPubkeyMatchesAddress(publicKey, address)).toBe(true)
  })

  test('multiple keypairs produce unique addresses', async () => {
    const addresses = new Set<string>()

    for (let i = 0; i < 10; i++) {
      const { publicKey } = await generateKeypair()
      const { address } = pubkeyToAddress(publicKey)
      addresses.add(address)
    }

    expect(addresses.size).toBe(10)
  })
})

describe('Visual Variety', () => {
  test('addresses have good character variety', async () => {
    const addresses: string[] = []

    for (let i = 0; i < 20; i++) {
      const { publicKey } = await generateKeypair()
      const { address } = pubkeyToAddress(publicKey)
      addresses.push(address)
    }

    // Check that addresses use a good variety of characters overall
    // With 20 addresses of 18 chars each, we should see significant variety
    const allChars = new Set(addresses.join('').split(''))
    expect(allChars.size).toBeGreaterThan(15) // Good variety of Base58 chars

    // Verify addresses are unique (no collisions in 20 random addresses)
    const uniqueAddresses = new Set(addresses)
    expect(uniqueAddresses.size).toBe(20)
  })
})

describe('Constants', () => {
  test('version bytes are correct', () => {
    expect(ADDRESS_VERSION_MAINNET).toBe(0x41)
    expect(ADDRESS_VERSION_TESTNET).toBe(0x6f)
  })

  test('hash and checksum sizes are correct', () => {
    expect(ADDRESS_HASH_BYTES).toBe(8)
    expect(ADDRESS_CHECKSUM_BYTES).toBe(4)
  })
})
