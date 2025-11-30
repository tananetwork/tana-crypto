import { describe, test, expect } from 'bun:test'
import {
  sha256,
  sha256Hex,
  pubkeyToAddress,
  hexToBytes,
  generateKeypair,
  bytesToHex
} from './index'

// Test public key (from sovereign account)
const TEST_PUBKEY = 'ed25519_59ec49da6fc8c1882e37000b9facf3999cfd3ba27c9b5185d00ab113745d0cdf'
const TEST_PUBKEY_RAW = '59ec49da6fc8c1882e37000b9facf3999cfd3ba27c9b5185d00ab113745d0cdf'

// Helper to compare Uint8Arrays
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

describe('SHA-256 Basic Operations', () => {
  test('hashes empty string correctly', () => {
    // NIST test vector: SHA-256("") = e3b0c442...
    const hash = sha256('')
    expect(bytesToHex(hash)).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })

  test('hashes "abc" correctly', () => {
    // NIST test vector: SHA-256("abc") = ba7816bf...
    const hash = sha256('abc')
    expect(bytesToHex(hash)).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })

  test('hashes longer string correctly', () => {
    // NIST test vector: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    const input = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    const hash = sha256(input)
    expect(bytesToHex(hash)).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1')
  })

  test('sha256Hex returns hex string directly', () => {
    const hashHex = sha256Hex('abc')
    expect(hashHex).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    expect(typeof hashHex).toBe('string')
  })

  test('produces 32-byte output (256 bits)', () => {
    const hash = sha256('test')
    expect(hash.length).toBe(32)
    expect(bytesToHex(hash).length).toBe(64)
  })
})

describe('SHA-256 Input Types', () => {
  test('accepts string input', () => {
    const hash = sha256('hello')
    expect(bytesToHex(hash)).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
  })

  test('accepts Uint8Array input', () => {
    const bytes = new TextEncoder().encode('hello')
    const hash = sha256(bytes)
    expect(bytesToHex(hash)).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
  })

  test('string and Uint8Array with same content produce same hash', () => {
    const fromString = sha256('test data')
    const fromUint8Array = sha256(new TextEncoder().encode('test data'))
    expect(arraysEqual(fromString, fromUint8Array)).toBe(true)
  })

  test('handles binary data (non-UTF8)', () => {
    // Binary data that isn't valid UTF-8
    const binaryData = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd])
    const hash = sha256(binaryData)
    expect(hash.length).toBe(32)
    // This should be consistent
    const hash2 = sha256(binaryData)
    expect(arraysEqual(hash, hash2)).toBe(true)
  })
})

describe('SHA-256 Consistency', () => {
  test('same input always produces same output', () => {
    const input = 'consistent test data'
    const hash1 = sha256(input)
    const hash2 = sha256(input)
    const hash3 = sha256(input)

    expect(arraysEqual(hash1, hash2)).toBe(true)
    expect(arraysEqual(hash2, hash3)).toBe(true)
  })

  test('different inputs produce different outputs', () => {
    const hash1 = sha256('input1')
    const hash2 = sha256('input2')
    const hash3 = sha256('input3')

    expect(arraysEqual(hash1, hash2)).toBe(false)
    expect(arraysEqual(hash2, hash3)).toBe(false)
    expect(arraysEqual(hash1, hash3)).toBe(false)
  })

  test('small change in input produces completely different hash', () => {
    const hash1 = sha256('hello')
    const hash2 = sha256('hellp') // One character different

    expect(arraysEqual(hash1, hash2)).toBe(false)
    // Avalanche effect: roughly half the bits should change
    let differentBits = 0
    for (let i = 0; i < hash1.length; i++) {
      const xor = hash1[i] ^ hash2[i]
      differentBits += xor.toString(2).split('1').length - 1
    }
    // Expect roughly 128 bits different (half of 256), allow wide margin
    expect(differentBits).toBeGreaterThan(50)
    expect(differentBits).toBeLessThan(200)
  })
})

describe('Public Key Hashing', () => {
  test('hashing known public key produces expected hash prefix', () => {
    // Hash the test sovereign pubkey
    const pubkeyBytes = hexToBytes(TEST_PUBKEY)
    const hash = sha256(pubkeyBytes)

    // Verify it's 32 bytes
    expect(hash.length).toBe(32)

    // The first 8 bytes form the address hash
    const addressHash = bytesToHex(hash.slice(0, 8))
    expect(addressHash.length).toBe(16) // 8 bytes = 16 hex chars
  })

  test('pubkey hash is deterministic', () => {
    const pubkeyBytes = hexToBytes(TEST_PUBKEY)

    const hash1 = sha256(pubkeyBytes)
    const hash2 = sha256(pubkeyBytes)
    const hash3 = sha256(pubkeyBytes)

    expect(arraysEqual(hash1, hash2)).toBe(true)
    expect(arraysEqual(hash2, hash3)).toBe(true)
  })

  test('prefixed and raw pubkey produce same hash', () => {
    const hashWithPrefix = sha256(hexToBytes(TEST_PUBKEY))
    const hashWithoutPrefix = sha256(hexToBytes(TEST_PUBKEY_RAW))

    expect(arraysEqual(hashWithPrefix, hashWithoutPrefix)).toBe(true)
  })

  test('address hash extraction is consistent with pubkeyToAddress', () => {
    const pubkeyBytes = hexToBytes(TEST_PUBKEY)
    const fullHash = sha256(pubkeyBytes)
    const truncatedHash = bytesToHex(fullHash.slice(0, 8))

    // Get hash from pubkeyToAddress
    const addressInfo = pubkeyToAddress(TEST_PUBKEY)

    // They should match
    expect(addressInfo.hash).toBe(truncatedHash)
  })

  test('different pubkeys produce different address hashes', async () => {
    const hashes = new Set<string>()

    for (let i = 0; i < 10; i++) {
      const { publicKey } = await generateKeypair()
      const pubkeyBytes = hexToBytes(publicKey)
      const hash = sha256(pubkeyBytes)
      const addressHash = bytesToHex(hash.slice(0, 8))
      hashes.add(addressHash)
    }

    // All 10 should be unique
    expect(hashes.size).toBe(10)
  })
})

describe('Double SHA-256 (for checksums)', () => {
  test('double hash produces different result than single hash', () => {
    const input = new TextEncoder().encode('test data')
    const singleHash = sha256(input)
    const doubleHash = sha256(sha256(input))

    expect(arraysEqual(singleHash, doubleHash)).toBe(false)
  })

  test('double hash is deterministic', () => {
    const input = new TextEncoder().encode('checksum test')

    const double1 = sha256(sha256(input))
    const double2 = sha256(sha256(input))

    expect(arraysEqual(double1, double2)).toBe(true)
  })

  test('checksum extraction matches address checksum logic', () => {
    // This tests the exact logic used in pubkeyToAddress for checksums
    const pubkeyBytes = hexToBytes(TEST_PUBKEY)
    const fullHash = sha256(pubkeyBytes)
    const truncatedHash = fullHash.slice(0, 8)

    // Version byte + hash = versioned payload
    const versionedPayload = new Uint8Array(1 + truncatedHash.length)
    versionedPayload[0] = 0x41 // mainnet version
    versionedPayload.set(truncatedHash, 1)

    // Double hash for checksum
    const checksum = sha256(sha256(versionedPayload)).slice(0, 4)

    // Checksum should be 4 bytes
    expect(checksum.length).toBe(4)

    // Should be deterministic
    const checksum2 = sha256(sha256(versionedPayload)).slice(0, 4)
    expect(arraysEqual(checksum, checksum2)).toBe(true)
  })
})

describe('SHA-256 Unicode and Special Cases', () => {
  test('handles unicode strings correctly', () => {
    const emoji = sha256('\u{1F510}\u{1F511}\u{1F4B0}')
    const japanese = sha256('\u3053\u3093\u306B\u3061\u306F')
    const mixed = sha256('Hello \u4E16\u754C \u{1F30D}')

    // All should produce valid 32-byte hashes
    expect(emoji.length).toBe(32)
    expect(japanese.length).toBe(32)
    expect(mixed.length).toBe(32)

    // And be different from each other
    expect(arraysEqual(emoji, japanese)).toBe(false)
    expect(arraysEqual(japanese, mixed)).toBe(false)
  })

  test('handles very long input', () => {
    const longInput = 'x'.repeat(100000)
    const hash = sha256(longInput)

    expect(hash.length).toBe(32)

    // Should still be deterministic
    const hash2 = sha256(longInput)
    expect(arraysEqual(hash, hash2)).toBe(true)
  })

  test('handles whitespace consistently', () => {
    const withSpace = sha256('hello world')
    const withoutSpace = sha256('helloworld')
    const withNewline = sha256('hello\nworld')
    const withTab = sha256('hello\tworld')

    // All should be different
    expect(arraysEqual(withSpace, withoutSpace)).toBe(false)
    expect(arraysEqual(withSpace, withNewline)).toBe(false)
    expect(arraysEqual(withSpace, withTab)).toBe(false)
  })

  test('JSON string hashing is deterministic', () => {
    // This is important for transaction message hashing
    const obj = { type: 'transfer', from: 'alice', to: 'bob', amount: '100' }
    const json = JSON.stringify(obj)

    const hash1 = sha256(json)
    const hash2 = sha256(json)

    expect(arraysEqual(hash1, hash2)).toBe(true)

    // Same JSON from different object should produce same hash
    const obj2 = { type: 'transfer', from: 'alice', to: 'bob', amount: '100' }
    const json2 = JSON.stringify(obj2)
    const hash3 = sha256(json2)

    expect(arraysEqual(hash1, hash3)).toBe(true)
  })
})

describe('Return Type Verification', () => {
  test('sha256 returns Uint8Array', () => {
    const result = sha256('test')
    expect(result instanceof Uint8Array).toBe(true)
  })

  test('sha256Hex returns string', () => {
    const result = sha256Hex('test')
    expect(typeof result).toBe('string')
    expect(result.length).toBe(64)
    expect(/^[0-9a-f]+$/.test(result)).toBe(true)
  })

  test('Uint8Array methods work on sha256 result', () => {
    const hash = sha256('test')

    // slice works
    const sliced = hash.slice(0, 8)
    expect(sliced.length).toBe(8)

    // bytesToHex works
    expect(typeof bytesToHex(hash)).toBe('string')

    // arraysEqual works
    expect(arraysEqual(hash, hash)).toBe(true)
  })
})
