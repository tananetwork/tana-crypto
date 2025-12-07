import {
  generateKeypair,
  signMessage,
  pubkeyToAddress
} from './src/index'

// Helper functions for JWT creation (matching @tananetwork/auth format)
function base64UrlEncode(data: string | Uint8Array): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
  return Buffer.from(bytes).toString('base64url')
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/**
 * Create a delegate JWT using @tananetwork/crypto signMessage
 * This matches the format expected by @tananetwork/auth verifyJwt
 */
async function createDelegateJwt(
  privateKey: string,
  publicKey: string,
  username: string,
  network: string,
  currentNonce: number,
  allowedTypes: string[]
): Promise<string> {
  const isMainnet = network.includes('mainnet') || network === 'tana.network'
  const networkType = isMainnet ? 'mainnet' : 'testnet'
  const addressInfo = pubkeyToAddress(publicKey, networkType as 'mainnet' | 'testnet')
  const address = addressInfo.address

  const now = Math.floor(Date.now() / 1000)
  const delegateExpiry = now + 300 // 5 minutes

  const claims = {
    sub: username,
    net: network,
    adr: address,
    iat: now,
    exp: delegateExpiry,
    iss: 'self',
    delegate: {
      allowed_types: allowedTypes,
      nonce_start: currentNonce,
      nonce_limit: 2,
      exp: delegateExpiry
    }
  }

  const header = { alg: 'EdDSA', typ: 'JWT' }
  const headerB64 = base64UrlEncode(JSON.stringify(header))
  const payloadB64 = base64UrlEncode(JSON.stringify(claims))
  const signatureInput = `${headerB64}.${payloadB64}`

  // Sign using @tananetwork/crypto signMessage (produces ed25519_sig_ prefixed signature)
  const signature = signMessage(signatureInput, privateKey)

  // Extract just the signature hex (remove 'ed25519_sig_' prefix)
  const signatureHex = signature.startsWith('ed25519_sig_')
    ? signature.substring(12)
    : signature

  // Encode signature as base64url
  const signatureB64 = base64UrlEncode(hexToBytes(signatureHex))

  return `${headerB64}.${payloadB64}.${signatureB64}`
}

async function main() {
  console.log('=== Website Update E2E Test ===\n')

  // Generate a fresh key pair for testing
  const keyPair = await generateKeypair()
  const addressResult = pubkeyToAddress(keyPair.publicKey)
  const address = addressResult.address  // Extract string from result object
  const username = '@testweb' + Date.now().toString().slice(-4)

  console.log('Test user address:', address)
  console.log('Test user public key:', keyPair.publicKey)
  console.log('Test username:', username)

  // Step 1: Create user
  console.log('\n--- Step 1: Create test user ---')
  const timestamp = Date.now()
  const userId = crypto.randomUUID()  // User ID is a UUID, not the address
  const userTx = {
    txId: crypto.randomUUID(),
    type: 'user_creation',
    from: userId,  // For self-signup, from and to are the same (new user's UUID)
    to: userId,    // User ID (UUID) for the new user
    contractInput: {
      username: username,
      displayName: username.slice(1),  // Remove @ prefix for display name
      publicKey: keyPair.publicKey,
      role: 'user'
    },
    timestamp,
    nonce: 0
  }

  const userPayload = JSON.stringify({
    type: userTx.type,
    from: userTx.from,
    to: userTx.to,
    contractInput: userTx.contractInput,
    timestamp: userTx.timestamp,
    nonce: userTx.nonce
  })
  const userSig = signMessage(userPayload, keyPair.privateKey)

  const userResp = await fetch('http://localhost:8502/transactions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...userTx, signature: userSig })
  })
  console.log('User creation queued:', await userResp.json())

  // Step 2: Produce block to create user
  console.log('\n--- Step 2: Produce block ---')
  const block1 = await fetch('http://localhost:8501/blocks/produce', { method: 'POST' })
  const block1Result = await block1.json()
  console.log('Block produced:', block1Result.height || block1Result)

  await new Promise(r => setTimeout(r, 1000))

  // Step 3: Deploy a new contract for our test user
  console.log('\n--- Step 3: Deploy a new contract ---')
  Bun.write(Bun.stdout, '')  // Force flush
  const contractId = crypto.randomUUID()
  console.log('Contract ID:', contractId)
  const contractSubdomain = `${address}-test-site`

  const deployTx = {
    txId: crypto.randomUUID(),
    type: 'contract_deployment',
    from: userId,  // User's UUID, not address
    to: contractId,
    contractInput: {
      name: contractSubdomain,
      sourceCode: 'export function contract() { return { content: "v1" }; }',
      codeHash: 'test-hash-' + Date.now(),
      initCode: '',
      contractCode: 'export function contract() { return { content: "v1" }; }',
      getCode: '',
      postCode: '',
      hasInit: false,
      hasGet: false,
      hasPost: false,
      version: '1.0.0',
      description: 'Test website pointer contract',
      metadata: {
        deploymentId: `${address}_initial1`,
        artifactHash: 'initial-hash',
        gitRepo: 'test-repo',
        fileManifest: [{ path: 'index.html', hash: 'initial', size: 100 }]
      }
    },
    timestamp: Date.now(),
    nonce: 1
  }

  const deployPayload = JSON.stringify({
    type: deployTx.type,
    from: deployTx.from,
    to: deployTx.to,
    contractInput: deployTx.contractInput,
    timestamp: deployTx.timestamp,
    nonce: deployTx.nonce
  })
  console.log('Signing deploy payload...')
  const deploySig = signMessage(deployPayload, keyPair.privateKey)
  console.log('Deploy signature:', deploySig.slice(0, 40) + '...')

  console.log('Sending to queue...')
  const deployResp = await fetch('http://localhost:8502/transactions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...deployTx, signature: deploySig })
  })
  console.log('Contract deployment queued:', await deployResp.json())

  // Step 4: Produce block for contract
  console.log('\n--- Step 4: Produce block ---')
  const block2 = await fetch('http://localhost:8501/blocks/produce', { method: 'POST' })
  const block2Result = await block2.json()
  console.log('Block produced:', block2Result.height || block2Result)

  await new Promise(r => setTimeout(r, 500))

  // Step 5: Stage updated content in T4
  console.log('\n--- Step 5: Stage content in T4 ---')
  const updateDeploymentId = `${address}_update01`
  const updatedContent = `<!DOCTYPE html><html><body><h1>Updated via website_update!</h1><p>Timestamp: ${new Date().toISOString()}</p></body></html>`
  const contentHash = await computeHash(updatedContent)

  const stageResp = await fetch(`http://localhost:8507/_pending/${updateDeploymentId}/index.html`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'text/html',
      'X-Content-Hash': contentHash
    },
    body: updatedContent
  })
  console.log('Content staged:', await stageResp.json())

  // Step 6: Generate delegate JWT using proper signMessage format
  console.log('\n--- Step 6: Generate delegate JWT ---')
  const jwt = await createDelegateJwt(
    keyPair.privateKey,
    keyPair.publicKey,
    username,
    'localhost:8501',
    2, // currentNonce
    ['website_update']
  )
  console.log('Generated JWT:', jwt.slice(0, 50) + '...')

  // Step 7: Submit website_update transaction
  console.log('\n--- Step 7: Submit website_update ---')
  const updateTimestamp = Date.now()
  const updateTxBase = {
    txId: crypto.randomUUID(),
    type: 'website_update',
    from: userId,  // User's UUID
    to: contractId,  // Target contract being updated
    payload: {
      subdomain: contractSubdomain,
      deploymentId: updateDeploymentId,
      artifactHash: contentHash,
      fileManifest: [{ path: 'index.html', hash: contentHash, size: updatedContent.length }]
    },
    delegateJwt: jwt,
    timestamp: updateTimestamp,
    nonce: 2
  }

  // Sign the transaction payload
  const updatePayload = JSON.stringify({
    type: updateTxBase.type,
    from: updateTxBase.from,
    to: updateTxBase.to,
    payload: updateTxBase.payload,
    timestamp: updateTxBase.timestamp,
    nonce: updateTxBase.nonce
  })
  const updateSig = signMessage(updatePayload, keyPair.privateKey)

  const updateTx = { ...updateTxBase, signature: updateSig }

  const updateResp = await fetch('http://localhost:8502/transactions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updateTx)
  })
  console.log('Website update queued:', await updateResp.json())

  // Step 8: Produce final block
  console.log('\n--- Step 8: Produce final block ---')
  const block3 = await fetch('http://localhost:8501/blocks/produce', { method: 'POST' })
  const block3Result = await block3.json()
  console.log('Block produced:', JSON.stringify(block3Result, null, 2))

  await new Promise(r => setTimeout(r, 500))

  // Step 9: Verify update
  console.log('\n--- Step 9: Verify update ---')
  const verifyResp = await fetch(`http://localhost:8507/content/${address}/${contractId}/index.html`)
  const verifyContent = await verifyResp.text()
  console.log('Content at T4:')
  console.log(verifyContent.slice(0, 200))

  if (verifyContent.includes('Updated via website_update')) {
    console.log('\n✅ SUCCESS: Website update worked!')
  } else {
    console.log('\n❌ Content not updated yet. Checking pending...')
    const pendingResp = await fetch(`http://localhost:8507/_pending/${updateDeploymentId}/index.html`)
    console.log('Pending content:', (await pendingResp.text()).slice(0, 200))
  }

  // Output values for manual verification
  console.log('\n=== Test Values ===')
  console.log('Address:', address)
  console.log('Username:', username)
  console.log('Contract ID:', contractId)
  console.log('Contract subdomain:', contractSubdomain)
  console.log('Update deployment ID:', updateDeploymentId)
}

async function computeHash(content: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(content)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

main().catch(console.error)
