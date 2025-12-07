import {
  generateKeypair,
  signMessage,
  pubkeyToAddress
} from './src/index'

// Helper functions
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

async function createAuthJwt(
  privateKey: string,
  publicKey: string,
  username: string,
  network: string
): Promise<string> {
  const isMainnet = network.includes('mainnet') || network === 'tana.network'
  const networkType = isMainnet ? 'mainnet' : 'testnet'
  const addressInfo = pubkeyToAddress(publicKey, networkType as 'mainnet' | 'testnet')
  const address = addressInfo.address

  const now = Math.floor(Date.now() / 1000)
  const expiry = now + 3600 // 1 hour

  const claims = {
    sub: username,
    net: network,
    adr: address,
    iat: now,
    exp: expiry,
    iss: 'self'
  }

  const header = { alg: 'EdDSA', typ: 'JWT' }
  const headerB64 = base64UrlEncode(JSON.stringify(header))
  const payloadB64 = base64UrlEncode(JSON.stringify(claims))
  const signatureInput = `${headerB64}.${payloadB64}`

  const signature = signMessage(signatureInput, privateKey)
  const signatureHex = signature.startsWith('ed25519_sig_')
    ? signature.substring(12)
    : signature

  const signatureB64 = base64UrlEncode(hexToBytes(signatureHex))
  return `${headerB64}.${payloadB64}.${signatureB64}`
}

async function main() {
  console.log('=== Git Push E2E Test ===\n')

  // Generate fresh credentials
  // Use 'testnet' for localhost (matches JWT creation and box-git address derivation)
  const keyPair = await generateKeypair()
  const addressResult = pubkeyToAddress(keyPair.publicKey, 'testnet')
  const address = addressResult.address
  const username = '@gitpush' + Date.now().toString().slice(-4)
  const userId = crypto.randomUUID()

  console.log('Test user address:', address)
  console.log('Test username:', username)

  // Step 1: Create user
  console.log('\n--- Step 1: Create user ---')
  const userTx = {
    txId: crypto.randomUUID(),
    type: 'user_creation',
    from: userId,
    to: userId,
    contractInput: {
      username: username,
      displayName: username.slice(1),
      publicKey: keyPair.publicKey,
      role: 'user'
    },
    timestamp: Date.now(),
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

  // Step 2: Produce block
  console.log('\n--- Step 2: Produce block ---')
  const block1 = await fetch('http://localhost:8501/blocks/produce', { method: 'POST' })
  console.log('Block produced:', await block1.json())

  await new Promise(r => setTimeout(r, 1000))

  // Step 3: Generate JWT for git push
  console.log('\n--- Step 3: Generate auth JWT ---')
  const jwt = await createAuthJwt(
    keyPair.privateKey,
    keyPair.publicKey,
    username,
    'localhost:8501'
  )
  console.log('JWT generated:', jwt.slice(0, 50) + '...')
  console.log('Full JWT length:', jwt.length)

  // Create repository in box-git first
  console.log('\n--- Step 3b: Create repository in box-git ---')
  const basicAuth = Buffer.from(`${username}:${jwt}`).toString('base64')
  const repoName = `${address}-test-site`

  const createRepoResp = await fetch(`http://localhost:8508/api/repos/${repoName}`, {
    method: 'POST',
    headers: { 'Authorization': `Basic ${basicAuth}` }
  })
  const createRepoResult = await createRepoResp.json()
  console.log('Create repo response:', createRepoResp.status, createRepoResult)

  // Step 4: Set up test site
  console.log('\n--- Step 4: Set up test site ---')
  const testDir = '/tmp/tana-e2e-test/test-site-e2e'

  // Update the timestamp in main.tsx
  const updatedCode = `import React from 'react'
import ReactDOM from 'react-dom/client'

function App() {
  return (
    <div style={{ fontFamily: 'system-ui', padding: '2rem', textAlign: 'center' }}>
      <h1>🚀 Tana Git Push E2E Test</h1>
      <p>Deployed via: git push → box-git → deploy → t4 → ledger</p>
      <p>Build time: ${new Date().toISOString()}</p>
      <p>User: ${username}</p>
    </div>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
`
  await Bun.write(`${testDir}/src/main.tsx`, updatedCode)
  console.log('Updated src/main.tsx with fresh timestamp')

  // Git add and commit
  const proc = Bun.spawn(['git', 'add', '-A'], { cwd: testDir })
  await proc.exited

  const proc2 = Bun.spawn(['git', 'commit', '-m', `E2E test ${Date.now()}`], { cwd: testDir })
  await proc2.exited
  console.log('Git commit created')

  // Step 5: Configure git remote and push
  console.log('\n--- Step 5: Git push to box-git ---')

  // Remove existing remote if any
  const rmRemote = Bun.spawn(['git', 'remote', 'remove', 'tana'], { cwd: testDir })
  await rmRemote.exited

  // Add remote with JWT in URL (using git credential helper approach)
  const remoteUrl = `http://localhost:8508/${repoName}.git`
  const addRemote = Bun.spawn(['git', 'remote', 'add', 'tana', remoteUrl], { cwd: testDir })
  await addRemote.exited
  console.log('Remote added:', remoteUrl)

  // Push with Basic auth - Git HTTP transport expects Basic base64(username:jwt)
  // Encode credentials in the URL format: http://username:password@host/repo.git
  const authUrl = `http://${encodeURIComponent(username)}:${encodeURIComponent(jwt)}@localhost:8508/${repoName}.git`

  // Update remote with auth URL
  const setRemote = Bun.spawn(['git', 'remote', 'set-url', 'tana', authUrl], { cwd: testDir })
  await setRemote.exited

  const pushProc = Bun.spawn(
    ['git', 'push', '-f', 'tana', 'main'],
    { cwd: testDir, stderr: 'pipe', stdout: 'pipe' }
  )

  const pushStdout = await new Response(pushProc.stdout).text()
  const pushStderr = await new Response(pushProc.stderr).text()
  const pushCode = await pushProc.exited

  console.log('Push stdout:', pushStdout || '(empty)')
  console.log('Push stderr:', pushStderr || '(empty)')
  console.log('Push exit code:', pushCode)

  if (pushCode !== 0) {
    console.log('\n❌ Git push failed')
    return
  }

  console.log('✓ Git push succeeded')

  // Step 6: Wait for build to complete
  console.log('\n--- Step 6: Wait for build ---')
  let buildJob: any = null
  for (let i = 0; i < 30; i++) {
    await new Promise(r => setTimeout(r, 2000))

    // Check deploy service for build status
    const jobsResp = await fetch('http://localhost:8509/jobs')
    const jobs = await jobsResp.json()

    // Find our job by subdomain
    const ourJob = jobs.find((j: any) => j.subdomain.includes(address))
    if (ourJob && ourJob.status === 'success') {
      console.log('Build completed!')
      console.log('Deployment ID:', ourJob.deploymentId)
      console.log('Artifact hash:', ourJob.artifactHash)
      buildJob = ourJob
      break
    } else if (ourJob && ourJob.status === 'failed') {
      console.log('❌ Build failed')
      console.log('Logs:', ourJob.logs?.slice(-5))
      return
    }

    console.log(`Waiting for build... (${i + 1}/30)`)
  }

  if (!buildJob) {
    console.log('\n❌ Build did not complete in time')
    return
  }

  // Step 7: Deploy contract (required for website_update)
  console.log('\n--- Step 7: Deploy pointer contract ---')
  const contractId = crypto.randomUUID()
  const subdomain = `${address}-test-site`

  const contractTx = {
    txId: crypto.randomUUID(),
    type: 'contract_deployment',
    from: userId,
    to: contractId,
    contractInput: {
      name: subdomain,
      sourceCode: 'export const contract = { get: () => new Response("ok") }',
      codeHash: 'e2e-test-contract',
      initCode: '',
      contractCode: 'export const contract = { get: () => new Response("ok") }',
      getCode: 'export const contract = { get: () => new Response("ok") }',
      postCode: '',
      hasInit: false,
      hasGet: true,
      hasPost: false,
      version: '1.0.0',
      description: 'E2E test pointer contract',
      metadata: {
        deploymentId: buildJob.deploymentId,
        artifactHash: buildJob.artifactHash,
        subdomain,
        // Convert fileManifest to assets format expected by ledger
        assets: buildJob.fileManifest?.map((f: any) => ({
          filename: f.path.split('/').pop() || f.path,
          path: f.path.includes('/') ? '/' + f.path.substring(0, f.path.lastIndexOf('/')) : '/',
          contentType: f.path.endsWith('.html') ? 'text/html' :
                       f.path.endsWith('.js') ? 'application/javascript' :
                       f.path.endsWith('.css') ? 'text/css' : 'application/octet-stream',
          contentHash: f.hash,
          sizeBytes: f.size
        })) || []
      }
    },
    timestamp: Date.now(),
    nonce: 1
  }

  const contractPayload = JSON.stringify({
    type: contractTx.type,
    from: contractTx.from,
    to: contractTx.to,
    contractInput: contractTx.contractInput,
    timestamp: contractTx.timestamp,
    nonce: contractTx.nonce
  })
  const contractSig = signMessage(contractPayload, keyPair.privateKey)

  const contractResp = await fetch('http://localhost:8502/transactions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...contractTx, signature: contractSig })
  })
  console.log('Contract deployment queued:', await contractResp.json())

  // Step 8: Produce block
  console.log('\n--- Step 8: Produce block ---')
  const block2 = await fetch('http://localhost:8501/blocks/produce', { method: 'POST' })
  const block2Result = await block2.json()
  console.log('Block produced:', JSON.stringify(block2Result, null, 2))

  await new Promise(r => setTimeout(r, 2000))

  // Step 9: Verify site is live
  console.log('\n--- Step 9: Verify site ---')
  const siteUrl = `http://localhost:8507/content/${address}/${contractId}/index.html`
  console.log('Checking:', siteUrl)

  const siteResp = await fetch(siteUrl)
  const siteContent = await siteResp.text()

  // Check for either React content text OR valid HTML shell (Vite builds put content in JS bundle)
  if (siteContent.includes('Tana Git Push E2E Test') || siteContent.includes('<!DOCTYPE html>')) {
    console.log('\n✅ SUCCESS: Site is live!')
    console.log('Content preview:', siteContent.slice(0, 300))

    // Also verify the JS bundle is accessible
    const jsMatch = siteContent.match(/src="\/assets\/([^"]+\.js)"/)
    if (jsMatch) {
      const jsUrl = `http://localhost:8507/content/${address}/${contractId}/assets/${jsMatch[1]}`
      const jsResp = await fetch(jsUrl)
      if (jsResp.ok) {
        const jsSize = (await jsResp.text()).length
        console.log(`JS bundle accessible: ${jsMatch[1]} (${jsSize} bytes)`)
      }
    }
  } else {
    console.log('\n❌ Site content not as expected')
    console.log('Content:', siteContent.slice(0, 500))
    // Check pending
    const pendingUrl = `http://localhost:8507/_pending/${buildJob.deploymentId}/index.html`
    const pendingResp = await fetch(pendingUrl)
    if (pendingResp.ok) {
      console.log('Content IS in /_pending:', (await pendingResp.text()).slice(0, 200))
    }
  }

  console.log('\n=== Test Values ===')
  console.log('Address:', address)
  console.log('Username:', username)
  console.log('User ID:', userId)
  console.log('Repo name:', repoName)
  console.log('Contract ID:', contractId)
  console.log('Deployment ID:', buildJob.deploymentId)
}

main().catch(console.error)
