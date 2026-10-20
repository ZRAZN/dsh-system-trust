/**
 * dsh-system-trust — make DeepSeek Harness trust the OS certificate store.
 *
 * Problem: Node only trusts its bundled roots. HTTPS-inspecting software
 * (Kaspersky, ESET, Bitdefender, Zscaler, corporate proxies…) replaces the
 * server certificate with one signed by its own root, so every TLS request
 * fails with a certificate error (DSH shows "request failed (502)").
 *
 * Fix: probe a known endpoint with the strict Node trust store. If the probe
 * fails, read the OS root store and append it to Node's default CA list
 * (`tls.setDefaultCACertificates`), then probe again. If the first probe
 * already succeeds, nothing is changed — trust is not widened needlessly.
 */
import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import tls from 'node:tls'

export const name = 'dsh-system-trust'
export const inject = []

const PROBE_HOST = 'api.deepseek.com'
const PROBE_TIMEOUT_MS = 8000

const STATUS_FILE = join(homedir(), '.dsh', 'system-trust-status.json')

function writeStatus(data) {
  try {
    mkdirSync(join(homedir(), '.dsh'), { recursive: true })
    writeFileSync(STATUS_FILE, JSON.stringify({ at: new Date().toISOString(), ...data }, null, 2))
  } catch {
    // best effort only
  }
}

const PS_QUERY = String.raw`Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | ForEach-Object { [Convert]::ToBase64String($_.RawData) }`

function pemFromBase64(b64) {
  const body = b64.match(/.{1,64}/g).join('\n')
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`
}

function pemBlocks(text) {
  const blocks = []
  const re = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g
  for (const match of text.matchAll(re)) blocks.push(match[0] + '\n')
  return blocks
}

/** Read every root CA from the OS trust store, as PEM strings. */
function readSystemRoots(logger) {
  if (process.platform === 'win32') {
    const out = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', PS_QUERY], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 20000,
    })
    const b64 = out
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => /^[A-Za-z0-9+/]{200,}={0,2}$/.test(line))
    return b64.map(pemFromBase64)
  }
  if (process.platform === 'darwin') {
    const out = execFileSync('security', ['find-certificate', '-a', '-p', '/Library/Keychains/System.keychain'], {
      encoding: 'utf8',
      timeout: 20000,
    })
    return pemBlocks(out)
  }
  const candidates = [
    '/etc/ssl/certs/ca-certificates.crt',
    '/etc/pki/tls/certs/ca-bundle.crt',
    '/etc/ssl/ca-bundle.pem',
  ]
  for (const file of candidates) {
    try {
      return pemBlocks(readFileSync(file, 'utf8'))
    } catch {
      // try the next location
    }
  }
  logger?.warn?.('[system-trust] no system CA bundle found')
  return []
}

function probeStrict(host) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port: 443, servername: host, rejectUnauthorized: true, timeout: PROBE_TIMEOUT_MS },
      () => {
        socket.end()
        resolve(true)
      },
    )
    socket.once('timeout', () => {
      socket.destroy()
      reject(new Error(`TLS probe timed out after ${PROBE_TIMEOUT_MS}ms`))
    })
    socket.once('error', (error) => reject(error))
  })
}

function defaultCAs() {
  if (typeof tls.getCACertificates === 'function') {
    try {
      return tls.getCACertificates('default')
    } catch {
      // fall through
    }
  }
  return tls.rootCertificates
}

function installExtraRoots(pems) {
  if (typeof tls.setDefaultCACertificates === 'function') {
    const merged = [...new Set([...defaultCAs(), ...pems])]
    tls.setDefaultCACertificates(merged)
    return merged.length
  }
  // Fallback for Node < 24: inject into every secure context created later.
  const original = tls.createSecureContext
  tls.createSecureContext = function createSecureContext(options = {}) {
    const ca = options.ca === undefined ? pems : Array.isArray(options.ca) ? [...options.ca, ...pems] : [options.ca, ...pems]
    return original({ ...options, ca })
  }
  return defaultCAs().length + pems.length
}

let everInstalled = false

async function main(logger) {
  try {
    await probeStrict(PROBE_HOST)
    logger?.info?.(`[system-trust] ${PROBE_HOST} TLS trusted with Node default roots — no change needed`)
    if (!everInstalled) writeStatus({ ok: true, action: 'none', host: PROBE_HOST })
    return
  } catch (error) {
    logger?.warn?.(`[system-trust] strict TLS probe failed (${error.message}) — installing OS root CA store`)
  }

  let roots = []
  try {
    roots = readSystemRoots(logger)
  } catch (error) {
    logger?.warn?.(`[system-trust] failed to read the OS root store: ${error.message}`)
  }
  if (roots.length === 0) {
    logger?.warn?.('[system-trust] no OS roots available; TLS trust unchanged')
    writeStatus({ ok: false, action: 'none', error: 'no OS roots available' })
    return
  }

  everInstalled = true
  const total = installExtraRoots(roots)
  logger?.info?.(`[system-trust] added ${roots.length} OS root CA(s); default trust store now has ${total} CA(s)`)

  try {
    await probeStrict(PROBE_HOST)
    logger?.info?.(`[system-trust] ${PROBE_HOST} is trusted after adding the OS roots`)
    writeStatus({ ok: true, action: 'installed', roots: roots.length, total, host: PROBE_HOST })
  } catch (error) {
    logger?.warn?.(`[system-trust] ${PROBE_HOST} still fails after adding the OS roots: ${error.message}`)
    writeStatus({ ok: false, action: 'installed', roots: roots.length, total, error: error.message })
  }
}

export function apply(ctx) {
  const logger = ctx?.logger ?? console
  void main(logger).catch((error) => logger?.warn?.(`[system-trust] unexpected failure: ${error?.message ?? error}`))

  const timer = setInterval(() => {
    void main(logger).catch((error) => logger?.warn?.(`[system-trust] periodic check failed: ${error?.message ?? error}`))
  }, 5 * 60 * 1000)
  ctx?.effect?.(() => () => clearInterval(timer), 'system-trust: periodic TLS check')
}
