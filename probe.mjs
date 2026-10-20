import { execFileSync } from 'node:child_process'
import tls from 'node:tls'

const PS = String.raw`Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | ForEach-Object { [Convert]::ToBase64String($_.RawData) }`

const out = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', PS], { encoding: 'utf8', windowsHide: true })
const b64 = out.split(/\r?\n/).map((s) => s.trim()).filter((s) => /^[A-Za-z0-9+/]{200,}={0,2}$/.test(s))
console.log('system roots:', b64.length)

async function probe(label) {
  try {
    const res = await fetch('https://api.deepseek.com/', { signal: AbortSignal.timeout(15000) })
    console.log(label, '-> HTTP', res.status)
  } catch (e) {
    console.log(label, '-> FAILED:', e.message, '|', e.cause?.code ?? '')
  }
}

await probe('before patch')

const pems = b64.map((x) => '-----BEGIN CERTIFICATE-----\n' + x.match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n')
const base = typeof tls.getCACertificates === 'function' ? tls.getCACertificates('default') : tls.rootCertificates
tls.setDefaultCACertificates([...new Set([...base, ...pems])])
console.log('default CA now:', tls.getCACertificates('default').length)

await probe('after patch')
