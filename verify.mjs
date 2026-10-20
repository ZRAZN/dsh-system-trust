import { execFileSync } from 'node:child_process'
import tls from 'node:tls'

const PS = String.raw`Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | ForEach-Object { [Convert]::ToBase64String($_.RawData) }`

function pemFromBase64(b64) {
  return '-----BEGIN CERTIFICATE-----\n' + b64.match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n'
}

function probe() {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: 'api.deepseek.com', port: 443, servername: 'api.deepseek.com', rejectUnauthorized: true, timeout: 8000 },
      () => {
        socket.end()
        resolve(true)
      },
    )
    socket.once('timeout', () => reject(new Error('timeout')))
    socket.once('error', (error) => reject(error))
  })
}

async function attempt(label) {
  try {
    await probe()
    console.log(label, '-> OK')
  } catch (error) {
    console.log(label, '-> FAIL:', error.code ?? error.message)
  }
}

tls.setDefaultCACertificates([])
await attempt('empty trust store')

const out = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', PS], { encoding: 'utf8', windowsHide: true })
const pems = out
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter((line) => /^[A-Za-z0-9+/]{200,}={0,2}$/.test(line))
  .map(pemFromBase64)
console.log('system roots read:', pems.length)

tls.setDefaultCACertificates(pems)
await attempt('after installing OS roots')
