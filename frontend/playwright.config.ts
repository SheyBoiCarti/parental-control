import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from '@playwright/test'

const passwordFile = fileURLToPath(new URL('./test-results/.e2e-password', import.meta.url))
const stateDirectory = fileURLToPath(new URL('./test-results/.e2e-runtime', import.meta.url))
mkdirSync(dirname(passwordFile), { recursive: true })
const e2ePassword = `pc-e2e-${randomBytes(18).toString('base64url')}`

function findPython(): string {
  if (process.env.PYTHON) return process.env.PYTHON
  const candidates = process.platform === 'win32'
    ? [
        resolve(fileURLToPath(new URL('../backend/.venv/Scripts/python.exe', import.meta.url))),
        resolve(fileURLToPath(new URL('../backend/venv/Scripts/python.exe', import.meta.url))),
      ]
    : [
        resolve(fileURLToPath(new URL('../backend/venv/bin/python', import.meta.url))),
        resolve(fileURLToPath(new URL('../backend/.venv/bin/python', import.meta.url))),
      ]
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate
  }
  return process.platform === 'win32' ? '..\\backend\\.venv\\Scripts\\python.exe' : 'python3'
}

const python = findPython()

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  retries: 0,
  reporter: 'list',
  globalTeardown: './e2e/global-teardown.ts',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
  },
  projects: [{
    name: 'chromium',
    use: { browserName: 'chromium' },
  }],
  webServer: {
    command: `npm run build && ${python} ../backend/e2e_server.py`,
    url: 'http://127.0.0.1:4173/health',
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      PC_E2E_PASSWORD: e2ePassword,
      PC_E2E_PASSWORD_FILE: passwordFile,
      PC_E2E_DATA_DIR: stateDirectory,
    },
  },
})
