import { randomBytes } from 'node:crypto'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from '@playwright/test'

const passwordFile = fileURLToPath(new URL('./test-results/.e2e-password', import.meta.url))
const stateDirectory = fileURLToPath(new URL('./test-results/.e2e-runtime', import.meta.url))
mkdirSync(dirname(passwordFile), { recursive: true })
const e2ePassword = `pc-e2e-${randomBytes(18).toString('base64url')}`
const python = process.platform === 'win32' ? '..\\backend\\.venv\\Scripts\\python.exe' : 'python3'

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
