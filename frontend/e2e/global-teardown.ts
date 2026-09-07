import { existsSync, rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const sleep = (milliseconds: number) => new Promise((resolve) => setTimeout(resolve, milliseconds))

export default async () => {
  const testResults = new URL('../test-results/', import.meta.url)
  const stateDirectory = fileURLToPath(new URL('.e2e-runtime', testResults))
  try {
    await fetch('http://127.0.0.1:4173/__e2e/shutdown', { method: 'POST' })
  } catch {
    // The web server did not start, so no server process can hold its fixture state.
  }
  for (let attempt = 0; existsSync(stateDirectory) && attempt < 50; attempt++) {
    await sleep(100)
  }
  rmSync(fileURLToPath(new URL('.e2e-password', testResults)), { force: true })
  rmSync(stateDirectory, { force: true, recursive: true })
}
