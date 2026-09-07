import { rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export default () => {
  rmSync(fileURLToPath(new URL('../test-results/.e2e-password', import.meta.url)), { force: true })
}
