import { expect, test } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

async function login(page: import('@playwright/test').Page, password: string) {
  await page.goto('/login')
  await page.getByLabel('Username').fill('e2e-admin')
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign In' }).click()
  await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible()
}

function testPassword(): string {
  return readFileSync(fileURLToPath(new URL('../test-results/.e2e-password', import.meta.url)), 'utf8')
}

test('serves the production dashboard and authenticates the seeded administrator', async ({ page }) => {
  const password = testPassword()
  const encodedPassword = Buffer.from(password).toString('base64')
  const legacyBasic = `Basic ${Buffer.from(`e2e-admin:${password}`).toString('base64')}`
  const requestUrls: string[] = []
  const requestAuthorization: string[] = []
  page.on('request', (request) => {
    requestUrls.push(request.url())
    requestAuthorization.push(request.headers().authorization || '')
  })
  await login(page, password)
  const markers = [password, encodedPassword, legacyBasic]
  const assertNoCredentialLeak = async () => {
    const storage = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }))
    const serializedStorage = JSON.stringify(storage)
    for (const marker of markers) {
      expect(serializedStorage).not.toContain(marker)
      expect(page.url()).not.toContain(marker)
      expect(requestUrls.join('\n')).not.toContain(marker)
      expect(requestAuthorization.join('\n')).not.toContain(marker)
    }
    expect(requestAuthorization.some((header) => header.toLowerCase().startsWith('basic '))).toBe(false)
  }
  await assertNoCredentialLeak()

  await page.evaluate((value) => localStorage.setItem('auth', value), legacyBasic)
  await page.reload()
  await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible()
  await expect(page).toHaveURL('http://127.0.0.1:4173/')
  await assertNoCredentialLeak()
  const cookie = (await page.context().cookies()).find(({ name }) => name === 'pc_session')
  expect(cookie).toMatchObject({ httpOnly: true, sameSite: 'Strict', path: '/' })

  await page.getByRole('button', { name: 'Logout' }).click()
  await expect(page.getByRole('button', { name: 'Sign In' })).toBeVisible()
  await expect.poll(async () => (await page.request.get('/api/auth/session')).status()).toBe(401)
})

test('serves authenticated deep links with offline desired state and catalog display names', async ({ page }) => {
  await login(page, testPassword())
  await page.goto('/devices/02%3A00%3A00%3A00%3A00%3A10')
  await page.getByRole('button', { name: 'Bandwidth' }).click()
  await expect(page.getByText('Applied', { exact: true })).toBeVisible()

  await page.goto('/devices/02%3A00%3A00%3A00%3A00%3A20')
  await expect(page.getByRole('heading', { name: 'Offline Tablet' })).toBeVisible()
  await expect(page.getByText('Offline', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Stop Monitoring' })).toBeVisible()
  await expect(page.getByRole('option', { name: 'YouTube' })).toHaveAttribute('value', 'youtube')
})

test('keeps the rejected rule input visible with the current apply failure', async ({ page }) => {
  await login(page, testPassword())
  await page.goto('/devices/02%3A00%3A00%3A00%3A00%3A10')
  await page.getByRole('button', { name: 'Block Domains' }).click()
  const domain = page.getByPlaceholder('Enter domain (e.g., example.com)')
  await domain.fill('reject.example')
  await domain.locator('xpath=..').getByRole('button', { name: 'Block', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('Content application failed')
  await expect(domain).toHaveValue('reject.example')
  await page.reload()
  await page.getByRole('button', { name: 'Block Domains' }).click()
  await expect(page.getByText('Failed to apply', { exact: true })).toBeVisible()
})

test('changes password in settings, invalidates previous session, and rejects old credentials', async ({ page }) => {
  const initialPassword = testPassword()
  const newPassword = `${initialPassword}-rotated`
  await login(page, initialPassword)
  await page.goto('/settings')
  await page.getByPlaceholder('Enter current password').fill(initialPassword)
  await page.getByPlaceholder('Enter new password').fill(newPassword)
  await page.getByPlaceholder('Confirm new password').fill(newPassword)
  await page.getByRole('button', { name: 'Change Password' }).click()

  // After password change, session is invalidated and user is redirected to login
  await expect(page.getByRole('button', { name: 'Sign In' })).toBeVisible()

  // Old password must fail
  await page.getByLabel('Username').fill('e2e-admin')
  await page.getByLabel('Password').fill(initialPassword)
  await page.getByRole('button', { name: 'Sign In' }).click()
  await expect(page.getByRole('alert')).toBeVisible()

  // New password must succeed
  await page.getByLabel('Password').fill(newPassword)
  await page.getByRole('button', { name: 'Sign In' }).click()
  await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible()
})
