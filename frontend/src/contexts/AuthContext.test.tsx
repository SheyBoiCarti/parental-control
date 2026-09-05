import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useState } from 'react'
import { AuthProvider, useAuth } from './AuthContext'

function Probe() {
  const auth = useAuth()
  const [error, setError] = useState('')
  return <>
    <p>{auth.isLoading ? 'loading' : auth.isAuthenticated ? 'authenticated' : 'anonymous'}</p>
    <p>{error}</p>
    <button onClick={() => { auth.login('admin', 'secret-password').catch(e => setError(e.message)) }}>Login</button>
    <button onClick={() => { void auth.logout() }}>Logout</button>
  </>
}

const response = (status: number, body: object) => new Response(JSON.stringify(body), { status })
beforeEach(() => { localStorage.clear(); vi.stubGlobal('fetch', vi.fn()) })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('confirmed browser sessions', () => {
  it('removes legacy credentials and rejects stale storage', async () => {
    localStorage.setItem('auth', JSON.stringify({ username: 'admin', password: 'old' }))
    vi.mocked(fetch).mockResolvedValue(response(401, { detail: 'Unauthorized' }))
    render(<AuthProvider><Probe /></AuthProvider>)
    await screen.findByText('anonymous')
    expect(localStorage.getItem('auth')).toBeNull()
    expect(fetch).toHaveBeenCalledWith('/api/auth/session', expect.anything())
  })

  it.each([500, 503])('never authenticates on HTTP %s', async (status) => {
    vi.mocked(fetch).mockResolvedValueOnce(response(401, {})).mockResolvedValue(response(status, { detail: 'Service unavailable' }))
    render(<AuthProvider><Probe /></AuthProvider>)
    await screen.findByText('anonymous')
    fireEvent.click(screen.getByText('Login'))
    await screen.findByText('Service unavailable')
    expect(screen.queryByText('authenticated')).toBeNull()
    expect(localStorage.length).toBe(0)
  })

  it('confirms login and never stores credentials or sends Basic headers', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(response(401, {})).mockResolvedValue(response(200, {
      username: 'admin', csrf_token: 'csrf-example', expires_at: new Date(Date.now() + 3600000).toISOString(),
    }))
    render(<AuthProvider><Probe /></AuthProvider>)
    await screen.findByText('anonymous')
    fireEvent.click(screen.getByText('Login'))
    await screen.findByText('authenticated')
    expect(localStorage.length).toBe(0)
    await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/auth/login', expect.objectContaining({ credentials: 'same-origin' })))
    const headers = vi.mocked(fetch).mock.calls[1][1]?.headers as Record<string, string>
    expect(headers.Authorization).toBeUndefined()
  })
})
