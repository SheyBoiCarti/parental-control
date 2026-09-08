import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import Devices from './Devices'

const sockets = vi.hoisted(() => new Map<string, (data: unknown) => void>())
vi.mock('../contexts/WebSocketContext', () => ({
  useWebSocket: () => ({ subscribe }),
}))
function subscribe(type: string, callback: (data: unknown) => void) {
  sockets.set(type, callback)
  return () => sockets.delete(type)
}
afterEach(() => { cleanup(); sockets.clear(); vi.unstubAllGlobals() })

it('adds an unknown device from a single update while retaining saved offline devices', async () => {
  const saved = { id: 1, mac_address: 'AA:BB:CC:DD:EE:01', friendly_name: 'Offline tablet',
    is_online: false, is_monitored: false, is_blocked: false, ip_address: '192.0.2.1',
    hostname: null, vendor: null, first_seen: null, last_seen: null }
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ devices: [saved], total: 1 }))))
  render(<MemoryRouter><Devices /></MemoryRouter>)
  await screen.findByText('Offline tablet')
  act(() => sockets.get('device_update')?.({ ...saved, id: 2,
    mac_address: 'AA:BB:CC:DD:EE:02', friendly_name: 'New phone', is_online: true }))
  expect(screen.getByText('Offline tablet')).toBeTruthy()
  expect(screen.getByText('New phone')).toBeTruthy()
})

it('shows desired blocking as pending instead of claiming the device is blocked', async () => {
  const timestamp = '2026-09-06T00:00:00Z'
  const pending = { state: 'pending', last_error: null, updated_at: timestamp }
  const inactive = { state: 'inactive', last_error: null, updated_at: timestamp }
  const saved = {
    id: 3,
    mac_address: 'AA:BB:CC:DD:EE:03',
    friendly_name: 'Offline console',
    is_online: false,
    is_monitored: false,
    is_blocked: true,
    ip_address: null,
    hostname: null,
    vendor: null,
    first_seen: null,
    last_seen: null,
    enforcement: {
      ...pending,
      components: {
        interception: pending,
        blocking: pending,
        content: inactive,
        bandwidth: inactive,
      },
    },
  }
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
    new Response(JSON.stringify({ devices: [saved], total: 1 })),
  ))

  render(<MemoryRouter><Devices /></MemoryRouter>)

  await screen.findByText('Block pending')
  expect(screen.queryByText('Blocked', { selector: 'span' })).toBeNull()
})

it('keeps a failed removal visible after desired blocking is cleared', async () => {
  const timestamp = '2026-09-06T00:00:00Z'
  const failed = { state: 'error', last_error: 'Block removal failed', updated_at: timestamp }
  const inactive = { state: 'inactive', last_error: null, updated_at: timestamp }
  const device = {
    id: 4, mac_address: 'AA:BB:CC:DD:EE:04', friendly_name: 'Failed cleanup',
    is_online: true, is_monitored: false, is_blocked: false, ip_address: '192.0.2.4',
    hostname: null, vendor: null, first_seen: null, last_seen: null,
    enforcement: { ...failed, components: { interception: failed, blocking: failed, content: inactive, bandwidth: inactive } },
  }
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ devices: [device], total: 1 }))))

  render(<MemoryRouter><Devices /></MemoryRouter>)

  await screen.findByText('Block failed')
})

it('reloads persisted cleanup failure after unblock returns an error', async () => {
  const timestamp = '2026-09-06T00:00:00Z'
  const applied = { state: 'applied', last_error: null, updated_at: timestamp }
  const failed = { state: 'error', last_error: 'Block removal failed', updated_at: timestamp }
  const inactive = { state: 'inactive', last_error: null, updated_at: timestamp }
  const initiallyBlocked = {
    id: 5, mac_address: 'AA:BB:CC:DD:EE:05', friendly_name: 'Unblock failure',
    is_online: true, is_monitored: false, is_blocked: true, ip_address: '192.0.2.5',
    hostname: null, vendor: null, first_seen: null, last_seen: null,
    enforcement: { ...applied, components: { interception: applied, blocking: applied, content: inactive, bandwidth: inactive } },
  }
  const persistedFailure = {
    ...initiallyBlocked, is_blocked: false,
    enforcement: { ...failed, components: { interception: failed, blocking: failed, content: inactive, bandwidth: inactive } },
  }
  vi.stubGlobal('fetch', vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({ devices: [initiallyBlocked], total: 1 })))
    .mockResolvedValueOnce(new Response(JSON.stringify({ detail: 'Block removal failed' }), { status: 503 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ devices: [persistedFailure], total: 1 }))))

  render(<MemoryRouter><Devices /></MemoryRouter>)
  await screen.findByText('Unblock failure')
  fireEvent.click(screen.getByTitle('Unblock device'))

  expect(await screen.findByText('Block failed')).toBeTruthy()
})
