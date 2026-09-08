import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import DeviceDetail from './DeviceDetail'

const client = vi.hoisted(() => ({
  createDomainBlockRule: vi.fn(),
  getDevice: vi.fn(),
  getDeviceRules: vi.fn(),
  getDeviceBandwidthStats: vi.fn(),
  getDeviceAccessStats: vi.fn(),
}))

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return { ...actual, ...client }
})

afterEach(() => { cleanup(); vi.clearAllMocks(); vi.unstubAllGlobals() })

it('refreshes the persisted failed rule after an apply rejection', async () => {
  const device = {
    id: 1, mac_address: 'AA:BB:CC:DD:EE:01', friendly_name: 'Tablet',
    is_online: true, is_monitored: false, is_blocked: false, ip_address: '192.0.2.1',
    hostname: null, vendor: null, first_seen: null, last_seen: null,
  }
  const failedRule = {
    id: 5, device_id: 1, rule_type: 'block_domain', rule_value: { domain: 'blocked.example' },
    is_active: true, created_at: null, validation_error: null,
    enforcement: { state: 'error', last_error: 'Content application failed', updated_at: '2026-09-06T00:00:00Z' },
  }
  client.getDevice.mockResolvedValue(device)
  client.getDeviceRules.mockResolvedValueOnce({ rules: [], total: 0 }).mockResolvedValue({ rules: [failedRule], total: 1 })
  client.getDeviceBandwidthStats.mockResolvedValue(null)
  client.getDeviceAccessStats.mockResolvedValue({ logs: [] })
  client.createDomainBlockRule.mockRejectedValue(new Error('Content application failed'))
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ apps: [] }))))

  render(<MemoryRouter initialEntries={['/devices/AA%3ABB%3ACC%3ADD%3AEE%3A01']}>
    <Routes><Route path="/devices/:mac" element={<DeviceDetail />} /></Routes>
  </MemoryRouter>)

  await screen.findByText('Tablet')
  fireEvent.click(screen.getByText('Block Domains'))
  const input = screen.getByPlaceholderText('Enter domain (e.g., example.com)')
  fireEvent.change(input, { target: { value: 'blocked.example' } })
  fireEvent.click(input.parentElement!.querySelector('button')!)

  await screen.findByRole('alert')
  expect(await screen.findByText('Failed to apply')).toBeTruthy()
})
