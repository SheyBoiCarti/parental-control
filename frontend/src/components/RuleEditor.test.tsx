import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import RuleEditor from './RuleEditor'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('awaits domain saves, prevents duplicate submission and preserves input after rejection', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ apps: [] }))))
  let rejectSave!: (error: Error) => void
  const save = vi.fn(() => new Promise<void>((_resolve, reject) => { rejectSave = reject }))
  render(<RuleEditor rules={[]} onCreateDomainBlockRule={save}
    onCreateAppBlockRule={vi.fn()} onCreateBandwidthRule={vi.fn()} onDeleteRule={vi.fn()} />)
  fireEvent.click(screen.getByText('Block Domains'))
  const input = screen.getByPlaceholderText('Enter domain (e.g., example.com)') as HTMLInputElement
  fireEvent.change(input, { target: { value: 'example.com' } })
  fireEvent.click(screen.getByRole('button', { name: 'Block' }))
  expect(input.value).toBe('example.com')
  fireEvent.click(screen.getByRole('button', { name: 'Block' }))
  expect(save).toHaveBeenCalledTimes(1)
  await act(async () => { rejectSave(new Error('Firewall unavailable')) })
  expect(screen.getByRole('alert').textContent).toContain('Firewall unavailable')
  expect(input.value).toBe('example.com')
})

it('shows persisted rule validation and enforcement failures', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ apps: [] }))))
  render(<RuleEditor rules={[{
    id: 7,
    device_id: 1,
    rule_type: 'block_domain',
    rule_value: { domain: 'broken rule' },
    is_active: true,
    created_at: null,
    validation_error: 'Invalid legacy rule; edit or remove this rule',
    enforcement: {
      state: 'error',
      last_error: 'Content application failed',
      updated_at: '2026-09-06T00:00:00Z',
    },
  }]} onCreateDomainBlockRule={vi.fn()}
    onCreateAppBlockRule={vi.fn()} onCreateBandwidthRule={vi.fn()} onDeleteRule={vi.fn()} />)

  fireEvent.click(screen.getByText('Block Domains'))
  expect(screen.getByText('Invalid legacy rule; edit or remove this rule')).toBeTruthy()
  expect(screen.getByText('Failed to apply')).toBeTruthy()
})
