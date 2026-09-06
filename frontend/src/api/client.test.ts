import { afterEach, expect, it, vi } from 'vitest'

import { ApiError, createBandwidthRule } from './client'


afterEach(() => vi.unstubAllGlobals())


it('preserves stable enforcement failure code and sanitized component error', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
    detail: {
      code: 'ENFORCEMENT_APPLY_FAILED',
      enforcement: {
        state: 'error',
        last_error: 'Bandwidth application failed',
      },
    },
  }), { status: 503 })))

  const failure = await createBandwidthRule(
    'AA:BB:CC:DD:EE:01', 2000, 500,
  ).catch((error: unknown) => error)

  expect(failure).toBeInstanceOf(ApiError)
  if (!(failure instanceof ApiError)) throw new Error('Expected ApiError')
  expect(failure.code).toBe('ENFORCEMENT_APPLY_FAILED')
  expect(failure.message).toBe('Bandwidth application failed')
})
