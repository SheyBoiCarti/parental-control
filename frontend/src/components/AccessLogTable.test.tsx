import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { AccessLogTable } from './AccessLogTable'

describe('AccessLogTable', () => {
  it('shows the protocol, enforced rule, and verdict reason', () => {
    render(<AccessLogTable logs={[{
      timestamp: '2026-09-06T10:00:00Z',
      domain: 'blocked.example',
      action: 'blocked',
      app_name: 'Example App',
      rule_id: 42,
      protocol: 'tls_sni',
      reason: 'domain_rule',
    }]} />)

    expect(screen.getByText('TLS SNI')).toBeTruthy()
    expect(screen.getByText('domain rule')).toBeTruthy()
    expect(screen.getByText('#42')).toBeTruthy()
  })
})
