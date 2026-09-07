import { render, screen } from '@testing-library/react'
import { expect, it } from 'vitest'

import CoverageNotice from './CoverageNotice'


it('states the supported filtering contract and material bypasses', () => {
  render(<CoverageNotice />)

  expect(screen.getByText(/IPv4 devices on the same local network/)).toBeTruthy()
  expect(screen.getByText(/DNS over UDP or TCP port 53/)).toBeTruthy()
  expect(screen.getByText(/IPv6, encrypted DNS, encrypted ClientHello, VPNs/)).toBeTruthy()
})
