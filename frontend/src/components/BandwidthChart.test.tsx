import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import BandwidthChart from './BandwidthChart'

describe('BandwidthChart', () => {
  it('explains when no bandwidth samples are available', () => {
    render(<BandwidthChart data={[]} />)

    expect(screen.getByText('No bandwidth data available')).toBeTruthy()
  })
})
