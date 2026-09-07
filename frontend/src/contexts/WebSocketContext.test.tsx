import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { StrictMode, useEffect } from 'react'
import { WebSocketProvider, useWebSocket } from './WebSocketContext'
import { invalidateSession } from '../api/client'

let authenticated = false
vi.mock('./AuthContext', () => ({ useAuth: () => ({ isAuthenticated: authenticated }) }))
vi.mock('../api/client', () => ({ invalidateSession: vi.fn() }))

class FakeSocket {
  static OPEN = 1
  static instances: FakeSocket[] = []
  readyState = 0
  onopen: (() => void) | null = null
  onclose: ((event: { code: number }) => void) | null = null
  onerror: (() => void) | null = null
  onmessage: (((event: { data: string }) => void) | null) = null
  send = vi.fn()
  constructor(public url: string) { FakeSocket.instances.push(this) }
  open() { this.readyState = 1; this.onopen?.() }
  close(code = 1000) { this.readyState = 3; this.onclose?.({ code }) }
  receive(data: object | string) {
    this.onmessage?.({ data: typeof data === 'string' ? data : JSON.stringify(data) })
  }
}

function Probe() { return <p>{useWebSocket().isConnected ? 'connected' : 'disconnected'}</p> }
beforeEach(() => {
  authenticated = false
  FakeSocket.instances = []
  vi.useFakeTimers()
  vi.spyOn(Math, 'random').mockReturnValue(0.5)
  vi.stubGlobal('WebSocket', FakeSocket)
})
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

it('connects only after authentication and reconnects after an established socket closes', () => {
  const view = render(<WebSocketProvider><Probe /></WebSocketProvider>)
  expect(FakeSocket.instances).toHaveLength(0)
  authenticated = true
  view.rerender(<WebSocketProvider><Probe /></WebSocketProvider>)
  expect(FakeSocket.instances).toHaveLength(1)
  act(() => FakeSocket.instances[0].open())
  expect(screen.getByText('connected')).toBeTruthy()
  act(() => FakeSocket.instances[0].close())
  expect(screen.getByText('disconnected')).toBeTruthy()
  act(() => vi.advanceTimersByTime(1000))
  expect(FakeSocket.instances).toHaveLength(2)
  authenticated = false
  view.rerender(<WebSocketProvider><Probe /></WebSocketProvider>)
  act(() => vi.advanceTimersByTime(120000))
  expect(FakeSocket.instances).toHaveLength(2)
  expect(FakeSocket.instances[1].readyState).toBe(3)
})

it('cleans up StrictMode attempts, ping timers and unmounted reconnects', () => {
  authenticated = true
  const view = render(<StrictMode><WebSocketProvider><Probe /></WebSocketProvider></StrictMode>)
  expect(FakeSocket.instances.filter(socket => socket.readyState !== 3)).toHaveLength(1)
  const socket = FakeSocket.instances[FakeSocket.instances.length - 1]
  act(() => socket.open())
  act(() => vi.advanceTimersByTime(30000))
  expect(socket.send).toHaveBeenCalledTimes(1)
  const count = FakeSocket.instances.length
  view.unmount()
  act(() => vi.advanceTimersByTime(120000))
  expect(FakeSocket.instances).toHaveLength(count)
  expect(vi.getTimerCount()).toBe(0)
})

it('applies exponential backoff on repeated connection failures and resets on success', () => {
  authenticated = true
  render(<WebSocketProvider><Probe /></WebSocketProvider>)
  expect(FakeSocket.instances).toHaveLength(1)

  // First failure (initial delay = 1000ms)
  act(() => FakeSocket.instances[0].close())
  act(() => vi.advanceTimersByTime(999))
  expect(FakeSocket.instances).toHaveLength(1)
  act(() => vi.advanceTimersByTime(1))
  expect(FakeSocket.instances).toHaveLength(2)

  // Second failure (delay doubled to 2000ms)
  act(() => FakeSocket.instances[1].close())
  act(() => vi.advanceTimersByTime(1999))
  expect(FakeSocket.instances).toHaveLength(2)
  act(() => vi.advanceTimersByTime(1))
  expect(FakeSocket.instances).toHaveLength(3)

  // Third succeeds and resets backoff delay to 1000ms
  act(() => FakeSocket.instances[2].open())
  expect(screen.getByText('connected')).toBeTruthy()
  act(() => FakeSocket.instances[2].close())

  // Next reconnect is back to 1000ms
  act(() => vi.advanceTimersByTime(1000))
  expect(FakeSocket.instances).toHaveLength(4)
})

it('preserves subscriptions across socket reconnection', () => {
  authenticated = true
  const received: unknown[] = []
  function SubProbe() {
    const { subscribe } = useWebSocket()
    useEffect(() => {
      return subscribe('device_update', (data) => { received.push(data) })
    }, [subscribe])
    return null
  }
  render(<WebSocketProvider><SubProbe /></WebSocketProvider>)
  expect(FakeSocket.instances).toHaveLength(1)
  act(() => FakeSocket.instances[0].open())
  act(() => FakeSocket.instances[0].receive({ type: 'device_update', data: { mac: '02:00:00:00:00:10' } }))
  expect(received).toEqual([{ mac: '02:00:00:00:00:10' }])

  // Reconnect
  act(() => FakeSocket.instances[0].close())
  act(() => vi.advanceTimersByTime(1000))
  expect(FakeSocket.instances).toHaveLength(2)
  act(() => FakeSocket.instances[1].open())
  act(() => FakeSocket.instances[1].receive({ type: 'device_update', data: { mac: '02:00:00:00:00:20' } }))
  expect(received).toEqual([
    { mac: '02:00:00:00:00:10' },
    { mac: '02:00:00:00:00:20' },
  ])
})

it('stops reconnection and invalidates session on authentication failure code 4401 or 1008', () => {
  authenticated = true
  render(<WebSocketProvider><Probe /></WebSocketProvider>)
  expect(FakeSocket.instances).toHaveLength(1)
  act(() => FakeSocket.instances[0].close(4401))
  expect(invalidateSession).toHaveBeenCalled()
  act(() => vi.advanceTimersByTime(120000))
  expect(FakeSocket.instances).toHaveLength(1)
})
