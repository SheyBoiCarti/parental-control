import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { StrictMode } from 'react'
import { WebSocketProvider, useWebSocket } from './WebSocketContext'

let authenticated = false
vi.mock('./AuthContext', () => ({ useAuth: () => ({ isAuthenticated: authenticated }) }))

class FakeSocket {
  static OPEN = 1
  static instances: FakeSocket[] = []
  readyState = 0
  onopen: (() => void) | null = null
  onclose: ((event: { code: number }) => void) | null = null
  onerror: (() => void) | null = null
  onmessage = null
  send = vi.fn()
  constructor(public url: string) { FakeSocket.instances.push(this) }
  open() { this.readyState = 1; this.onopen?.() }
  close(code = 1000) { this.readyState = 3; this.onclose?.({ code }) }
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
