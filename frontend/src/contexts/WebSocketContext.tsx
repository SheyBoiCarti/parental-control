import { createContext, useContext, useEffect, useState, useCallback, useRef, ReactNode } from 'react'
import { useAuth } from './AuthContext'
import { invalidateSession } from '../api/client'

interface WSMessage { type: string; data: unknown; timestamp: string }
interface WebSocketContextType {
  isConnected: boolean
  lastMessage: WSMessage | null
  send: (message: object) => void
  subscribe: (type: string, callback: (data: unknown) => void) => () => void
}
const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined)

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth()
  const socket = useRef<WebSocket | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null)
  const subscribers = useRef(new Map<string, Set<(data: unknown) => void>>())

  useEffect(() => {
    setIsConnected(false)
    setLastMessage(null)
    if (!isAuthenticated) return
    let disposed = false
    let reconnect: number | undefined
    let ping: number | undefined
    let delay = 1000
    const stopTimers = () => { window.clearTimeout(reconnect); window.clearInterval(ping) }
    const connect = () => {
      if (disposed) return
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const ws = new WebSocket(`${protocol}//${window.location.host}/ws`)
      socket.current = ws
      ws.onopen = () => {
        if (disposed || socket.current !== ws) return
        delay = 1000
        setIsConnected(true)
        ping = window.setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ping' }))
        }, 30000)
      }
      ws.onmessage = event => {
        if (disposed || socket.current !== ws) return
        try {
          const message: WSMessage = JSON.parse(event.data)
          if (typeof message.type !== 'string') return
          setLastMessage(message)
          subscribers.current.get(message.type)?.forEach(callback => callback(message.data))
          subscribers.current.get('all')?.forEach(callback => callback(message))
        } catch { /* Ignore malformed telemetry; subsequent messages remain usable. */ }
      }
      ws.onerror = () => ws.close()
      ws.onclose = event => {
        stopTimers()
        if (disposed || socket.current !== ws) return
        socket.current = null
        setIsConnected(false)
        if (event.code === 1008 || event.code === 4401) {
          disposed = true
          invalidateSession()
          return
        }
        const wait = Math.min(30000, delay * (0.9 + Math.random() * 0.2))
        delay = Math.min(30000, delay * 2)
        reconnect = window.setTimeout(connect, wait)
      }
    }
    connect()
    return () => {
      disposed = true
      stopTimers()
      const ws = socket.current
      socket.current = null
      if (ws) {
        ws.onopen = ws.onmessage = ws.onclose = ws.onerror = null
        ws.close()
      }
    }
  }, [isAuthenticated])

  const send = useCallback((message: object) => {
    if (socket.current?.readyState === WebSocket.OPEN) socket.current.send(JSON.stringify(message))
  }, [])
  const subscribe = useCallback((type: string, callback: (data: unknown) => void) => {
    if (!subscribers.current.has(type)) subscribers.current.set(type, new Set())
    subscribers.current.get(type)!.add(callback)
    return () => {
      const entries = subscribers.current.get(type)
      entries?.delete(callback)
      if (entries?.size === 0) subscribers.current.delete(type)
    }
  }, [])
  return <WebSocketContext.Provider value={{ isConnected, lastMessage, send, subscribe }}>{children}</WebSocketContext.Provider>
}

export function useWebSocket() {
  const value = useContext(WebSocketContext)
  if (!value) throw new Error('useWebSocket must be used within a WebSocketProvider')
  return value
}
