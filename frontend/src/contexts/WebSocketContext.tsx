import { createContext, useContext, useEffect, useState, useCallback, ReactNode } from 'react'

interface WSMessage {
  type: string
  data: unknown
  timestamp: string
}

interface WebSocketContextType {
  isConnected: boolean
  lastMessage: WSMessage | null
  send: (message: object) => void
  subscribe: (type: string, callback: (data: unknown) => void) => () => void
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined)

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const [socket, setSocket] = useState<WebSocket | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null)
  const [subscribers, setSubscribers] = useState<Map<string, Set<(data: unknown) => void>>>(new Map())

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/ws`

    let ws: WebSocket | null = null
    let reconnectTimeout: number | null = null

    const connect = () => {
      ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        console.log('WebSocket connected')
        setIsConnected(true)
        setSocket(ws)

        // Send ping periodically
        const pingInterval = setInterval(() => {
          if (ws?.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }))
          }
        }, 30000)

        ws!.onclose = () => {
          clearInterval(pingInterval)
        }
      }

      ws.onmessage = (event) => {
        try {
          const message: WSMessage = JSON.parse(event.data)
          setLastMessage(message)

          // Notify subscribers
          const typeSubscribers = subscribers.get(message.type)
          if (typeSubscribers) {
            typeSubscribers.forEach((callback) => callback(message.data))
          }

          // Also notify 'all' subscribers
          const allSubscribers = subscribers.get('all')
          if (allSubscribers) {
            allSubscribers.forEach((callback) => callback(message))
          }
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e)
        }
      }

      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
      }

      ws.onclose = () => {
        console.log('WebSocket disconnected')
        setIsConnected(false)
        setSocket(null)

        // Reconnect after 5 seconds
        reconnectTimeout = window.setTimeout(() => {
          console.log('Attempting to reconnect...')
          connect()
        }, 5000)
      }
    }

    connect()

    return () => {
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout)
      }
      if (ws) {
        ws.close()
      }
    }
  }, [])

  // Update subscribers ref when it changes
  useEffect(() => {
    if (socket) {
      socket.onmessage = (event) => {
        try {
          const message: WSMessage = JSON.parse(event.data)
          setLastMessage(message)

          const typeSubscribers = subscribers.get(message.type)
          if (typeSubscribers) {
            typeSubscribers.forEach((callback) => callback(message.data))
          }

          const allSubscribers = subscribers.get('all')
          if (allSubscribers) {
            allSubscribers.forEach((callback) => callback(message))
          }
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e)
        }
      }
    }
  }, [socket, subscribers])

  const send = useCallback((message: object) => {
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(message))
    }
  }, [socket])

  const subscribe = useCallback((type: string, callback: (data: unknown) => void) => {
    setSubscribers((prev) => {
      const newMap = new Map(prev)
      if (!newMap.has(type)) {
        newMap.set(type, new Set())
      }
      newMap.get(type)!.add(callback)
      return newMap
    })

    // Return unsubscribe function
    return () => {
      setSubscribers((prev) => {
        const newMap = new Map(prev)
        const typeSubscribers = newMap.get(type)
        if (typeSubscribers) {
          typeSubscribers.delete(callback)
          if (typeSubscribers.size === 0) {
            newMap.delete(type)
          }
        }
        return newMap
      })
    }
  }, [])

  return (
    <WebSocketContext.Provider value={{ isConnected, lastMessage, send, subscribe }}>
      {children}
    </WebSocketContext.Provider>
  )
}

export function useWebSocket() {
  const context = useContext(WebSocketContext)
  if (context === undefined) {
    throw new Error('useWebSocket must be used within a WebSocketProvider')
  }
  return context
}
