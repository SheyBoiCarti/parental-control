import { createContext, useContext, useState, useEffect, useRef, useCallback, ReactNode } from 'react'
import { ApiError, getSession, loginSession, logoutSession, onSessionExpired, setSessionCsrf, SessionInfo } from '../api/client'

interface AuthContextType {
  isAuthenticated: boolean
  isLoading: boolean
  username: string | null
  login: (username: string, password: string) => Promise<boolean>
  logout: () => Promise<void>
}
const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const generation = useRef(0)
  const cancelRequests = useCallback(() => { generation.current++ }, [])
  const clear = useCallback(() => {
    generation.current++
    setSessionCsrf(null)
    setSession(null)
  }, [])
  const confirm = useCallback((value: SessionInfo) => {
    if (!value.username || !value.csrf_token || !(Date.parse(value.expires_at) > Date.now())) {
      throw new Error('Server returned an invalid session')
    }
    setSessionCsrf(value.csrf_token)
    setSession(value)
  }, [])

  useEffect(() => {
    localStorage.removeItem('auth')
    const controller = new AbortController()
    const attempt = ++generation.current
    const unsubscribe = onSessionExpired(clear)
    getSession(controller.signal).then(value => {
      if (!controller.signal.aborted && attempt === generation.current) confirm(value)
    }).catch(() => {
      if (!controller.signal.aborted && attempt === generation.current) clear()
    }).finally(() => {
      if (!controller.signal.aborted) setIsLoading(false)
    })
    return () => { controller.abort(); cancelRequests(); unsubscribe(); setSessionCsrf(null) }
  }, [clear, confirm, cancelRequests])

  useEffect(() => {
    if (!session) return
    const timeout = window.setTimeout(clear, Math.max(0, Date.parse(session.expires_at) - Date.now()))
    return () => window.clearTimeout(timeout)
  }, [session, clear])

  const login = async (username: string, password: string): Promise<boolean> => {
    const attempt = ++generation.current
    try {
      const value = await loginSession(username, password)
      if (attempt !== generation.current) return false
      confirm(value)
      return true
    } catch (error) {
      if (attempt === generation.current) clear()
      if (error instanceof ApiError && error.status === 401) return false
      throw error
    }
  }
  const logout = async () => {
    generation.current++
    await logoutSession()
    clear()
  }
  return <AuthContext.Provider value={{ isAuthenticated: session !== null, isLoading, username: session?.username || null, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used within an AuthProvider')
  return value
}
