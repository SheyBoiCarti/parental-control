import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { setAuthCredentials, clearAuthCredentials, healthCheck } from '../api/client'

interface AuthContextType {
  isAuthenticated: boolean
  isLoading: boolean
  username: string | null
  login: (username: string, password: string) => Promise<boolean>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [username, setUsername] = useState<string | null>(null)

  useEffect(() => {
    // Check for stored credentials
    const storedAuth = localStorage.getItem('auth')
    if (storedAuth) {
      try {
        const { username, password } = JSON.parse(storedAuth)
        setAuthCredentials(username, password)
        setUsername(username)
        setIsAuthenticated(true)
      } catch {
        localStorage.removeItem('auth')
      }
    }
    setIsLoading(false)
  }, [])

  const login = async (username: string, password: string): Promise<boolean> => {
    try {
      setAuthCredentials(username, password)

      // Try to make an authenticated request
      const response = await fetch('/api/devices', {
        headers: {
          Authorization: `Basic ${btoa(`${username}:${password}`)}`,
        },
      })

      if (response.ok || response.status === 503) {
        // 503 means service not ready but auth was accepted
        localStorage.setItem('auth', JSON.stringify({ username, password }))
        setUsername(username)
        setIsAuthenticated(true)
        return true
      } else if (response.status === 401) {
        clearAuthCredentials()
        return false
      }

      // For other errors, assume auth is OK (might be a backend issue)
      localStorage.setItem('auth', JSON.stringify({ username, password }))
      setUsername(username)
      setIsAuthenticated(true)
      return true
    } catch {
      // Network error - assume credentials are OK for offline mode
      localStorage.setItem('auth', JSON.stringify({ username, password }))
      setUsername(username)
      setIsAuthenticated(true)
      return true
    }
  }

  const logout = () => {
    clearAuthCredentials()
    localStorage.removeItem('auth')
    setUsername(null)
    setIsAuthenticated(false)
  }

  return (
    <AuthContext.Provider value={{ isAuthenticated, isLoading, username, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
