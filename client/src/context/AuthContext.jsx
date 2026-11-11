
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState
} from 'react'

import { api, clearCsrfToken } from '../api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  // Restore the current session on page load
  useEffect(() => {
    api.get('/auth/me')
      .then(res => {
        setUser(res.data.user || null)
      })
      .catch(() => {
        setUser(null)
        clearCsrfToken()
      })
      .finally(() => {
        setLoading(false)
      })
  }, [])

  // Login
  const login = useCallback(async (email, password) => {
    const res = await api.post('/auth/login', {
      email,
      password
    })

    // Authentication cookie has changed
    clearCsrfToken()

    setUser(res.data.user)
  }, [])

  // Register
  const register = useCallback(async (name, email, password) => {
    const res = await api.post('/auth/register', {
      name,
      email,
      password
    })

    // Registration creates a new authenticated session
    clearCsrfToken()

    setUser(res.data.user)
  }, [])

  // Logout
  const logout = useCallback(async () => {
    // The Axios interceptor automatically adds the CSRF token
    // to this POST request.
    await api.post('/auth/logout')

    // The server has successfully cleared the auth cookie.
    clearCsrfToken()
    setUser(null)

    window.location.href = '/login'
  }, [])

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        register,
        logout
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)

  if (!ctx) {
    throw new Error('useAuth must be used within <AuthProvider>')
  }

  return ctx
}
