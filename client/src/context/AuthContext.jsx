import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { api, setCsrfToken, clearCsrfToken } from '../api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  // The session now lives in an httpOnly cookie the browser sends automatically,
  // so there is no token in localStorage to read. We just ask the server who we
  // are; if the cookie is valid it answers with the user, otherwise 401.
  async function loadCsrfToken() {
  const res = await api.get('/auth/csrf-token')
  setCsrfToken(res.data.csrfToken)
}
useEffect(() => {
  async function initializeAuth() {
    try {
      const res = await api.get('/auth/me')
      setUser(res.data.user || null)

      if (res.data.user) {
        await loadCsrfToken()
      }
    } catch {
      setUser(null)
      clearCsrfToken()
    } finally {
      setLoading(false)
    }
  }

  initializeAuth()
}, [])

const login = useCallback(async (email, password) => {
  const res = await api.post('/auth/login', { email, password })
  setUser(res.data.user)
  await loadCsrfToken()
}, [])
 const register = useCallback(async (name, email, password) => {
  const res = await api.post('/auth/register', { name, email, password })
  setUser(res.data.user)
  await loadCsrfToken()
}, [])
  const logout = useCallback(async () => {
  try {
    await api.post('/auth/logout')
  } catch (err) {
    console.error('Logout error:', err)
  } finally {
    clearCsrfToken()
    setUser(null)
    window.location.href = '/login'
  }
}, [])


  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within <AuthProvider>')
  return ctx
}
