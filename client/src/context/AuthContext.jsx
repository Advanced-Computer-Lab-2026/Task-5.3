
import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api, fetchCsrfToken, clearCsrfToken } from '../api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function restoreSession() {
      try {
        const res = await api.get('/auth/me');
        const currentUser = res.data.user || null;

        setUser(currentUser);

        if (currentUser) {
          await fetchCsrfToken();
        }
      } catch {
        setUser(null);
        clearCsrfToken();
      } finally {
        setLoading(false);
      }
    }

    restoreSession();
  }, []);

  const login = useCallback(async (email, password) => {
    clearCsrfToken();

    const res = await api.post('/auth/login', { email, password });

    setUser(res.data.user);
    await fetchCsrfToken();
  }, []);

  const register = useCallback(async (name, email, password) => {
    clearCsrfToken();

    const res = await api.post('/auth/register', {
      name,
      email,
      password
    });

    setUser(res.data.user);
    await fetchCsrfToken();
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout');
    } catch (err) {
      console.error('Logout failed:', err);
    } finally {
      clearCsrfToken();
      setUser(null);
      window.location.href = '/login';
    }
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);

  if (!ctx) {
    throw new Error('useAuth must be used within <AuthProvider>');
  }

  return ctx;
}
