
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState
} from 'react';

import { api, clearCsrfToken } from '../api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Restore the authenticated session
  useEffect(() => {
    api.get('/auth/me')
      .then(res => setUser(res.data.user || null))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (email, password) => {
    const res = await api.post('/auth/login', {
      email,
      password
    });

    clearCsrfToken();
    setUser(res.data.user);
  }, []);

  const register = useCallback(async (name, email, password) => {
    const res = await api.post('/auth/register', {
      name,
      email,
      password
    });

    clearCsrfToken();
    setUser(res.data.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout');
    } catch {
      // Continue clearing the local session
    }

    clearCsrfToken();
    setUser(null);
    window.location.href = '/login';
  }, []);

  return (
    <AuthContext.Provider
      value={{ user, loading, login, register, logout }}
    >
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
