import { useEffect, useState } from 'react'
import { api } from '../api'

export default function Settings() {
  const [recoveryEmail, setRecoveryEmail] = useState('')
  const [current, setCurrent] = useState('')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  async function load() {
    setError('')
    try {
      const { data } = await api.get('/settings')
      setCurrent(data.settings.recoveryEmail || '')
      setRecoveryEmail(data.settings.recoveryEmail || '')
    } catch (err) {
      setError(err?.response?.data?.message || 'Could not load settings')
    }
  }

  useEffect(() => { load() }, [])

  async function onSubmit(e) {
    e.preventDefault()
    setError('')
    setSaved(false)
    try {
      const { data } = await api.post('/settings/recovery-email', { recoveryEmail })
      setCurrent(data.settings.recoveryEmail || '')
      setSaved(true)
    } catch (err) {
      setError(err?.response?.data?.message || 'Could not save settings')
    }
  }

  return (
    <div className="max-w-md mx-auto card">
      <h1 className="text-xl font-semibold mb-2">Account Settings</h1>
      <p className="text-sm text-zinc-600 mb-4">
        Your recovery email receives password-reset links. Current value:{' '}
        <b>{current || '(none set)'}</b>
      </p>
      <form onSubmit={onSubmit} className="space-y-3">
        <input
          className="input"
          type="email"
          placeholder="you@example.com"
          value={recoveryEmail}
          onChange={e => setRecoveryEmail(e.target.value)}
          required
        />
        {error && <div className="text-red-600 text-sm">{error}</div>}
        {saved && <div className="text-green-600 text-sm">Recovery email updated.</div>}
        <button className="btn" type="submit">Save recovery email</button>
      </form>
    </div>
  )
}
