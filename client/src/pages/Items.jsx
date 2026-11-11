import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../hooks/useAuth'

const CATEGORIES = ['electronics', 'clothing', 'documents', 'accessories', 'other']
const STATUSES = ['lost', 'found', 'claimed']

export default function Items() {
  const { user } = useAuth()
  const [items, setItems] = useState([])
  const [status, setStatus] = useState('')
  const [category, setCategory] = useState('')
  const [error, setError] = useState('')

  async function load() {
    const res = await api.get('/items', { params: { status: status || undefined, category: category || undefined } })
    setItems(res.data.items)
  }

  useEffect(() => { load() }, [status, category])

  async function onDelete(id) {
    setError('')
    try {
      await api.delete('/items/' + id)
      setItems(prev => prev.filter(i => i._id !== id))
    } catch (err) {
      setError(err?.response?.data?.message || 'Delete failed')
    }
  }

  return (
    <div className="space-y-4">
      <div className="card flex items-center gap-2">
        <select className="input" value={status} onChange={e => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input" value={category} onChange={e => setCategory(e.target.value)}>
          <option value="">All categories</option>
          {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>
      {error && <div className="text-red-600 text-sm">{error}</div>}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {items.map(i => {
          const isMine = user && i.reportedBy?._id === user.id
          return (
            <div key={i._id} className="card">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-semibold">{i.title}</div>
                  <div className="text-sm text-zinc-600">
                    {i.status} • {i.category}{i.location && <> • {i.location}</>} • by {i.reportedBy?.name || 'unknown'}
                  </div>
                </div>
                {isMine && (
                  <div className="flex gap-2">
                    <Link to={`/items/${i._id}`} className="btn text-sm">Edit</Link>
                    <button onClick={() => onDelete(i._id)} className="btn text-sm">Delete</button>
                  </div>
                )}
              </div>
              {i.description && <p className="mt-2 text-sm">{i.description}</p>}
            </div>
          )
        })}
        {items.length === 0 && <div className="text-sm text-zinc-600">No items found.</div>}
      </div>
    </div>
  )
}
