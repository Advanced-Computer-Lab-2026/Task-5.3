import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'

const defaults = { title: '', description: '', category: 'other', status: 'lost', location: '' }
const statuses = ['lost', 'found', 'claimed']
const categories = ['electronics', 'clothing', 'documents', 'accessories', 'other']

export default function ItemForm() {
  const nav = useNavigate()
  const { id } = useParams()
  const [form, setForm] = useState(defaults)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!id) {
      setForm(defaults)
      return
    }

    let ignore = false

    async function loadItem() {
      setError('')
      try {
        const { data } = await api.get(`/items/${id}`)
        if (!ignore) {
          const { title, status, category, location = '', description = '' } = data.item
          setForm({ title, status, category, location, description })
        }
      } catch (err) {
        if (!ignore) setError(err?.response?.data?.message || 'Could not load item')
      }
    }

    loadItem()
    return () => { ignore = true }
  }, [id])

  function onChange(e) {
    const { name, value } = e.target
    setForm(current => ({ ...current, [name]: value }))
  }

  async function onSubmit(e) {
    e.preventDefault()
    setError('')

    const item = {
      title: form.title,
      status: form.status,
      category: form.category,
      location: form.location,
      description: form.description
    }

    try {
      if (id) {
        await api.patch(`/items/${id}`, item)
      } else {
        await api.post('/items', item)
      }
      nav('/items')
    } catch (err) {
      setError(err?.response?.data?.message || 'Could not save item')
    }
  }

  return (
    <div className="max-w-lg mx-auto card">
      <h1 className="text-xl font-semibold mb-4">{id ? 'Edit' : 'Report'} Item</h1>
      <form onSubmit={onSubmit} className="space-y-3">
        <input
          className="input"
          name="title"
          placeholder="Black backpack"
          value={form.title}
          onChange={onChange}
          required
        />
        <select className="input" name="status" value={form.status} onChange={onChange}>
          {statuses.map(status => (
            <option key={status} value={status}>
              {status[0].toUpperCase() + status.slice(1)}
            </option>
          ))}
        </select>
        <select className="input" name="category" value={form.category} onChange={onChange}>
          {categories.map(category => (
            <option key={category} value={category}>
              {category[0].toUpperCase() + category.slice(1)}
            </option>
          ))}
        </select>
        <input
          className="input"
          name="location"
          placeholder="Library 2nd floor"
          value={form.location}
          onChange={onChange}
        />
        <textarea
          className="input"
          name="description"
          placeholder="Description"
          value={form.description}
          onChange={onChange}
          rows="4"
        />
        {error && <div className="text-red-600 text-sm">{error}</div>}
        <button className="btn" type="submit">Save</button>
      </form>
    </div>
  )
}