import { useState } from 'react'
import { api } from '../api'

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setU] = useState('')
  const [password, setP] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setErr(null)
    try { await api.post('/api/auth/login', { username, password }); onLogin() }
    catch (ex) { setErr(ex instanceof Error ? ex.message : 'Login failed') }
    finally { setBusy(false) }
  }
  return (
    <div className="login">
      <form className="card" onSubmit={submit} aria-labelledby="login-h">
        <div className="row" style={{ marginBottom: '1rem' }}><img src="/pwa-192.png" alt="" width={36} height={36} style={{ borderRadius: 8 }} /><h1 id="login-h" style={{ margin: 0 }}>Threat Watch</h1></div>
        <label className="field"><span>Username</span><input className="input" autoComplete="username" value={username} onChange={(e) => setU(e.target.value)} required autoFocus /></label>
        <label className="field"><span>Password</span><input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setP(e.target.value)} required /></label>
        {err && <p className="error" role="alert">{err}</p>}
        <button className="btn primary" style={{ width: '100%' }} disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <p className="small faint" style={{ marginTop: '1rem', marginBottom: 0 }}>Private application. All content requires authentication.</p>
      </form>
    </div>
  )
}
