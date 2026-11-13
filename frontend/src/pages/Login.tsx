import { useState } from 'react'
import { api, ApiError } from '../api'
import { Field, usePageTitle } from '../components/ui'

function message(ex: unknown): string {
  if (ex instanceof ApiError) {
    if (ex.status === 401) return 'That username and password do not match. Check both and try again.'
    if (ex.status === 429) return ex.message
    return `Sign-in failed: ${ex.message}`
  }
  return 'The Threat Watch server could not be reached. Check that it is running, then try again.'
}

export default function Login({ onLogin }: { onLogin: () => void }) {
  usePageTitle('Sign in')
  const [username, setU] = useState('')
  const [password, setP] = useState('')
  const [show, setShow] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setErr(null)
    try { await api.post('/api/auth/login', { username: username.trim(), password }); onLogin() }
    catch (ex) { setErr(message(ex)); setP('') }
    finally { setBusy(false) }
  }

  return (
    <main className="auth">
      <section className="auth-brand" aria-label="About Threat Watch">
        <div className="row nowrap"><img src="/pwa-192.png" alt="" width={40} height={40} className="logo" /><span className="auth-name">Threat Watch</span></div>
        <div className="auth-copy">
          <p className="eyebrow">Personal security intelligence</p>
          <h1>Today’s threats, ranked by evidence.</h1>
          <ul className="auth-facts">
            <li>Collects from security press, vendor research, CISA KEV, FIRST EPSS and NCSC NZ every two hours.</li>
            <li>Every severity rating states its reasons. Every claim links to its source.</li>
            <li>Follow an incident, CVE or actor and new reporting is added to its record as it appears.</li>
          </ul>
        </div>
        <p className="xsmall auth-foot">Private instance. All content requires sign-in.</p>
      </section>

      <section className="auth-form-wrap">
        <form className="auth-form" onSubmit={submit} aria-labelledby="login-h" noValidate>
          <div className="row nowrap auth-mobile-brand"><img src="/pwa-192.png" alt="" width={32} height={32} className="logo" /><span className="auth-name">Threat Watch</span></div>
          <h2 id="login-h">Sign in</h2>
          <Field label="Username">
            <input className="input" name="username" autoComplete="username" autoCapitalize="none" spellCheck={false} value={username} onChange={(e) => setU(e.target.value)} required autoFocus />
          </Field>
          <Field label="Password">
            <span className="pw">
              <input className="input" name="password" type={show ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={(e) => setP(e.target.value)} required />
              <button type="button" className="btn quiet small" aria-pressed={show} onClick={() => setShow(!show)}>{show ? 'Hide' : 'Show'}</button>
            </span>
          </Field>
          {err && <div className="alert mb-3" role="alert"><p className="mb-0">{err}</p></div>}
          <button className="btn primary block" aria-busy={busy || undefined} disabled={!username || !password}>Sign in</button>
          <p className="xsmall muted mt-3 mb-0">Forgotten the password? Reset it on the host with <code>deploy/local.sh password</code>.</p>
        </form>
      </section>
    </main>
  )
}
