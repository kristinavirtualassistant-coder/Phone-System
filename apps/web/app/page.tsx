'use client';

import { FormEvent, useState } from 'react';

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:3001';

type View = 'login' | 'register' | 'verify' | 'reset' | 'dashboard';

type ApiResponse = {
  data?: Record<string, unknown>;
  error?: { code: string; message: string };
};

async function api(path: string, body?: Record<string, unknown>) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: body ? 'POST' : 'GET',
    ...(body ? { headers: { 'Content-Type': 'application/json' } } : {}),
    credentials: 'include',
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const payload = (await response.json().catch(() => ({}))) as ApiResponse;
  if (!response.ok) {
    throw new Error(payload.error?.message ?? 'Request failed');
  }
  return payload;
}

export default function Home() {
  const [view, setView] = useState<View>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [token, setToken] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [userId, setUserId] = useState('');

  function resetFeedback() {
    setMessage('');
    setError('');
  }

  async function submitLogin(event: FormEvent) {
    event.preventDefault();
    resetFeedback();
    try {
      const result = await api('/api/v1/auth/login', {
        email,
        password,
        ...(mfaCode ? { mfa_code: mfaCode } : {}),
      });
      setUserId(String(result.data?.user_id ?? ''));
      setView('dashboard');
    } catch (err) {
      const text = err instanceof Error ? err.message : 'Login failed';
      if (text.toLowerCase().includes('mfa')) {
        setError(`${text} Enter your six-digit code and submit again.`);
      } else {
        setError(text);
      }
    }
  }

  async function submitRegister(event: FormEvent) {
    event.preventDefault();
    resetFeedback();
    try {
      await api('/api/v1/auth/register', {
        email,
        password,
      });
      setView('verify');
      setMessage('Account created. Enter the verification token from the development API log.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    }
  }

  async function submitVerify(event: FormEvent) {
    event.preventDefault();
    resetFeedback();
    try {
      await api('/api/v1/auth/verify-email', { token });
      setView('login');
      setMessage('Email verified. You can now sign in.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    }
  }

  async function submitReset(event: FormEvent) {
    event.preventDefault();
    resetFeedback();
    try {
      await api('/api/v1/auth/password-reset/request', { email });
      setView('login');
      setMessage('If the account exists, reset instructions were issued.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Reset request failed');
    }
  }

  async function logout() {
    await api('/api/v1/auth/logout', {});
    setUserId('');
    setView('login');
    setMessage('Signed out.');
  }

  if (view === 'dashboard') {
    return (
      <main className="shell">
        <section className="app-card dashboard">
          <div className="brand-row">
            <div>
              <span className="eyebrow">PLATFORM</span>
              <h1>Workspace</h1>
            </div>
            <button className="button secondary" onClick={logout}>Sign out</button>
          </div>
          <div className="welcome">
            <span className="status-dot" />
            <div>
              <strong>Authenticated</strong>
              <p>Session active for user {userId}</p>
            </div>
          </div>
          <div className="grid">
            {['Contacts', 'Campaigns', 'Communications', 'Sequences', 'Integrations', 'Billing'].map((item) => (
              <div className="module" key={item}>
                <span className="module-icon">+</span>
                <strong>{item}</strong>
                <small>Coming in a future handoff</small>
              </div>
            ))}
          </div>
          <div className="security-panel">
            <div>
              <span className="eyebrow">SECURITY</span>
              <h2>Foundation active</h2>
            </div>
            <p>Tenant isolation, server-managed sessions, MFA, RBAC, audit logging and API-key controls are provided by the API.</p>
          </div>
        </section>
      </main>
    );
  }

  const title =
    view === 'register' ? 'Create your account' :
    view === 'verify' ? 'Verify your email' :
    view === 'reset' ? 'Reset your password' :
    'Welcome back';

  return (
    <main className="auth-shell">
      <section className="hero">
        <span className="eyebrow">SALES ENGAGEMENT PLATFORM</span>
        <h1>One secure workspace for your team.</h1>
        <p>Build relationships, manage conversations, and grow your pipeline from one tenant-aware workspace.</p>
        <div className="feature-list">
          <span>✓ Multi-tenant by design</span>
          <span>✓ Server-managed authentication</span>
          <span>✓ Role-based access control</span>
        </div>
      </section>

      <section className="auth-card">
        <div className="logo-mark">P</div>
        <h2>{title}</h2>
        <p className="muted">
          {view === 'login' && 'Sign in to continue to your workspace.'}
          {view === 'register' && 'Create your global account first.'}
          {view === 'verify' && 'Confirm ownership of your email address.'}
          {view === 'reset' && 'We will issue a short-lived reset token.'}
        </p>

        {message && <div className="notice success">{message}</div>}
        {error && <div className="notice error">{error}</div>}

        {view === 'verify' ? (
          <form onSubmit={submitVerify}>
            <label>Verification token<input value={token} onChange={(e) => setToken(e.target.value)} required /></label>
            <button className="button" type="submit">Verify email</button>
          </form>
        ) : view === 'reset' ? (
          <form onSubmit={submitReset}>
            <label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
            <button className="button" type="submit">Request reset</button>
          </form>
        ) : (
          <form onSubmit={view === 'register' ? submitRegister : submitLogin}>
            <label>Email<input type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
            <label>Password<input type="password" autoComplete={view === 'register' ? 'new-password' : 'current-password'} value={password} onChange={(e) => setPassword(e.target.value)} required minLength={12} /></label>
            {view === 'login' && (
              <label>MFA code <span className="optional">(if enabled)</span><input inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={mfaCode} onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))} /></label>
            )}
            <button className="button" type="submit">{view === 'register' ? 'Create account' : 'Sign in'}</button>
          </form>
        )}

        <div className="auth-links">
          {view === 'login' && <>
            <button onClick={() => { resetFeedback(); setView('register'); }}>Create an account</button>
            <button onClick={() => { resetFeedback(); setView('reset'); }}>Forgot password?</button>
          </>}
          {view !== 'login' && <button onClick={() => { resetFeedback(); setView('login'); }}>Back to sign in</button>}
        </div>
      </section>
    </main>
  );
}
