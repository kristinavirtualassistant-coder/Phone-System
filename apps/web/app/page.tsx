'use client';

import { FormEvent, useEffect, useRef, useState } from 'react';

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:3001';

type View = 'login' | 'register' | 'verify' | 'reset' | 'dashboard';

type ApiResponse = {
  data?: Record<string, unknown>;
  error?: { code: string; message: string };
};

async function api(path: string, body?: Record<string, unknown>, tenantId?: string) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: body ? 'POST' : 'GET',
    ...(body || tenantId ? { headers: { 'Content-Type': 'application/json', ...(tenantId ? { 'X-Tenant-Id': tenantId } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) } : {}),
    credentials: 'include',
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
  const [tenantId, setTenantId] = useState('');
  const [tenants, setTenants] = useState<Array<{ tenant_id: string; name: string; role: string }>>([]);
  const [phoneNumbers, setPhoneNumbers] = useState<Array<{ id: string; provider_id: string; e164: string; label?: string }>>([]);
  const [dialNumber, setDialNumber] = useState('');
  const [selectedPhone, setSelectedPhone] = useState('');
  const [dialerStatus, setDialerStatus] = useState('Disconnected');
  const [callStatus, setCallStatus] = useState('');
  const [conversations, setConversations] = useState<any[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<any | null>(null);
  const [conversationMessages, setConversationMessages] = useState<any[]>([]);
  const [communicationProviders, setCommunicationProviders] = useState<any[]>([]);
  const [emailAccounts, setEmailAccounts] = useState<any[]>([]);
  const [smsTo, setSmsTo] = useState('');
  const [smsText, setSmsText] = useState('');
  const [smsContactId, setSmsContactId] = useState('');
  const [emailAccountId, setEmailAccountId] = useState('');
  const [emailTo, setEmailTo] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [emailBody, setEmailBody] = useState('');
  const rtcRef = useRef<any>(null);
  const callRef = useRef<any>(null);

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
      const tenantResult = await api('/api/v1/tenants');
      const rows = (tenantResult.data ?? []) as Array<{ tenant_id: string; name: string; role: string }> ;
      setTenants(rows);
      if (rows[0]) setTenantId(rows[0].tenant_id);
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

  useEffect(() => {
    if (view !== 'dashboard' || !tenantId) return;
    void Promise.all([
      api('/api/v1/telephony/phone-numbers', undefined, tenantId),
      api('/api/v1/telephony/providers', undefined, tenantId),
      api('/api/v1/communications/conversations', undefined, tenantId),
      api('/api/v1/communications/email/accounts', undefined, tenantId),
    ]).then(([phones, providers, convs, accounts]) => {
      setPhoneNumbers((phones.data ?? []) as Array<{ id: string; provider_id: string; e164: string; label?: string }>);
      setCommunicationProviders((providers.data ?? []) as any[]);
      setConversations((convs.data ?? []) as any[]);
      setEmailAccounts((accounts.data ?? []) as any[]);
      if (!emailAccountId && accounts.data?.[0]) setEmailAccountId(String((accounts.data as unknown as any[])[0].id));
    }).catch((err) => setError(err instanceof Error ? err.message : 'Unable to load communications'));
  }, [view, tenantId]);


  async function openConversation(conversation: any) {
    setSelectedConversation(conversation);
    try { const result = await api(`/api/v1/communications/conversations/${conversation.id}/messages`, undefined, tenantId); setConversationMessages((result.data ?? []) as any[]); } catch (err) { setError(err instanceof Error ? err.message : 'Unable to load conversation'); }
  }

  async function sendSms(event: FormEvent) {
    event.preventDefault(); resetFeedback();
    const provider = communicationProviders.find((p) => p.status === 'ACTIVE');
    const sender = phoneNumbers.find((n: any) => n.status === 'ACTIVE');
    try {
      if (!provider || !sender || !smsContactId) throw new Error('Select an active Telnyx provider, caller number, and contact ID.');
      await api('/api/v1/communications/sms', { provider_id: provider.id, from_number: sender.e164, to: smsTo, text: smsText, contact_id: smsContactId, idempotency_key: crypto.randomUUID() }, tenantId);
      setSmsText(''); setMessage('SMS queued/sent.');
    } catch (err) { setError(err instanceof Error ? err.message : 'SMS send failed'); }
  }

  async function connectMailbox(provider: 'google'|'microsoft') {
    try { const result = await api(`/api/v1/communications/email/${provider}/connect`, undefined, tenantId); window.location.href = String((result.data as any)?.authorize_url); } catch (err) { setError(err instanceof Error ? err.message : 'Mailbox connection failed'); }
  }

  async function sendEmail(event: FormEvent) {
    event.preventDefault(); resetFeedback();
    try { if (!emailAccountId) throw new Error('Connect/select an email account first.'); await api(`/api/v1/communications/email/${emailAccountId}/send`, { to: emailTo.split(',').map((v) => v.trim()).filter(Boolean), subject: emailSubject, text: emailBody, idempotency_key: crypto.randomUUID() }, tenantId); setEmailBody(''); setMessage('Email submitted to the provider.'); } catch (err) { setError(err instanceof Error ? err.message : 'Email send failed'); }
  }

  async function connectBrowser() {
    resetFeedback();
    try {
      if (!tenantId || !selectedPhone) throw new Error('Select a workspace and caller number first.');
      const selected = phoneNumbers.find((n) => n.id === selectedPhone);
      if (!selected) throw new Error('Caller number not found.');
      const result = await api(`/api/v1/telephony/providers/${selected.provider_id}/browser-token`, {}, tenantId);
      const { TelnyxRTC } = await import('@telnyx/webrtc');
      const client = new TelnyxRTC({ login_token: String((result.data as any)?.token) });
      client.remoteElement = 'remoteMedia';
      client.on('telnyx.ready', () => setDialerStatus('Ready'));
      client.on('telnyx.error', (err: unknown) => setDialerStatus(`Error: ${String(err)}`));
      client.on('telnyx.notification', (notification: any) => {
        if (notification?.type === 'callUpdate') setCallStatus(notification.call?.state ?? 'updated');
      });
      await client.connect();
      rtcRef.current = client;
      setDialerStatus('Ready');
    } catch (err) { setDialerStatus('Error'); setError(err instanceof Error ? err.message : 'Browser calling failed'); }
  }

  function placeBrowserCall() {
    const client = rtcRef.current;
    const selected = phoneNumbers.find((n) => n.id === selectedPhone);
    if (!client || !selected || !dialNumber) { setError('Connect the browser and enter a destination number.'); return; }
    try {
      callRef.current = client.newCall({ destinationNumber: dialNumber, callerNumber: selected.e164, audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true } });
      setCallStatus('trying');
    } catch (err) { setError(err instanceof Error ? err.message : 'Call failed'); }
  }

  async function hangupBrowserCall() {
    try { if (callRef.current?.hangup) await callRef.current.hangup(); else if (rtcRef.current) await rtcRef.current.disconnect(); } finally { callRef.current = null; setCallStatus('hangup'); }
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
          <div className="security-panel">
            <div>
              <span className="eyebrow">WORKSPACE</span>
              <h2>Telephony</h2>
            </div>
            <div className="grid">
              <label>Workspace<select value={tenantId} onChange={(e) => setTenantId(e.target.value)}>{tenants.map((t) => <option key={t.tenant_id} value={t.tenant_id}>{t.name} ({t.role})</option>)}</select></label>
              <label>Caller number<select value={selectedPhone} onChange={(e) => setSelectedPhone(e.target.value)}><option value="">Select number</option>{phoneNumbers.map((n) => <option key={n.id} value={n.id}>{n.label ? `${n.label} — ` : ''}{n.e164}</option>)}</select></label>
            </div>
            <div className="grid">
              <label>Destination<input value={dialNumber} onChange={(e) => setDialNumber(e.target.value)} placeholder="+15551234567" /></label>
              <div><span className="eyebrow">STATUS</span><p>{dialerStatus}{callStatus ? ` · ${callStatus}` : ''}</p></div>
            </div>
            <div className="auth-links">
              <button className="button secondary" onClick={connectBrowser}>Connect browser</button>
              <button className="button" onClick={placeBrowserCall}>Call</button>
              <button className="button secondary" onClick={hangupBrowserCall}>Hang up</button>
            </div>
            <audio id="remoteMedia" autoPlay />
          </div>
          <div className="security-panel">
            <div><span className="eyebrow">COMMUNICATIONS</span><h2>Unified inbox</h2></div>
            <div className="grid">
              <div>
                <strong>Conversations</strong>
                <div className="module-list">{conversations.map((c) => <button className="module" key={c.id} onClick={() => void openConversation(c)}><strong>{c.display_name || c.email || c.phone_e164 || 'Contact'}</strong><small>{c.channel} · {c.status} · {c.unread_count ?? 0} unread</small></button>)}</div>
              </div>
              <div>
                <strong>Timeline / messages</strong>
                <div className="module-list">{conversationMessages.map((m) => <div className="module" key={m.id}><strong>{m.direction} · {m.status}</strong><small>{m.body || '[media/email]'}</small></div>)}</div>
              </div>
            </div>
          </div>
          <div className="grid">
            <div className="security-panel"><span className="eyebrow">SMS / MMS</span><h2>Send message</h2><form onSubmit={sendSms}><label>Contact ID<input value={smsContactId} onChange={(e)=>setSmsContactId(e.target.value)} placeholder="UUID" required /></label><label>To<input value={smsTo} onChange={(e)=>setSmsTo(e.target.value)} placeholder="+15551234567" required /></label><label>Message<textarea value={smsText} onChange={(e)=>setSmsText(e.target.value)} maxLength={1600} required /></label><button className="button" type="submit">Send SMS</button></form></div>
            <div className="security-panel"><span className="eyebrow">EMAIL</span><h2>Connected mailboxes</h2><div className="auth-links"><button className="button secondary" onClick={()=>void connectMailbox('google')}>Connect Gmail</button><button className="button secondary" onClick={()=>void connectMailbox('microsoft')}>Connect Microsoft 365</button></div><select value={emailAccountId} onChange={(e)=>setEmailAccountId(e.target.value)}><option value="">Select mailbox</option>{emailAccounts.map((a)=><option key={a.id} value={a.id}>{a.provider} — {a.email} ({a.sync_status})</option>)}</select><form onSubmit={sendEmail}><label>To<input value={emailTo} onChange={(e)=>setEmailTo(e.target.value)} placeholder="owner@example.com" required /></label><label>Subject<input value={emailSubject} onChange={(e)=>setEmailSubject(e.target.value)} required /></label><label>Body<textarea value={emailBody} onChange={(e)=>setEmailBody(e.target.value)} required /></label><button className="button" type="submit">Send email</button></form></div>
          </div>
          <div className="grid">
            {['Contacts', 'Campaigns', 'Sequences', 'Integrations', 'Billing'].map((item) => <div className="module" key={item}><span className="module-icon">+</span><strong>{item}</strong><small>Reserved for a later handoff</small></div>)}
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
