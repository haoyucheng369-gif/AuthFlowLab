import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const authServer = 'http://127.0.0.1:5001';
const apiServer = 'http://127.0.0.1:5002';
const clientId = 'demo-spa';
const redirectUri = 'http://127.0.0.1:5173/callback';
const scope = 'openid profile content.read';

type TokenResponse = {
  access_token: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
  scope: string;
};

type CallResult = {
  label: string;
  status: number;
  body: string;
};

function App() {
  const [username, setUsername] = useState('user');
  const [password, setPassword] = useState('user123');
  const [tokens, setTokens] = useState<TokenResponse | null>(() => readJson<TokenResponse>('authflowlab.tokens'));
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<CallResult | null>(null);

  const idTokenPayload = useMemo(() => {
    return tokens?.id_token ? decodeJwtPayload(tokens.id_token) : null;
  }, [tokens]);

  useEffect(() => {
    if (window.location.pathname !== '/callback') {
      return;
    }

    void completeLogin(setTokens, setMessage);
  }, []);

  async function login() {
    setMessage('');
    setResult(null);

    const verifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = await createCodeChallenge(verifier);
    const state = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
    const nonce = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));

    sessionStorage.setItem('authflowlab.pkce.verifier', verifier);
    sessionStorage.setItem('authflowlab.pkce.state', state);
    sessionStorage.setItem('authflowlab.pkce.nonce', nonce);

    const authorizeUrl = new URL(`${authServer}/connect/authorize`);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('client_id', clientId);
    authorizeUrl.searchParams.set('redirect_uri', redirectUri);
    authorizeUrl.searchParams.set('scope', scope);
    authorizeUrl.searchParams.set('state', state);
    authorizeUrl.searchParams.set('nonce', nonce);
    authorizeUrl.searchParams.set('code_challenge', challenge);
    authorizeUrl.searchParams.set('code_challenge_method', 'S256');
    authorizeUrl.searchParams.set('username', username);
    authorizeUrl.searchParams.set('password', password);

    window.location.assign(authorizeUrl.toString());
  }

  async function callApi(path: string, label: string) {
    if (!tokens?.access_token) {
      setMessage('Login first.');
      return;
    }

    const response = await fetch(path, {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`
      }
    });
    const body = await response.text();
    setResult({ label, status: response.status, body });
  }

  function logout() {
    localStorage.removeItem('authflowlab.tokens');
    sessionStorage.removeItem('authflowlab.pkce.verifier');
    sessionStorage.removeItem('authflowlab.pkce.state');
    sessionStorage.removeItem('authflowlab.pkce.nonce');
    setTokens(null);
    setResult(null);
    setMessage('Logged out locally.');
  }

  return (
    <main className="shell">
      <section className="panel login-panel">
        <div>
          <p className="eyebrow">OAuth2 / OIDC</p>
          <h1>AuthFlowLab</h1>
        </div>

        <label>
          Username
          <input value={username} onChange={(event) => setUsername(event.target.value)} />
        </label>

        <label>
          Password
          <input
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            type="password"
          />
        </label>

        <div className="actions">
          <button type="button" onClick={() => void login()}>
            Login with PKCE
          </button>
          <button type="button" className="secondary" onClick={logout}>
            Clear
          </button>
        </div>

        {message ? <p className="message">{message}</p> : null}
      </section>

      <section className="panel">
        <div className="section-title">
          <h2>Session</h2>
          <span className={tokens ? 'badge good' : 'badge'}>{tokens ? 'Authenticated' : 'Anonymous'}</span>
        </div>

        <dl className="claims">
          <div>
            <dt>Subject</dt>
            <dd>{stringClaim(idTokenPayload?.sub)}</dd>
          </div>
          <div>
            <dt>Name</dt>
            <dd>{stringClaim(idTokenPayload?.name)}</dd>
          </div>
          <div>
            <dt>Audience</dt>
            <dd>{stringClaim(idTokenPayload?.aud)}</dd>
          </div>
          <div>
            <dt>Scope</dt>
            <dd>{tokens?.scope ?? '-'}</dd>
          </div>
        </dl>

        <div className="actions">
          <button type="button" onClick={() => void callApi(`${apiServer}/content/read`, 'ApiServer /content/read')}>
            Call API
          </button>
          <button type="button" onClick={() => void callApi(`${authServer}/connect/userinfo`, 'AuthServer /connect/userinfo')}>
            UserInfo
          </button>
        </div>
      </section>

      <section className="panel output-panel">
        <h2>Result</h2>
        {result ? (
          <pre>{`${result.label}\nHTTP ${result.status}\n\n${formatBody(result.body)}`}</pre>
        ) : (
          <p className="empty">No API call yet.</p>
        )}
      </section>

      <section className="panel token-panel">
        <h2>Tokens</h2>
        <TokenBlock label="access_token" value={tokens?.access_token} />
        <TokenBlock label="id_token" value={tokens?.id_token} />
      </section>
    </main>
  );
}

async function completeLogin(
  setTokens: (tokens: TokenResponse | null) => void,
  setMessage: (message: string) => void
) {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const returnedState = params.get('state');
  const expectedState = sessionStorage.getItem('authflowlab.pkce.state');
  const verifier = sessionStorage.getItem('authflowlab.pkce.verifier');
  const expectedNonce = sessionStorage.getItem('authflowlab.pkce.nonce');

  if (!code || !verifier || !expectedState || returnedState !== expectedState) {
    setMessage('Callback validation failed.');
    window.history.replaceState({}, document.title, '/');
    return;
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier
  });

  const response = await fetch(`${authServer}/connect/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body
  });

  if (!response.ok) {
    setMessage(`Token exchange failed: HTTP ${response.status}`);
    window.history.replaceState({}, document.title, '/');
    return;
  }

  const tokenResponse = (await response.json()) as TokenResponse;
  const idTokenPayload = tokenResponse.id_token ? decodeJwtPayload(tokenResponse.id_token) : null;
  if (idTokenPayload?.nonce !== expectedNonce) {
    setMessage('Nonce validation failed.');
    window.history.replaceState({}, document.title, '/');
    return;
  }

  localStorage.setItem('authflowlab.tokens', JSON.stringify(tokenResponse));
  setTokens(tokenResponse);
  setMessage('Login completed.');
  window.history.replaceState({}, document.title, '/');
}

function TokenBlock({ label, value }: { label: string; value?: string }) {
  return (
    <div className="token-block">
      <h3>{label}</h3>
      <pre>{value ?? '-'}</pre>
    </div>
  );
}

async function createCodeChallenge(verifier: string) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(bytes: Uint8Array) {
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const [, payload] = token.split('.');
  if (!payload) {
    return null;
  }

  const padded = payload.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(payload.length / 4) * 4, '=');
  return JSON.parse(atob(padded)) as Record<string, unknown>;
}

function readJson<T>(key: string): T | null {
  const value = localStorage.getItem(key);
  return value ? (JSON.parse(value) as T) : null;
}

function stringClaim(value: unknown) {
  if (Array.isArray(value)) {
    return value.join(', ');
  }

  return typeof value === 'string' || typeof value === 'number' ? String(value) : '-';
}

function formatBody(body: string) {
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
