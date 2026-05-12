import { useEffect, useMemo, useState } from 'react';
import { apiServer, authServer } from './config';
import {
  clearSession,
  decodeJwtPayload,
  getApiToken,
  getGraphAccessToken,
  initializeAuthState,
  readTokens,
  startEntraLogin,
  startLogin
} from './auth';
import { LoginPanel } from './components/LoginPanel';
import { ResultPanel } from './components/ResultPanel';
import { SessionPanel } from './components/SessionPanel';
import { TokenPanel } from './components/TokenPanel';
import type { CallResult, TokenResponse } from './types';

export function App() {
  const [tokens, setTokens] = useState<TokenResponse | null>(() => readTokens());
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<CallResult | null>(null);

  const idTokenPayload = useMemo(() => {
    return tokens?.id_token ? decodeJwtPayload(tokens.id_token) : null;
  }, [tokens]);

  const accessTokenPayload = useMemo(() => {
    return tokens?.access_token ? decodeJwtPayload(tokens.access_token) : null;
  }, [tokens]);

  useEffect(() => {
    void initializeAuthState()
      .then((tokenResponse) => {
        if (tokenResponse) {
          setTokens(tokenResponse);
          setMessage(tokenResponse.provider === 'entra' ? 'Entra session ready.' : 'Login completed.');
        }
      })
      .catch((error: Error) => setMessage(error.message));
  }, []);

  useEffect(() => {
    const onFocus = () => {
      if (tokens) {
        return;
      }

      void initializeAuthState()
        .then((tokenResponse) => {
          if (tokenResponse) {
            setTokens(tokenResponse);
            setMessage(tokenResponse.provider === 'entra' ? 'Entra session ready.' : 'Login completed.');
          }
        })
        .catch((error: Error) => setMessage(error.message));
    };

    window.addEventListener('focus', onFocus);
    return () => {
      window.removeEventListener('focus', onFocus);
    };
  }, [tokens]);

  async function handleLogin() {
    setMessage('');
    setResult(null);
    await startLogin();
  }

  async function handleEntraLogin() {
    setMessage('');
    setResult(null);
    await startEntraLogin();
  }

  async function callApi(path: string, label: string, method = 'GET') {
    if (!tokens?.access_token) {
      setMessage('Login first.');
      return;
    }

    const currentTokens = await getApiToken(tokens);
    setTokens(currentTokens);

    const response = await fetch(path, {
      method,
      headers: {
        Authorization: `Bearer ${currentTokens.access_token}`
      }
    });

    const body = await response.text();
    const authenticateHeader = response.headers.get('www-authenticate');
    setResult({
      label,
      status: response.status,
      body: authenticateHeader ? `${body}\n\nWWW-Authenticate: ${authenticateHeader}` : body
    });
  }

  async function callUserInfo() {
    if (!tokens?.access_token) {
      setMessage('Login first.');
      return;
    }

    if (tokens.provider === 'entra') {
      const graphToken = await getGraphAccessToken();
      const response = await fetch('https://graph.microsoft.com/v1.0/me', {
        headers: {
          Authorization: `Bearer ${graphToken}`
        }
      });
      const body = await response.text();
      const authenticateHeader = response.headers.get('www-authenticate');
      setResult({
        label: 'Microsoft Graph /me',
        status: response.status,
        body: authenticateHeader ? `${body}\n\nWWW-Authenticate: ${authenticateHeader}` : body
      });
      return;
    }

    await callApi(`${authServer}/connect/userinfo`, 'AuthServer /connect/userinfo');
  }

  function logout() {
    clearSession();
    setTokens(null);
    setResult(null);
    setMessage('Logged out locally.');
  }

  return (
    <main className="app-shell">
      <LoginPanel
        message={message}
        onClear={logout}
        onEntraLogin={() => void handleEntraLogin()}
        onLogin={() => void handleLogin()}
      />

      <SessionPanel
        accessTokenPayload={accessTokenPayload}
        idTokenPayload={idTokenPayload}
        provider={tokens?.provider}
        isAuthenticated={Boolean(tokens)}
        onCallApi={() => void callApi(`${apiServer}/content/read`, 'ApiServer /content/read')}
        onCallWriteApi={() => void callApi(`${apiServer}/content/write`, 'ApiServer /content/write', 'POST')}
        onUserInfo={() => void callUserInfo()}
      />

      <ResultPanel result={result} />
      <TokenPanel accessToken={tokens?.access_token} idToken={tokens?.id_token} />
    </main>
  );
}
