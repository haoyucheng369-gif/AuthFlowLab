import { useEffect, useMemo, useState } from 'react';
import { apiServer, authServer } from './config';
import { clearSession, completeLoginCallback, decodeJwtPayload, readTokens, startLogin } from './auth';
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

  useEffect(() => {
    if (window.location.pathname !== '/callback') {
      return;
    }

    // 中文注释: 登录回调只在应用层处理一次，组件只展示状态。
    void completeLoginCallback()
      .then((tokenResponse) => {
        setTokens(tokenResponse);
        setMessage('Login completed.');
      })
      .catch((error: Error) => setMessage(error.message));
  }, []);

  async function handleLogin() {
    setMessage('');
    setResult(null);
    await startLogin();
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
        onLogin={() => void handleLogin()}
      />

      <SessionPanel
        idTokenPayload={idTokenPayload}
        scope={tokens?.scope}
        isAuthenticated={Boolean(tokens)}
        onCallApi={() => void callApi(`${apiServer}/content/read`, 'ApiServer /content/read')}
        onUserInfo={() => void callApi(`${authServer}/connect/userinfo`, 'AuthServer /connect/userinfo')}
      />

      <ResultPanel result={result} />
      <TokenPanel accessToken={tokens?.access_token} idToken={tokens?.id_token} />
    </main>
  );
}
