import { useEffect, useMemo, useState } from 'react';
import { apiServer, authServer, bffServer } from './config';
import {
  decodeJwtPayload,
  getApiToken,
  getGraphAccessToken,
  initializeAuthState,
  logoutBffSession,
  logoutSession,
  readBffSession,
  readTokens,
  startBffLogin,
  startEntraLogin,
  startLogin
} from './auth';
import { LoginPanel } from './components/LoginPanel';
import { ResultPanel } from './components/ResultPanel';
import { SessionPanel } from './components/SessionPanel';
import { TokenPanel } from './components/TokenPanel';
import type { BffSessionResponse, CallResult, TokenResponse } from './types';

export function App() {
  const [tokens, setTokens] = useState<TokenResponse | null>(() => readTokens());
  const [bffSession, setBffSession] = useState<BffSessionResponse | null>(null);
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<CallResult | null>(null);

  const idTokenPayload = useMemo(() => {
    return tokens?.id_token ? decodeJwtPayload(tokens.id_token) : null;
  }, [tokens]);

  const accessTokenPayload = useMemo(() => {
    return tokens?.access_token ? decodeJwtPayload(tokens.access_token) : null;
  }, [tokens]);

  useEffect(() => {
    // 页面加载后检查 BFF 的 HttpOnly cookie，用独立状态表示服务端 token 会话。
    void readBffSession()
      .then((session) => {
        if (session) {
          setBffSession(session);
          setMessage('BFF session ready.');
        }
      })
      .catch((error: Error) => setMessage(error.message));
  }, []);

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

  function handleBffLogin() {
    setMessage('');
    setResult(null);
    startBffLogin();
  }

  async function callApi(path: string, label: string, method = 'GET') {
    // BFF 模式统一走服务端代理；写请求额外携带 CSRF token。
    if (bffSession) {
      const bffPath = path === `${apiServer}/content/read`
        ? '/bff/content/read'
        : path === `${apiServer}/content/me`
          ? '/bff/content/me'
          : '/bff/content/write';
      const response = await fetch(`${bffServer}${bffPath}`, {
        method,
        credentials: 'include',
        headers: method === 'POST'
          ? { 'X-CSRF-TOKEN': bffSession.csrfToken }
          : undefined
      });
      setResult({
        label: `BFF ${bffPath} -> ${label}`,
        status: response.status,
        body: await response.text()
      });
      return;
    }

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
    if (bffSession) {
      const response = await fetch(`${bffServer}/bff/userinfo`, {
        credentials: 'include'
      });
      setResult({
        label: 'BFF /bff/userinfo -> AuthServer /connect/userinfo',
        status: response.status,
        body: await response.text()
      });
      return;
    }

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

  async function logout() {
    // Logout 同时清除 SPA token、Auth Server cookie 和 BFF 服务端 token session。
    await logoutBffSession();
    await logoutSession();
    setTokens(null);
    setBffSession(null);
    setResult(null);
    setMessage('Logged out.');
  }

  const browserTokens = bffSession ? null : tokens;
  const browserIdTokenPayload = bffSession ? null : idTokenPayload;
  const browserAccessTokenPayload = bffSession ? null : accessTokenPayload;

  return (
    <main className="app-shell">
      <LoginPanel
        message={message}
        onLogout={() => void logout()}
        onBffLogin={handleBffLogin}
        onEntraLogin={() => void handleEntraLogin()}
        onLogin={() => void handleLogin()}
      />

      {/* Claims 按钮会调用 /content/me，查看 token 在 API 中被解析成哪些 Identity 和 Claims。 */}
      <SessionPanel
        accessTokenPayload={browserAccessTokenPayload}
        idTokenPayload={browserIdTokenPayload}
        provider={bffSession ? 'bff' : tokens?.provider}
        serverSideScope={bffSession?.scope}
        isAuthenticated={Boolean(bffSession ?? tokens)}
        onCallApi={() => void callApi(`${apiServer}/content/read`, 'ApiServer /content/read')}
        onCallClaims={() => void callApi(`${apiServer}/content/me`, 'ApiServer /content/me')}
        onCallWriteApi={() => void callApi(`${apiServer}/content/write`, 'ApiServer /content/write', 'POST')}
        onUserInfo={() => void callUserInfo()}
      />

      <ResultPanel result={result} />
      <TokenPanel
        accessToken={browserTokens?.access_token}
        accessTokenPayload={browserAccessTokenPayload}
        idToken={browserTokens?.id_token}
        idTokenPayload={browserIdTokenPayload}
        provider={browserTokens?.provider}
      />
    </main>
  );
}
