import { authServer, clientId, redirectUri, scope, storageKeys } from './config';
import type { TokenResponse } from './types';

export async function startLogin() {
  // 中文注释: SPA 只生成 PKCE 参数并跳转 authorize，不收集也不传递用户密码。
  const verifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = await createCodeChallenge(verifier);
  const state = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
  const nonce = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));

  sessionStorage.setItem(storageKeys.verifier, verifier);
  sessionStorage.setItem(storageKeys.state, state);
  sessionStorage.setItem(storageKeys.nonce, nonce);

  // 中文注释: state/nonce/verifier 留在浏览器本地，回调时用于防重放和校验 id_token。
  const authorizeUrl = new URL(`${authServer}/connect/authorize`);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', clientId);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('scope', scope);
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('nonce', nonce);
  authorizeUrl.searchParams.set('code_challenge', challenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');

  window.location.assign(authorizeUrl.toString());
}

export async function completeLoginCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const returnedState = params.get('state');
  const expectedState = sessionStorage.getItem(storageKeys.state);
  const verifier = sessionStorage.getItem(storageKeys.verifier);
  const expectedNonce = sessionStorage.getItem(storageKeys.nonce);

  // 中文注释: 先移除 URL 中的一次性 code，避免 React 开发模式重复执行 effect 时再次换 token。
  window.history.replaceState({}, document.title, '/');

  // 中文注释: state 必须和登录前保存的一致，否则拒绝继续换 token。
  if (!code || !verifier || !expectedState || returnedState !== expectedState) {
    throw new Error('Callback validation failed.');
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier
  });

  // 中文注释: authorization code 不能直接当 token 用，必须和 code_verifier 一起提交给 token endpoint。
  const response = await fetch(`${authServer}/connect/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed: HTTP ${response.status}`);
  }

  const tokenResponse = (await response.json()) as TokenResponse;
  const idTokenPayload = tokenResponse.id_token ? decodeJwtPayload(tokenResponse.id_token) : null;

  // 中文注释: nonce 用来确认 id_token 属于这次登录请求，不是旧登录响应被重放。
  if (idTokenPayload?.nonce !== expectedNonce) {
    throw new Error('Nonce validation failed.');
  }

  // 中文注释: demo 为了便于观察把 token 存 localStorage；生产 SPA 需要额外评估 XSS 风险。
  localStorage.setItem(storageKeys.tokens, JSON.stringify(tokenResponse));
  return tokenResponse;
}

export function clearSession() {
  localStorage.removeItem(storageKeys.tokens);
  sessionStorage.removeItem(storageKeys.verifier);
  sessionStorage.removeItem(storageKeys.state);
  sessionStorage.removeItem(storageKeys.nonce);
}

export function readTokens() {
  return readJson<TokenResponse>(storageKeys.tokens);
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const [, payload] = token.split('.');
  if (!payload) {
    return null;
  }

  const padded = payload.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(payload.length / 4) * 4, '=');
  return JSON.parse(atob(padded)) as Record<string, unknown>;
}

async function createCodeChallenge(verifier: string) {
  // 中文注释: PKCE S256 = BASE64URL(SHA256(code_verifier))。
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(bytes: Uint8Array) {
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function readJson<T>(key: string): T | null {
  const value = localStorage.getItem(key);
  return value ? (JSON.parse(value) as T) : null;
}
