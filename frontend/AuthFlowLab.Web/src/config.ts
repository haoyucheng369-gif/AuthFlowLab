export const authServer = 'http://localhost:5001';
export const apiServer = 'http://localhost:5002';
export const bffServer = 'http://localhost:5003';

// Local AuthFlowLab IdP public client. SPA clients do not store client_secret.
export const clientId = 'demo-spa';
export const redirectUri = 'http://localhost:5173/callback';
export const scope = 'openid profile content.read content.write';

// Entra ID SPA registration and delegated API scope.
export const entra = {
  clientId: '35b46efc-ba76-4940-bc2a-a4fa1b904dcb',
  authority: 'https://login.microsoftonline.com/976c3c85-e425-4880-a658-3653df9cebf2/v2.0',
  redirectUri: 'http://localhost:5173/callback',
  // 当前 Azure API 只暴露 read scope；Direct Entra Login 暂时只请求读权限，避免缺少 write_as_user scope 导致登录失败。
  apiScopes: [
    'api://b5b7fdde-0835-4e46-863d-463b1432e9f7/access_as_user'
  ],
  graphScopes: ['User.Read']
} as const;

// Centralized storage keys keep browser state names consistent across components.
export const storageKeys = {
  tokens: 'authflowlab.tokens',
  verifier: 'authflowlab.pkce.verifier',
  state: 'authflowlab.pkce.state',
  nonce: 'authflowlab.pkce.nonce',
  provider: 'authflowlab.login.provider'
} as const;
