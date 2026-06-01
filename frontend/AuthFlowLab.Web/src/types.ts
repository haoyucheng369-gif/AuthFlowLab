export type TokenResponse = {
  provider?: 'local' | 'entra';
  access_token: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
  scope: string;
};

export type CallResult = {
  label: string;
  status: number;
  body: string;
};

export type BffSessionResponse = {
  authenticated: boolean;
  scope: string;
  expiresAt: string;
  csrfToken: string;
};
