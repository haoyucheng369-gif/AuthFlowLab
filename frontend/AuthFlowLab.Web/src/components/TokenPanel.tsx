import { stringClaim } from '../format';

type TokenPanelProps = {
  accessToken?: string;
  accessTokenPayload: Record<string, unknown> | null;
  idToken?: string;
  idTokenPayload: Record<string, unknown> | null;
  provider?: 'local' | 'entra';
};

export function TokenPanel({
  accessToken,
  accessTokenPayload,
  idToken,
  idTokenPayload,
  provider
}: TokenPanelProps) {
  return (
    <section className="card content-card">
      <h2>Token Inspector</h2>

      {/* 这里解码浏览器当前持有的 JWT，帮助对比本地 IdP token 和 Entra ID token 的 issuer、audience、scope。 */}
      <dl className="claim-list">
        <ClaimItem label="Provider" value={provider ?? inferProvider(accessTokenPayload)} />
        <ClaimItem label="Issuer" value={stringClaim(accessTokenPayload?.iss)} />
        <ClaimItem label="Audience" value={stringClaim(accessTokenPayload?.aud)} />
        <ClaimItem label="Subject" value={stringClaim(accessTokenPayload?.sub ?? idTokenPayload?.sub)} />
        <ClaimItem label="Scopes" value={stringClaim(accessTokenPayload?.scp ?? accessTokenPayload?.scope)} />
        <ClaimItem label="Roles" value={stringClaim(accessTokenPayload?.roles ?? accessTokenPayload?.role)} />
        <ClaimItem label="Expires" value={formatUnixTime(accessTokenPayload?.exp)} />
        <ClaimItem label="Token Use" value={idToken ? 'access_token + id_token' : accessToken ? 'access_token' : '-'} />
      </dl>

      <TokenBlock label="access_token" value={accessToken} />
      <TokenBlock label="id_token" value={idToken} />
    </section>
  );
}

function ClaimItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="claim-item">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function TokenBlock({ label, value }: { label: string; value?: string }) {
  return (
    <div className="token-block">
      <h3>{label}</h3>
      <pre>{value ?? '-'}</pre>
    </div>
  );
}

function inferProvider(payload: Record<string, unknown> | null) {
  // 根据 issuer 粗略推断 token 来自 Entra ID 还是本地 AuthServer；最终安全判断仍由 API Server 的 JWT 验证完成。
  const issuer = stringClaim(payload?.iss);
  if (issuer.startsWith('https://login.microsoftonline.com/') || issuer.startsWith('https://sts.windows.net/')) {
    return 'entra';
  }

  return issuer === '-' ? '-' : 'local';
}

function formatUnixTime(value: unknown) {
  if (typeof value !== 'number') {
    return '-';
  }

  return `${new Date(value * 1000).toLocaleString()} (${value})`;
}
