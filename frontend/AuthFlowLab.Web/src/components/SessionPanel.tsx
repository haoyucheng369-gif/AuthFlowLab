import { stringClaim } from '../format';

type SessionPanelProps = {
  idTokenPayload: Record<string, unknown> | null;
  scope?: string;
  isAuthenticated: boolean;
  onCallApi: () => void;
  onUserInfo: () => void;
};

export function SessionPanel({
  idTokenPayload,
  scope,
  isAuthenticated,
  onCallApi,
  onUserInfo
}: SessionPanelProps) {
  return (
    <section className="card">
      <div className="card-header">
        <h2>Session</h2>
        <span className={isAuthenticated ? 'status status-success' : 'status'}>{isAuthenticated ? 'Authenticated' : 'Anonymous'}</span>
      </div>

      <dl className="claim-list">
        {/* 中文注释: 这些字段来自 id_token，表示“谁登录了”，不是 API 授权结果。 */}
        <ClaimItem label="Subject" value={stringClaim(idTokenPayload?.sub)} />
        <ClaimItem label="Name" value={stringClaim(idTokenPayload?.name)} />
        <ClaimItem label="Audience" value={stringClaim(idTokenPayload?.aud)} />
        <ClaimItem label="Scope" value={scope ?? '-'} />
      </dl>

      <div className="button-row">
        {/* 中文注释: 下面两个请求都会携带 access_token，浏览器会因为 Authorization header 先发 CORS preflight。 */}
        <button type="button" className="btn btn-primary" onClick={onCallApi}>
          Call API
        </button>
        <button type="button" className="btn btn-primary" onClick={onUserInfo}>
          UserInfo
        </button>
      </div>
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
