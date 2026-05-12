import { stringClaim } from '../format';

type SessionPanelProps = {
  accessTokenPayload: Record<string, unknown> | null;
  idTokenPayload: Record<string, unknown> | null;
  provider?: 'local' | 'entra';
  isAuthenticated: boolean;
  onCallApi: () => void;
  onCallWriteApi: () => void;
  onUserInfo: () => void;
};

export function SessionPanel({
  accessTokenPayload,
  idTokenPayload,
  provider,
  isAuthenticated,
  onCallApi,
  onCallWriteApi,
  onUserInfo
}: SessionPanelProps) {
  return (
    <section className="card">
      <div className="card-header">
        <h2>Session</h2>
        <span className={isAuthenticated ? 'status status-success' : 'status'}>{isAuthenticated ? 'Authenticated' : 'Anonymous'}</span>
      </div>

      <dl className="claim-list">
        <ClaimItem label="Provider" value={provider ?? '-'} />
        <ClaimItem label="Subject" value={stringClaim(idTokenPayload?.sub ?? accessTokenPayload?.sub)} />
        <ClaimItem label="Name" value={stringClaim(idTokenPayload?.name ?? accessTokenPayload?.name)} />
        <ClaimItem label="ID Token Audience" value={stringClaim(idTokenPayload?.aud)} />
        <ClaimItem label="Access Token Issuer" value={stringClaim(accessTokenPayload?.iss)} />
        <ClaimItem label="Access Token Audience" value={stringClaim(accessTokenPayload?.aud)} />
        <ClaimItem label="Access Token Scope" value={stringClaim(accessTokenPayload?.scp ?? accessTokenPayload?.scope)} />
      </dl>

      <div className="button-row">
        <button type="button" className="btn btn-primary" onClick={onCallApi}>
          Call Read API
        </button>
        <button type="button" className="btn btn-primary" onClick={onCallWriteApi}>
          Call Write API
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
