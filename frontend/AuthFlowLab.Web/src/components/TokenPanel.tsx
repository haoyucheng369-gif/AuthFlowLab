type TokenPanelProps = {
  accessToken?: string;
  idToken?: string;
};

export function TokenPanel({ accessToken, idToken }: TokenPanelProps) {
  return (
    <section className="card content-card">
      <h2>Tokens</h2>
      {/* 中文注释: access_token 给 API 用；id_token 给 SPA 识别用户用。 */}
      <TokenBlock label="access_token" value={accessToken} />
      <TokenBlock label="id_token" value={idToken} />
    </section>
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
