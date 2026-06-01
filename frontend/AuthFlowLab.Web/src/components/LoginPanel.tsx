type LoginPanelProps = {
  message: string;
  onLogin: () => void;
  onEntraLogin: () => void;
  onBffLogin: () => void;
  onLogout: () => void;
};

export function LoginPanel({
  message,
  onLogin,
  onEntraLogin,
  onBffLogin,
  onLogout
}: LoginPanelProps) {
  return (
    <section className="card login-card">
      <div>
        <p className="eyebrow">OAuth2 / OIDC</p>
        <h1>AuthFlowLab</h1>
      </div>

      <p className="muted">
        Compare browser token storage with a BFF session that keeps the access token on the server.
      </p>

      <div className="button-row">
        <button type="button" className="btn btn-primary" onClick={onLogin}>
          Local Login
        </button>
        <button type="button" className="btn btn-primary" onClick={onEntraLogin}>
          Entra Login
        </button>
        <button type="button" className="btn btn-primary" onClick={onBffLogin}>
          BFF Login
        </button>
        <button type="button" className="btn btn-outline" onClick={onLogout}>
          Logout
        </button>
      </div>

      {message ? <p className="alert">{message}</p> : null}
    </section>
  );
}
