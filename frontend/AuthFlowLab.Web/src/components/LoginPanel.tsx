type LoginPanelProps = {
  message: string;
  onLogin: () => void;
  onEntraLogin: () => void;
  onClear: () => void;
};

export function LoginPanel({
  message,
  onLogin,
  onEntraLogin,
  onClear
}: LoginPanelProps) {
  return (
    <section className="card login-card">
      <div>
        <p className="eyebrow">OAuth2 / OIDC</p>
        <h1>AuthFlowLab</h1>
      </div>

      <p className="muted">
        Sign in with the local lab IdP or Entra ID. The SPA starts the authorization request and stores demo tokens locally.
      </p>

      <div className="button-row">
        <button type="button" className="btn btn-primary" onClick={onLogin}>
          Local Login
        </button>
        <button type="button" className="btn btn-primary" onClick={onEntraLogin}>
          Entra Login
        </button>
        <button type="button" className="btn btn-outline" onClick={onClear}>
          Clear
        </button>
      </div>

      {message ? <p className="alert">{message}</p> : null}
    </section>
  );
}
