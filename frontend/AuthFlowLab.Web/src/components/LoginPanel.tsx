type LoginPanelProps = {
  message: string;
  onLogin: () => void;
  onClear: () => void;
};

export function LoginPanel({
  message,
  onLogin,
  onClear
}: LoginPanelProps) {
  return (
    <section className="card login-card">
      <div>
        <p className="eyebrow">OAuth2 / OIDC</p>
        <h1>AuthFlowLab</h1>
      </div>

      <p className="muted">
        {/* 中文注释: 前端只启动 OAuth/OIDC 登录，用户名密码在 Auth Server 登录页输入。 */}
        Sign in on the Auth Server. The SPA only starts the PKCE authorization request.
      </p>

      <div className="button-row">
        <button type="button" className="btn btn-primary" onClick={onLogin}>
          Login with PKCE
        </button>
        <button type="button" className="btn btn-outline" onClick={onClear}>
          Clear
        </button>
      </div>

      {message ? <p className="alert">{message}</p> : null}
    </section>
  );
}
