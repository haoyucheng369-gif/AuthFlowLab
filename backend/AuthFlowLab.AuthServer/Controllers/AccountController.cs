using System.Security.Claims;
using System.Text.Encodings.Web;
using AuthFlowLab.AuthServer.Models;
using AuthFlowLab.AuthServer.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthFlowLab.AuthServer.Controllers;

[Route("account")]
public sealed class AccountController : Controller
{
    private const string EntraExternalScheme = "Entra";

    private readonly AuthOptions _authOptions;
    private readonly EntraExternalLoginOptions _entraExternalLoginOptions;
    private readonly HtmlEncoder _htmlEncoder;

    public AccountController(
        IOptions<AuthOptions> authOptions,
        IOptions<EntraExternalLoginOptions> entraExternalLoginOptions,
        HtmlEncoder htmlEncoder)
    {
        _authOptions = authOptions.Value;
        _entraExternalLoginOptions = entraExternalLoginOptions.Value;
        _htmlEncoder = htmlEncoder;
    }

    [HttpGet("login")]
    public IActionResult Login([FromQuery] string? returnUrl = null)
    {
        //  登录页由 Auth Server 自己展示，SPA 不再收集或传递用户密码。
        return Content(RenderLoginPage(returnUrl, null), "text/html; charset=utf-8");
    }

    [HttpPost("login")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> LoginPost(
        [FromForm] string username,
        [FromForm] string password,
        [FromForm] string? returnUrl = null)
    {
        var user = _authOptions.Users.FirstOrDefault(user =>
            user.Username == username && user.Password == password);

        if (user is null)
        {
            //  登录页认证失败时只重新显示表单，不把密码写入 URL 或日志。
            return Content(RenderLoginPage(returnUrl, "The username or password is invalid."), "text/html; charset=utf-8");
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Username),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Role, user.Role)
        };

        foreach (var scope in user.Scopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        //  登录成功只写入 HttpOnly cookie；真正给 SPA 的 token 仍然要走 /connect/token。
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));

        return LocalRedirect(SanitizeReturnUrl(returnUrl));
    }

    [HttpPost("external-login")]
    [Consumes("application/x-www-form-urlencoded")]
    public IActionResult ExternalLogin(
        [FromForm] string provider,
        [FromForm] string? returnUrl = null)
    {
        // 外部登录入口只接受当前支持的 Entra provider，并且必须先确认配置完整。
        if (!IsEntraLoginEnabled() || provider != EntraExternalScheme)
        {
            return NotFound();
        }

        // 外部登录只负责认证企业用户；回调成功后仍然写入 Auth Server 自己的登录 cookie。
        return Challenge(
            new AuthenticationProperties
            {
                RedirectUri = SanitizeReturnUrl(returnUrl)
            },
            EntraExternalScheme);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/account/login");
    }

    private string RenderLoginPage(string? returnUrl, string? error)
    {
        var encodedReturnUrl = _htmlEncoder.Encode(SanitizeReturnUrl(returnUrl));
        var encodedError = error is null ? string.Empty : _htmlEncoder.Encode(error);
        var errorMarkup = error is null ? string.Empty : $"<div class=\"alert\">{encodedError}</div>";
        // 只有 Entra SSO 可用时才渲染 Microsoft 登录按钮，本地开发默认只显示本地账号登录。
        var externalLoginMarkup = IsEntraLoginEnabled()
            ? $$"""
    <div class="divider"><span>or</span></div>
    <form method="post" action="/account/external-login">
      <input type="hidden" name="provider" value="Entra">
      <input type="hidden" name="returnUrl" value="{{encodedReturnUrl}}">
      <button type="submit" class="btn-external">Sign in with Microsoft</button>
    </form>
"""
            : string.Empty;

        return $$"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AuthFlowLab Login</title>
  <style>
    :root {
      color: #212529;
      background: #f8f9fa;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    * { box-sizing: border-box; }
    body { display: grid; min-height: 100vh; place-items: center; margin: 0; padding: 1rem; }
    main { width: min(100%, 380px); border: 1px solid #dee2e6; border-radius: .5rem; background: #fff; padding: 1.25rem; box-shadow: 0 .125rem .25rem rgba(0,0,0,.075); }
    h1 { margin: 0 0 1rem; font-size: 1.5rem; }
    label { display: grid; gap: .375rem; margin-bottom: .875rem; color: #343a40; font-size: .875rem; font-weight: 600; }
    input { width: 100%; border: 1px solid #ced4da; border-radius: .375rem; padding: .5rem .75rem; font: inherit; }
    input:focus { border-color: #86b7fe; outline: 0; box-shadow: 0 0 0 .25rem rgba(13,110,253,.25); }
    button { width: 100%; border: 1px solid #0d6efd; border-radius: .375rem; padding: .5rem .75rem; color: #fff; background: #0d6efd; font: inherit; font-weight: 600; cursor: pointer; }
    button:hover { background: #0b5ed7; }
    .btn-external { border-color: #495057; background: #fff; color: #212529; }
    .btn-external:hover { background: #e9ecef; }
    .divider { display: flex; align-items: center; gap: .75rem; margin: 1rem 0; color: #6c757d; font-size: .8125rem; }
    .divider::before, .divider::after { content: ""; flex: 1; height: 1px; background: #dee2e6; }
    .eyebrow { margin: 0 0 .25rem; color: #6c757d; font-size: .75rem; font-weight: 700; text-transform: uppercase; }
    .alert { margin-bottom: .875rem; border: 1px solid #f5c2c7; border-radius: .375rem; padding: .625rem .75rem; color: #842029; background: #f8d7da; font-size: .875rem; }
  </style>
</head>
<body>
  <main>
    <p class="eyebrow">Auth Server</p>
    <h1>Sign in</h1>
    {{errorMarkup}}
    <form method="post" action="/account/login">
      <input type="hidden" name="returnUrl" value="{{encodedReturnUrl}}">
      <label>
        Username
        <input name="username" autocomplete="username" required>
      </label>
      <label>
        Password
        <input name="password" type="password" autocomplete="current-password" required>
      </label>
      <button type="submit">Continue</button>
    </form>
{{externalLoginMarkup}}
  </main>
</body>
</html>
""";
    }

    private string SanitizeReturnUrl(string? returnUrl)
    {
        //  只允许回跳到本站路径，避免登录后被恶意 returnUrl 带到外部网站。
        return Url.IsLocalUrl(returnUrl) ? returnUrl! : "/";
    }

    private bool IsEntraLoginEnabled()
    {
        // 只有 Entra 外部登录配置完整时才显示 SSO 入口，避免本地开发缺少 Azure 配置时误触发跳转。
        return _entraExternalLoginOptions.Enabled &&
            !string.IsNullOrWhiteSpace(_entraExternalLoginOptions.Authority) &&
            !string.IsNullOrWhiteSpace(_entraExternalLoginOptions.ClientId) &&
            !string.IsNullOrWhiteSpace(_entraExternalLoginOptions.ClientSecret);
    }
}
