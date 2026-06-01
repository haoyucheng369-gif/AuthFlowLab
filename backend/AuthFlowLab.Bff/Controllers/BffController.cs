using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using AuthFlowLab.Bff.Models;
using AuthFlowLab.Bff.Options;
using AuthFlowLab.Bff.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthFlowLab.Bff.Controllers;

[ApiController]
[Route("bff")]
public sealed class BffController : ControllerBase
{
    private const string CsrfHeaderName = "X-CSRF-TOKEN";
    private readonly BffOptions _options;
    private readonly BffSessionStore _sessionStore;
    private readonly IHttpClientFactory _httpClientFactory;

    public BffController(
        IOptions<BffOptions> options,
        BffSessionStore sessionStore,
        IHttpClientFactory httpClientFactory)
    {
        _options = options.Value;
        _sessionStore = sessionStore;
        _httpClientFactory = httpClientFactory;
    }

    [HttpGet("login")]
    public IActionResult Login()
    {
        // BFF 自己生成并保存 PKCE verifier，浏览器只负责跟随重定向，不保存 OAuth token。
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var state = _sessionStore.CreateLoginState(verifier);
        var nonce = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16));

        var authorizeUrl = QueryHelpers.AddQueryString(
            $"{_options.AuthServerPublicUrl.TrimEnd('/')}/connect/authorize",
            new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["client_id"] = _options.ClientId,
                ["redirect_uri"] = _options.CallbackUrl,
                ["scope"] = _options.Scope,
                ["state"] = state,
                ["nonce"] = nonce,
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256"
            });

        return Redirect(authorizeUrl);
    }

    [HttpGet("callback")]
    public async Task<IActionResult> Callback([FromQuery] string? code, [FromQuery] string? state)
    {
        // callback 必须消费一次性 state，再由 BFF 服务端携带 secret 和 PKCE verifier 换 token。
        if (string.IsNullOrWhiteSpace(code) ||
            string.IsNullOrWhiteSpace(state) ||
            !_sessionStore.TryConsumeLoginState(state, out var loginState) ||
            loginState is null)
        {
            return BadRequest(new { error = "invalid_callback" });
        }

        var authServer = _httpClientFactory.CreateClient("AuthServer");
        var response = await authServer.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = _options.ClientId,
            ["client_secret"] = _options.ClientSecret,
            ["code"] = code,
            ["redirect_uri"] = _options.CallbackUrl,
            ["code_verifier"] = loginState.CodeVerifier
        }));

        if (!response.IsSuccessStatusCode)
        {
            return StatusCode((int)response.StatusCode, await response.Content.ReadAsStringAsync());
        }

        var token = await response.Content.ReadFromJsonAsync<TokenResponse>();
        if (token is null)
        {
            return StatusCode(StatusCodes.Status502BadGateway, new { error = "invalid_token_response" });
        }

        var sessionId = _sessionStore.CreateSession(token);
        Response.Cookies.Append(
            _options.SessionCookieName,
            sessionId,
            CreateSessionCookieOptions(token.ExpiresIn));

        return Redirect(_options.FrontendUrl);
    }

    [HttpGet("session")]
    public IActionResult Session()
    {
        // 只返回页面需要的会话摘要和 CSRF token，不把服务端保存的 access_token 泄露给前端。
        return TryGetCurrentSession(out var session)
            ? Ok(new { authenticated = true, session.Scope, session.ExpiresAt, session.CsrfToken })
            : Unauthorized(new { authenticated = false });
    }

    [HttpGet("content/read")]
    public Task<IActionResult> ReadContent()
        => ProxyApiRequest(HttpMethod.Get, "/content/read");

    [HttpGet("content/me")]
    public Task<IActionResult> ReadClaims()
        => ProxyApiRequest(HttpMethod.Get, "/content/me");

    [HttpPost("content/write")]
    public Task<IActionResult> WriteContent()
    {
        // Cookie 会被浏览器自动携带，因此写请求必须额外校验前端显式发送的 CSRF token。
        return ProxyApiRequest(HttpMethod.Post, "/content/write", requireCsrfToken: true);
    }

    [HttpGet("userinfo")]
    public Task<IActionResult> UserInfo()
        => ProxyRequest("AuthServer", HttpMethod.Get, "/connect/userinfo");

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        // 退出时删除服务端 token session，并让浏览器删除只保存 session id 的 HttpOnly cookie。
        Request.Cookies.TryGetValue(_options.SessionCookieName, out var sessionId);
        _sessionStore.RemoveSession(sessionId);
        Response.Cookies.Delete(_options.SessionCookieName);
        return NoContent();
    }

    private Task<IActionResult> ProxyApiRequest(HttpMethod method, string path, bool requireCsrfToken = false)
        => ProxyRequest("ApiServer", method, path, requireCsrfToken);

    private async Task<IActionResult> ProxyRequest(
        string clientName,
        HttpMethod method,
        string path,
        bool requireCsrfToken = false)
    {
        // BFF 根据 cookie 找到服务端 token，再代理调用 Auth Server 或资源 API。
        if (!TryGetCurrentSession(out var session))
        {
            return Unauthorized();
        }

        if (requireCsrfToken && !HasValidCsrfToken(session.CsrfToken))
        {
            return BadRequest(new { error = "invalid_csrf_token" });
        }

        var client = _httpClientFactory.CreateClient(clientName);
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session.AccessToken);
        using var response = await client.SendAsync(request);

        return new ContentResult
        {
            Content = await response.Content.ReadAsStringAsync(),
            ContentType = response.Content.Headers.ContentType?.ToString() ?? "text/plain; charset=utf-8",
            StatusCode = (int)response.StatusCode
        };
    }

    private bool HasValidCsrfToken(string expectedToken)
    {
        var providedToken = Request.Headers[CsrfHeaderName].ToString();
        if (string.IsNullOrWhiteSpace(providedToken))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(providedToken),
            Encoding.UTF8.GetBytes(expectedToken));
    }

    private bool TryGetCurrentSession(out BffSession session)
    {
        Request.Cookies.TryGetValue(_options.SessionCookieName, out var sessionId);
        return _sessionStore.TryGetSession(sessionId, out session!);
    }

    private CookieOptions CreateSessionCookieOptions(int expiresIn)
    {
        // 本地 HTTP 测试允许非 Secure；部署到 HTTPS 后自动写入 Secure cookie。
        return new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = Request.IsHttps,
            Expires = DateTimeOffset.UtcNow.AddSeconds(expiresIn)
        };
    }
}
