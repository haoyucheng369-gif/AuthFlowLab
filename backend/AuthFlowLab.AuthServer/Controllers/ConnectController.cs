using System.Security.Cryptography;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthFlowLab.AuthServer.Models;
using AuthFlowLab.AuthServer.Options;
using AuthFlowLab.AuthServer.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthFlowLab.AuthServer.Controllers;

[ApiController]
[Route("connect")]
public class ConnectController : ControllerBase
{
    private const string ClientCredentialsGrantType = "client_credentials";
    private const string AuthorizationCodeGrantType = "authorization_code";
    private const string CodeResponseType = "code";
    private const string S256CodeChallengeMethod = "S256";

    private readonly JwtService _jwtService;
    private readonly IConfiguration _configuration;
    private readonly RsaKeyService _rsaKeyService;
    private readonly AuthorizationCodeStore _authorizationCodeStore;
    private readonly AuthOptions _authOptions;

    public ConnectController(
        JwtService jwtService,
        IConfiguration configuration,
        RsaKeyService rsaKeyService,
        AuthorizationCodeStore authorizationCodeStore,
        IOptions<AuthOptions> authOptions)
    {
        _jwtService = jwtService;
        _configuration = configuration;
        _rsaKeyService = rsaKeyService;
        _authorizationCodeStore = authorizationCodeStore;
        _authOptions = authOptions.Value;
    }

    [HttpGet("authorize")]
    public IActionResult Authorize(
        [FromQuery(Name = "response_type")] string? responseType,
        [FromQuery(Name = "client_id")] string? clientId,
        [FromQuery(Name = "redirect_uri")] string? redirectUri,
        [FromQuery(Name = "scope")] string? scope,
        [FromQuery(Name = "state")] string? state,
        [FromQuery] string? nonce,
        [FromQuery(Name = "code_challenge")] string? codeChallenge,
        [FromQuery(Name = "code_challenge_method")] string? codeChallengeMethod)
    {
        /*
         * Authorization Code + PKCE has two server-side steps.
         *
         * Step 1: /connect/authorize
         * - The browser/front-end sends client_id, redirect_uri, scope, state, nonce, and code_challenge.
         * - AuthServer validates the registered client and redirect_uri.
         * - AuthServer authenticates the user with its own login page and cookie.
         * - AuthServer creates a short-lived one-time code and stores the PKCE code_challenge
         *   together with that code.
         * - AuthServer redirects back to redirect_uri with code and state.
         *
         * The code_challenge is not client configuration. It is per-login temporary data.
         */
        if (responseType != CodeResponseType)
        {
            return BadRequest(new AuthErrorResponse("unsupported_response_type", "Only response_type=code is supported."));
        }

        var client = FindClient(clientId);
        if (client is null || !client.AllowedGrantTypes.Contains(AuthorizationCodeGrantType, StringComparer.Ordinal))
        {
            return BadRequest(new AuthErrorResponse("unauthorized_client", "The client cannot use authorization_code."));
        }

        if (string.IsNullOrWhiteSpace(redirectUri) ||
            !client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
        {
            return BadRequest(new AuthErrorResponse("invalid_request", "The redirect_uri is invalid."));
        }

        if (string.IsNullOrWhiteSpace(codeChallenge) || codeChallengeMethod != S256CodeChallengeMethod)
        {
            return BadRequest(new AuthErrorResponse("invalid_request", "PKCE S256 code_challenge is required."));
        }

        if (User.Identity?.IsAuthenticated != true)
        {
            // 中文注释: 未登录时跳转到 Auth Server 登录页，保留原始 authorize URL 作为登录后的 returnUrl。
            var returnUrl = Request.PathBase + Request.Path + Request.QueryString;
            var loginUrl = QueryHelpers.AddQueryString("/account/login", "returnUrl", returnUrl);
            return Redirect(loginUrl);
        }

        var username = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue(ClaimTypes.Name);
        var user = _authOptions.Users.FirstOrDefault(user => user.Username == username);
        if (user is null)
        {
            return Unauthorized(new AuthErrorResponse("invalid_grant", "The signed-in user is no longer valid."));
        }

        // 中文注释: scope 同时受用户权限和客户端注册权限约束，OIDC scope 不等同于 API 权限。
        var requestedScopes = ResolveRequestedScopes(scope, user.Scopes);
        if (requestedScopes.Contains("openid", StringComparer.Ordinal) && string.IsNullOrWhiteSpace(nonce))
        {
            return BadRequest(new AuthErrorResponse("invalid_request", "OIDC requests with openid scope require nonce."));
        }

        if (requestedScopes.Any(requestedScope => !IsScopeAllowedForUser(user, requestedScope)) ||
            requestedScopes.Any(requestedScope => !client.Scopes.Contains(requestedScope, StringComparer.Ordinal)))
        {
            return BadRequest(new AuthErrorResponse("invalid_scope", "The requested scope is not allowed for this user or client."));
        }

        // 中文注释: 授权码只保存服务端状态，浏览器地址栏只拿到一次性 code 和原始 state。
        var code = _authorizationCodeStore.Create(
            client.ClientId,
            redirectUri,
            user.Username,
            user.Role,
            requestedScopes,
            codeChallenge,
            codeChallengeMethod,
            nonce);

        var callback = QueryHelpers.AddQueryString(redirectUri, new Dictionary<string, string?>
        {
            ["code"] = code,
            ["state"] = state
        });

        return Redirect(callback);
    }

    [HttpGet("userinfo")]
    public IActionResult UserInfo()
    {
        /*
         * OIDC userinfo is a user profile endpoint.
         * The client calls it with an access_token, not with id_token.
         */
        var principal = ValidateAccessTokenFromAuthorizationHeader();
        if (principal is null)
        {
            return Unauthorized(new AuthErrorResponse("invalid_token", "A valid bearer access token is required."));
        }

        var subject = principal.FindFirstValue(JwtRegisteredClaimNames.Sub) ??
            principal.FindFirstValue(ClaimTypes.NameIdentifier);
        var name = principal.FindFirstValue(ClaimTypes.Name) ??
            principal.FindFirstValue(JwtRegisteredClaimNames.Name) ??
            subject;
        var role = principal.FindFirstValue(ClaimTypes.Role);

        return Ok(new
        {
            sub = subject,
            name,
            role
        });
    }

    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public IActionResult Token(
        [FromForm(Name = "grant_type")] string? grantType,
        [FromForm(Name = "client_id")] string? clientId,
        [FromForm(Name = "client_secret")] string? clientSecret,
        [FromForm(Name = "scope")] string? scope,
        [FromForm] string? code,
        [FromForm(Name = "redirect_uri")] string? redirectUri,
        [FromForm(Name = "code_verifier")] string? codeVerifier)
    {
        if (string.IsNullOrWhiteSpace(grantType))
        {
            return BadRequest(new AuthErrorResponse(
                "invalid_request",
                "The grant_type form field is required."));
        }

        // 中文注释: token endpoint 同时承载服务身份的 client_credentials 和用户登录后的 authorization_code。
        return grantType switch
        {
            ClientCredentialsGrantType => HandleClientCredentials(clientId, clientSecret, scope),
            AuthorizationCodeGrantType => HandleAuthorizationCode(clientId, code, redirectUri, codeVerifier),
            _ => BadRequest(new AuthErrorResponse(
                "unsupported_grant_type",
                "Only client_credentials and authorization_code are supported by this token endpoint."))
        };
    }

    private IActionResult HandleClientCredentials(string? clientId, string? clientSecret, string? scope)
    {
        var client = _authOptions.Clients.FirstOrDefault(client =>
            client.ClientId == clientId && client.ClientSecret == clientSecret);

        if (client is null)
        {
            return Unauthorized(new AuthErrorResponse(
                "invalid_client",
                "The client id or secret is invalid."));
        }

        if (!client.AllowedGrantTypes.Contains(ClientCredentialsGrantType, StringComparer.Ordinal))
        {
            return BadRequest(new AuthErrorResponse(
                "unauthorized_client",
                "The client is not allowed to use the requested grant type."));
        }

        var requestedScopes = ResolveRequestedScopes(scope, client.Scopes);
        if (requestedScopes.Any(requestedScope => !client.Scopes.Contains(requestedScope, StringComparer.Ordinal)))
        {
            return BadRequest(new AuthErrorResponse(
                "invalid_scope",
                "The requested scope is not allowed for this client."));
        }

        // 中文注释: client_credentials 发的是服务 token，不代表任何用户。
        return Ok(_jwtService.GenerateServiceToken(client.ClientId, requestedScopes));
    }

    private IActionResult HandleAuthorizationCode(
        string? clientId,
        string? code,
        string? redirectUri,
        string? codeVerifier)
    {
        /*
         * Step 2: /connect/token with grant_type=authorization_code
         * - The client sends the code from step 1 plus the original code_verifier.
         * - AuthServer consumes the code, so the same code cannot be reused.
         * - AuthServer verifies that the code belongs to the same client_id and redirect_uri.
         * - AuthServer hashes code_verifier and compares it with the saved code_challenge.
         * - Only after all checks pass does AuthServer issue a user access token.
         *
         * This is why stealing only the authorization code is not enough: the attacker also
         * needs the private code_verifier that was kept by the client.
         */
        var client = FindClient(clientId);
        if (client is null || !client.AllowedGrantTypes.Contains(AuthorizationCodeGrantType, StringComparer.Ordinal))
        {
            return BadRequest(new AuthErrorResponse("unauthorized_client", "The client cannot use authorization_code."));
        }

        if (string.IsNullOrWhiteSpace(code) ||
            !_authorizationCodeStore.TryConsume(code, out var authorizationCode) ||
            authorizationCode is null)
        {
            return BadRequest(new AuthErrorResponse("invalid_grant", "The authorization code is invalid or expired."));
        }

        if (authorizationCode.ClientId != client.ClientId || authorizationCode.RedirectUri != redirectUri)
        {
            return BadRequest(new AuthErrorResponse("invalid_grant", "The authorization code does not match the client request."));
        }

        if (string.IsNullOrWhiteSpace(codeVerifier) || !ValidatePkce(codeVerifier, authorizationCode))
        {
            return BadRequest(new AuthErrorResponse("invalid_grant", "The PKCE code_verifier is invalid."));
        }

        // 中文注释: code、redirect_uri、client_id、PKCE 全部校验后，才签发用户 access_token/id_token。
        return Ok(_jwtService.GenerateUserToken(
            authorizationCode.Username,
            authorizationCode.Role,
            authorizationCode.Scopes,
            authorizationCode.ClientId,
            authorizationCode.Nonce));
    }

    private AuthClient? FindClient(string? clientId)
    {
        return _authOptions.Clients.FirstOrDefault(client => client.ClientId == clientId);
    }

    private static List<string> ResolveRequestedScopes(string? scope, IReadOnlyCollection<string> defaultScopes)
    {
        return string.IsNullOrWhiteSpace(scope)
            ? defaultScopes.ToList()
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }

    private static bool IsScopeAllowedForUser(AuthUser user, string requestedScope)
    {
        return requestedScope is "openid" or "profile" ||
            user.Scopes.Contains(requestedScope, StringComparer.Ordinal);
    }

    private static bool ValidatePkce(string codeVerifier, AuthorizationCodeRecord authorizationCode)
    {
        /*
         * PKCE S256 check:
         *   code_challenge = BASE64URL(SHA256(code_verifier))
         *
         * The authorize request saved code_challenge with the temporary code.
         * The token request proves it owns the original code_verifier.
         */
        if (authorizationCode.CodeChallengeMethod != S256CodeChallengeMethod)
        {
            return false;
        }

        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        var computedChallenge = Base64UrlEncoder.Encode(hash);

        return computedChallenge == authorizationCode.CodeChallenge;
    }

    private ClaimsPrincipal? ValidateAccessTokenFromAuthorizationHeader()
    {
        var authorization = Request.Headers["Authorization"].ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var token = authorization["Bearer ".Length..].Trim();
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var handler = new JwtSecurityTokenHandler();
        try
        {
            // 中文注释: UserInfo 复用本 Auth Server 的签名公钥验证 access_token，避免信任未验证的 JWT 内容。
            return handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = (_configuration["Jwt:Issuer"] ?? "http://127.0.0.1:5001").TrimEnd('/'),
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"] ?? "api-server",
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _rsaKeyService.CreateJsonWebKey(),
                RoleClaimType = ClaimTypes.Role
            }, out _);
        }
        catch
        {
            return null;
        }
    }
}
