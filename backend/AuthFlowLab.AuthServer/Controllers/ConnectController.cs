using AuthFlowLab.AuthServer.Models;
using AuthFlowLab.AuthServer.Options;
using AuthFlowLab.AuthServer.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthFlowLab.AuthServer.Controllers;

[ApiController]
[Route("connect")]
public class ConnectController : ControllerBase
{
    private const string ClientCredentialsGrantType = "client_credentials";

    private readonly JwtService _jwtService;
    private readonly AuthOptions _authOptions;

    public ConnectController(JwtService jwtService, IOptions<AuthOptions> authOptions)
    {
        _jwtService = jwtService;
        _authOptions = authOptions.Value;
    }

    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public IActionResult Token(
        [FromForm(Name = "grant_type")] string? grantType,
        [FromForm(Name = "client_id")] string? clientId,
        [FromForm(Name = "client_secret")] string? clientSecret,
        [FromForm(Name = "scope")] string? scope)
    {
        // OAuth2 token endpoint 必须通过 grant_type 指明“用哪种方式换 token”。
        if (string.IsNullOrWhiteSpace(grantType))
        {
            return BadRequest(new AuthErrorResponse(
                "invalid_request",
                "The grant_type form field is required."));
        }

        // 当前阶段只实现 client_credentials；authorization_code + PKCE 后续再加。
        if (grantType != ClientCredentialsGrantType)
        {
            return BadRequest(new AuthErrorResponse(
                "unsupported_grant_type",
                "Only client_credentials is supported by this token endpoint."));
        }

        // client_credentials 认证的是“系统/服务客户端”，不是最终用户。
        var client = _authOptions.Clients.FirstOrDefault(client =>
            client.ClientId == clientId && client.ClientSecret == clientSecret);

        if (client is null)
        {
            // client_id 或 client_secret 错误属于客户端认证失败。
            return Unauthorized(new AuthErrorResponse(
                "invalid_client",
                "The client id or secret is invalid."));
        }

        // 同一个 client 未来可能允许不同 grant type，这里先校验它是否允许 client_credentials。
        if (!client.AllowedGrantTypes.Contains(ClientCredentialsGrantType, StringComparer.Ordinal))
        {
            return BadRequest(new AuthErrorResponse(
                "unauthorized_client",
                "The client is not allowed to use the requested grant type."));
        }

        // scope 是客户端申请访问 API 的权限范围；未传时使用该 client 默认允许的全部 scope。
        var requestedScopes = string.IsNullOrWhiteSpace(scope)
            ? client.Scopes
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

        // AuthServer 必须拒绝 client 配置中没有预先允许的 scope。
        if (requestedScopes.Any(requestedScope => !client.Scopes.Contains(requestedScope, StringComparer.Ordinal)))
        {
            return BadRequest(new AuthErrorResponse(
                "invalid_scope",
                "The requested scope is not allowed for this client."));
        }

        // 认证和授权范围校验都通过后，签发 service token 给系统调用 API。
        return Ok(_jwtService.GenerateServiceToken(client.ClientId, requestedScopes));
    }
}
