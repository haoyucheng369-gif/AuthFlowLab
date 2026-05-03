using AuthFlowLab.AuthServer.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthFlowLab.AuthServer.Controllers;

[ApiController]
[Route(".well-known")]
public sealed class DiscoveryController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly RsaKeyService _rsaKeyService;

    public DiscoveryController(IConfiguration configuration, RsaKeyService rsaKeyService)
    {
        _configuration = configuration;
        _rsaKeyService = rsaKeyService;
    }

    [HttpGet("openid-configuration")]
    public IActionResult OpenIdConfiguration()
    {
        var issuer = GetIssuer();

        // 中文注释: discovery 文档告诉客户端和 API：authorize/token/userinfo/JWKS 端点在哪里、支持哪些能力。
        return Ok(new
        {
            issuer,
            authorization_endpoint = $"{issuer}/connect/authorize",
            token_endpoint = $"{issuer}/connect/token",
            userinfo_endpoint = $"{issuer}/connect/userinfo",
            jwks_uri = $"{issuer}/.well-known/jwks.json",
            response_types_supported = new[] { "code" },
            grant_types_supported = new[] { "client_credentials", "authorization_code" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post", "none" },
            code_challenge_methods_supported = new[] { "S256" },
            scopes_supported = new[] { "openid", "profile", "content.read", "content.write" },
            claims_supported = new[] { "sub", "client_id", "scope", "token_type", "role", "name", "nonce" },
            id_token_signing_alg_values_supported = new[] { "RS256" }
        });
    }

    [HttpGet("jwks.json")]
    public IActionResult Jwks()
    {
        // 中文注释: JWKS 只暴露公钥参数，API Server 用它验证 JWT 签名，不需要 public.key 文件。
        return Ok(new
        {
            keys = new[] { _rsaKeyService.CreateJsonWebKey() }
        });
    }

    private string GetIssuer()
    {
        return (_configuration["Jwt:Issuer"] ?? $"{Request.Scheme}://{Request.Host}").TrimEnd('/');
    }
}
