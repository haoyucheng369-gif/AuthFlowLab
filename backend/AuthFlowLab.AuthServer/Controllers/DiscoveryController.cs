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

        return Ok(new
        {
            issuer,
            token_endpoint = $"{issuer}/connect/token",
            jwks_uri = $"{issuer}/.well-known/jwks.json",
            response_types_supported = Array.Empty<string>(),
            grant_types_supported = new[] { "client_credentials" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post" },
            scopes_supported = new[] { "content.read", "content.write" },
            claims_supported = new[] { "sub", "client_id", "scope", "token_type", "role", "name" },
            id_token_signing_alg_values_supported = new[] { "RS256" }
        });
    }

    [HttpGet("jwks.json")]
    public IActionResult Jwks()
    {
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
