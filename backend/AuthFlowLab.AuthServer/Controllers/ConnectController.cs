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
        if (string.IsNullOrWhiteSpace(grantType))
        {
            return BadRequest(new AuthErrorResponse(
                "invalid_request",
                "The grant_type form field is required."));
        }

        if (grantType != ClientCredentialsGrantType)
        {
            return BadRequest(new AuthErrorResponse(
                "unsupported_grant_type",
                "Only client_credentials is supported by this token endpoint."));
        }

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

        var requestedScopes = string.IsNullOrWhiteSpace(scope)
            ? client.Scopes
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

        if (requestedScopes.Any(requestedScope => !client.Scopes.Contains(requestedScope, StringComparer.Ordinal)))
        {
            return BadRequest(new AuthErrorResponse(
                "invalid_scope",
                "The requested scope is not allowed for this client."));
        }

        return Ok(_jwtService.GenerateServiceToken(client.ClientId, requestedScopes));
    }
}
