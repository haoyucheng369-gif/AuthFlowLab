using AuthFlowLab.AuthServer.Models;
using AuthFlowLab.AuthServer.Options;
using AuthFlowLab.AuthServer.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthFlowLab.AuthServer.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly JwtService _jwtService;
    private readonly AuthOptions _authOptions;

    public AuthController(JwtService jwtService, IOptions<AuthOptions> authOptions)
    {
        _jwtService = jwtService;
        _authOptions = authOptions.Value;
    }

    [HttpPost("login")]
    public IActionResult Login(LoginRequest request)
    {
        var user = _authOptions.Users.FirstOrDefault(user =>
            user.Username == request.Username && user.Password == request.Password);

        if (user is null)
        {
            return Unauthorized(new AuthErrorResponse(
                "invalid_grant",
                "The username or password is invalid."));
        }

        return Ok(_jwtService.GenerateUserToken(user.Username, user.Role, user.Scopes));
    }

    [HttpPost("client-token")]
    public IActionResult ClientToken(ClientTokenRequest request)
    {
        var client = _authOptions.Clients.FirstOrDefault(client =>
            client.ClientId == request.ClientId && client.ClientSecret == request.ClientSecret);

        if (client is null)
        {
            return Unauthorized(new AuthErrorResponse(
                "invalid_client",
                "The client id or secret is invalid."));
        }

        var requestedScopes = string.IsNullOrWhiteSpace(request.Scope)
            ? client.Scopes
            : request.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

        if (requestedScopes.Any(scope => !client.Scopes.Contains(scope, StringComparer.Ordinal)))
        {
            return BadRequest(new AuthErrorResponse(
                "invalid_scope",
                "The requested scope is not allowed for this client."));
        }

        return Ok(_jwtService.GenerateServiceToken(client.ClientId, requestedScopes));
    }
}
