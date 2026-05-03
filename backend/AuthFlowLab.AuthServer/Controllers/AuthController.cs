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

}
