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
        // 认证阶段：校验用户提交的 username/password，确认调用方是谁。
        var user = _authOptions.Users.FirstOrDefault(user =>
            user.Username == request.Username && user.Password == request.Password);

        if (user is null)
        {
            // 用户名或密码错误属于认证失败，返回 401 + OAuth 风格错误码。
            return Unauthorized(new AuthErrorResponse(
                "invalid_grant",
                "The username or password is invalid."));
        }

        // 登录成功后，AuthServer 根据配置中的 role/scope 生成用户 access token。
        return Ok(_jwtService.GenerateUserToken(user.Username, user.Role, user.Scopes));
    }

}
