using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthFlowLab.ApiServer.Controllers;

[ApiController]
[Route("content")]
public class ContentController : ControllerBase
{
    // 匿名接口：不需要 token，适合验证 API 是否存活。
    [HttpGet("public")]
    [AllowAnonymous]
    public IActionResult Public()
        => Ok("Public content");

    // 基础认证接口：只要 token 有效即可，不检查 role/scope。
    [HttpGet("user")]
    [Authorize]
    public IActionResult UserContent()
        => Ok("User or authenticated service content");

    // 当前身份调试接口：返回 ASP.NET Core 认证后的 Identity 和 Claims，方便对比本地 JWT、Entra JWT、API Key 的差异。
    [HttpGet("me")]
    [Authorize]
    public IActionResult Me()
        => Ok(new
        {
            authentication = new
            {
                isAuthenticated = User.Identity?.IsAuthenticated ?? false,
                name = User.Identity?.Name,
                authenticationType = User.Identity?.AuthenticationType,
                identities = User.Identities.Select(identity => new
                {
                    identity.AuthenticationType,
                    identity.Name,
                    identity.IsAuthenticated
                })
            },
            claims = User.Claims
                .GroupBy(claim => claim.Type)
                .OrderBy(group => group.Key, StringComparer.Ordinal)
                .ToDictionary(
                    group => group.Key,
                    group => ToClaimValue(group
                        .Select(claim => claim.Value)
                        .Distinct(StringComparer.Ordinal)
                        .OrderBy(value => value, StringComparer.Ordinal)
                        .ToArray()))
        });

    // 角色授权：要求 token 里有 Admin role。
    [HttpGet("admin")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminContent()
        => Ok("Admin content");

    // scope 授权：本地 token 使用 scope，Entra token 使用 scp。
    [HttpGet("read")]
    [Authorize(Policy = "ContentRead")]
    public IActionResult ReadContent()
        => Ok("Content read allowed");

    // 更细粒度的写权限：普通 user 没有 write scope 时会得到 403。
    [HttpPost("write")]
    [Authorize(Policy = "ContentWrite")]
    public IActionResult WriteContent()
        => Ok("Content write allowed");

    // 服务调用授权：要求 token_type=service，普通用户 token 不能访问。
    [HttpGet("service")]
    [Authorize(Policy = "ServiceOnly")]
    public IActionResult ServiceContent()
        => Ok("Service-only content");

    // API Key 鉴权：不使用 JWT，也不走 AuthServer，ApiServer 直接校验 X-Api-Key。
    [HttpGet("api-key")]
    [Authorize(Policy = "ApiKeyOnly")]
    public IActionResult ApiKeyContent()
        => Ok("API key content");

    private static object ToClaimValue(string[] values)
        => values.Length == 1 ? values[0] : values;
}
