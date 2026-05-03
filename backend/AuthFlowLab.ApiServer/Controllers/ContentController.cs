using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthFlowLab.ApiServer.Controllers;

[ApiController]
[Route("content")]
public class ContentController : ControllerBase
{
    // 匿名接口：不需要 token，适合验证 API 是否活着。
    [HttpGet("public")]
    [AllowAnonymous]
    public IActionResult Public()
        => Ok("Public content");

    // 基础认证接口：只要 token 有效即可，不检查 role/scope。
    [HttpGet("user")]
    [Authorize]
    public IActionResult UserContent()
        => Ok("User or authenticated service content");

    // 角色授权：要求 token 里有 role=Admin。
    [HttpGet("admin")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminContent()
        => Ok("Admin content");

    // scope 授权：要求 token 里包含 content.read。
    [HttpGet("read")]
    [Authorize(Policy = "ContentRead")]
    public IActionResult ReadContent()
        => Ok("Content read allowed");

    // 更细粒度的写权限：普通 user 没有 content.write，会得到 403。
    [HttpPost("write")]
    [Authorize(Policy = "ContentWrite")]
    public IActionResult WriteContent()
        => Ok("Content write allowed");

    // 服务调用授权：要求 token_type=service，用户 token 不能访问。
    [HttpGet("service")]
    [Authorize(Policy = "ServiceOnly")]
    public IActionResult ServiceContent()
        => Ok("Service-only content");
}
