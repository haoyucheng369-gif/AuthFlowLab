using System.Text.Json.Serialization;

namespace AuthFlowLab.Bff.Models;

// 登录跳转前暂存一次性 state 和 PKCE verifier，回调成功后立即消费，避免授权码回调被重复使用。
public sealed record BffLoginState(string CodeVerifier, DateTimeOffset ExpiresAt);

// 浏览器只持有随机 session id；access token 保存在 BFF 内存中，不暴露给前端 JavaScript。
public sealed record BffSession(
    string AccessToken,
    string Scope,
    DateTimeOffset ExpiresAt,
    string CsrfToken);

// BFF 使用该模型解析 Auth Server 的 token endpoint 返回值。
public sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("expires_in")] int ExpiresIn);
