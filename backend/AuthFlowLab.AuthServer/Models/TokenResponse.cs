using System.Text.Json.Serialization;

namespace AuthFlowLab.AuthServer.Models;

// OAuth2 token endpoint 的标准响应形状；JSON 字段名使用 snake_case。
public sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("scope")] string Scope);
