using System.Text.Json.Serialization;

namespace AuthFlowLab.AuthServer.Models;

// OAuth2 风格错误响应，便于前端和测试根据 error code 做稳定判断。
public sealed record AuthErrorResponse(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string ErrorDescription);
