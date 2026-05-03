using System.Text.Json.Serialization;

namespace AuthFlowLab.AuthServer.Models;

public sealed record AuthErrorResponse(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string ErrorDescription);
