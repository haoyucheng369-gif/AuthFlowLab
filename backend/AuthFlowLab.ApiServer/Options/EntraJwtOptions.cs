namespace AuthFlowLab.ApiServer.Options;

public sealed class EntraJwtOptions
{
    public string Authority { get; init; } = string.Empty;

    public string Audience { get; init; } = string.Empty;

    public string ClientId { get; init; } = string.Empty;

    public string TenantId { get; init; } = string.Empty;
}
