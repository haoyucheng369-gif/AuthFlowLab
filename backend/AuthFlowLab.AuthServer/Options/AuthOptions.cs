namespace AuthFlowLab.AuthServer.Options;

public sealed class AuthOptions
{
    public int AccessTokenMinutes { get; init; } = 30;

    public List<AuthUser> Users { get; init; } = [];

    public List<AuthClient> Clients { get; init; } = [];
}

public sealed class AuthUser
{
    public string Username { get; init; } = "";

    public string Password { get; init; } = "";

    public string Role { get; init; } = "";

    public List<string> Scopes { get; init; } = [];
}

public sealed class AuthClient
{
    public string ClientId { get; init; } = "";

    public string ClientSecret { get; init; } = "";

    public List<string> Scopes { get; init; } = [];
}
