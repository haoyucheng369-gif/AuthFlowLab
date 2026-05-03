namespace AuthFlowLab.AuthServer.Options;

public sealed class AuthOptions
{
    // access_token 有效期，单位是分钟；JwtService 会转换成 expires_in 秒数返回。
    public int AccessTokenMinutes { get; init; } = 30;

    // 实验阶段使用配置文件模拟用户库；真实系统通常来自数据库或 ASP.NET Core Identity。
    public List<AuthUser> Users { get; init; } = [];

    // OAuth2 client 注册表；每个 client 预先声明 grant type 和允许申请的 scope。
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

    // 实验用明文 secret；真实系统应存储哈希或放在安全密钥系统中。
    public string ClientSecret { get; init; } = "";

    // 控制该 client 能用哪些 OAuth2 授权方式换 token。
    public List<string> AllowedGrantTypes { get; init; } = [];

    // 控制该 client 最多能申请哪些 API 访问范围。
    public List<string> Scopes { get; init; } = [];
}
