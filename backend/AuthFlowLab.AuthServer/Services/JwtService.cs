using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthFlowLab.AuthServer.Models;
using AuthFlowLab.AuthServer.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthFlowLab.AuthServer.Services;

public class JwtService
{
    private readonly IConfiguration _configuration;
    private readonly AuthOptions _authOptions;
    private readonly RsaKeyService _rsaKeyService;

    public JwtService(
        IConfiguration configuration,
        IOptions<AuthOptions> authOptions,
        RsaKeyService rsaKeyService)
    {
        _configuration = configuration;
        _authOptions = authOptions.Value;
        _rsaKeyService = rsaKeyService;
    }

    public TokenResponse GenerateUserToken(string username, string role, IEnumerable<string> scopes)
    {
        // OAuth2 常见做法是把多个 scope 放在同一个 claim 中，用空格分隔。
        var scope = string.Join(' ', scopes);
        var claims = new List<Claim>
        {
            // sub 表示 token 的主体；用户 token 中就是用户名。
            new(JwtRegisteredClaimNames.Sub, username),
            // jti 是 token 唯一 ID，后续做撤销、审计或重放防护时会用到。
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            // iat 表示签发时间，使用 Unix epoch 秒。
            new(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64),
            new(ClaimTypes.Name, username),
            // role 是 ASP.NET Core [Authorize(Roles = "...")] 能直接识别的角色 claim。
            new(ClaimTypes.Role, role),
            new("scope", scope),
            // token_type 是本实验自定义 claim，用来区分 user token 和 service token。
            new("token_type", "user")
        };

        return GenerateToken(claims, scope);
    }

    public TokenResponse GenerateServiceToken(string clientId, IEnumerable<string> scopes)
    {
        var scope = string.Join(' ', scopes);
        var claims = new List<Claim>
        {
            // service token 的主体是 client_id，而不是用户。
            new(JwtRegisteredClaimNames.Sub, clientId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64),
            new("client_id", clientId),
            new("scope", scope),
            new("token_type", "service")
        };

        return GenerateToken(claims, scope);
    }

    private TokenResponse GenerateToken(List<Claim> claims, string scope)
    {
        // issuer/audience 是 ApiServer 验证 token 时必须匹配的信任边界。
        var issuer = _configuration["Jwt:Issuer"] ?? "http://127.0.0.1:5001";
        var audience = _configuration["Jwt:Audience"] ?? "api-server";
        var expiresIn = _authOptions.AccessTokenMinutes * 60;

        // RS256 = RSA 私钥签名 + SHA-256；签名凭证由 RsaKeyService 统一创建。
        var credentials = _rsaKeyService.CreateSigningCredentials();

        // payload 中放 claims，signature 由私钥生成；ApiServer 后续通过 JWKS 公钥验证 signature。
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.UtcNow.AddSeconds(expiresIn),
            signingCredentials: credentials
        );

        // 返回 OAuth2 风格 token response，access_token 才是调用 API 时放到 Authorization header 的值。
        return new TokenResponse(
            new JwtSecurityTokenHandler().WriteToken(token),
            "Bearer",
            expiresIn,
            scope);
    }
}
