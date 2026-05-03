using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AuthFlowLab.AuthServer.Models;
using AuthFlowLab.AuthServer.Options;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthFlowLab.AuthServer.Services;

public class JwtService
{
    private readonly IConfiguration _configuration;
    private readonly IWebHostEnvironment _environment;
    private readonly AuthOptions _authOptions;

    public JwtService(
        IConfiguration configuration,
        IWebHostEnvironment environment,
        IOptions<AuthOptions> authOptions)
    {
        _configuration = configuration;
        _environment = environment;
        _authOptions = authOptions.Value;
    }

    public TokenResponse GenerateUserToken(string username, string role, IEnumerable<string> scopes)
    {
        var scope = string.Join(' ', scopes);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, username),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64),
            new(ClaimTypes.Name, username),
            new(ClaimTypes.Role, role),
            new("scope", scope),
            new("token_type", "user")
        };

        return GenerateToken(claims, scope);
    }

    public TokenResponse GenerateServiceToken(string clientId, IEnumerable<string> scopes)
    {
        var scope = string.Join(' ', scopes);
        var claims = new List<Claim>
        {
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
        var issuer = _configuration["Jwt:Issuer"] ?? "auth-flow-lab";
        var audience = _configuration["Jwt:Audience"] ?? "api-server";
        var expiresIn = _authOptions.AccessTokenMinutes * 60;
        var privateKeyPath = _configuration["Jwt:PrivateKeyPath"]
            ?? throw new InvalidOperationException("Private key path is missing.");

        privateKeyPath = Path.IsPathRooted(privateKeyPath)
            ? privateKeyPath
            : Path.GetFullPath(privateKeyPath, _environment.ContentRootPath);

        var privateKey = File.ReadAllText(privateKeyPath);

        var rsa = RSA.Create();
        rsa.ImportFromPem(privateKey);

        var signingKey = new RsaSecurityKey(rsa);
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.UtcNow.AddSeconds(expiresIn),
            signingCredentials: credentials
        );

        return new TokenResponse(
            new JwtSecurityTokenHandler().WriteToken(token),
            "Bearer",
            expiresIn,
            scope);
    }
}
