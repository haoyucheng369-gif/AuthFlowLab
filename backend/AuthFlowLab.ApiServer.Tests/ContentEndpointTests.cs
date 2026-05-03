using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace AuthFlowLab.ApiServer.Tests;

public sealed class ContentEndpointTests : IClassFixture<ApiServerFactory>
{
    private readonly HttpClient _client;
    private readonly ApiServerFactory _factory;

    public ContentEndpointTests(ApiServerFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task PublicContent_AllowsAnonymous()
    {
        var content = await _client.GetStringAsync("/content/public");

        Assert.Equal("Public content", content);
    }

    [Fact]
    public async Task UserContent_RequiresAuthenticatedCaller()
    {
        var response = await _client.GetAsync("/content/user");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ReadContent_AllowsUserWithContentReadScope()
    {
        UseBearerToken(_factory.CreateToken("user", tokenType: "user", role: "User", scope: "content.read"));

        var response = await _client.GetAsync("/content/read");
        var challenge = string.Join(", ", response.Headers.WwwAuthenticate.Select(value => value.ToString()));
        var content = await response.Content.ReadAsStringAsync();

        Assert.True(response.IsSuccessStatusCode, $"{response.StatusCode}: {challenge} {content}");
        Assert.Equal("Content read allowed", content);
    }

    [Fact]
    public async Task AdminContent_RequiresAdminRole()
    {
        UseBearerToken(_factory.CreateToken("user", tokenType: "user", role: "User", scope: "content.read"));

        var response = await _client.GetAsync("/content/admin");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ServiceContent_RequiresServiceToken()
    {
        UseBearerToken(_factory.CreateToken("worker-service", tokenType: "service", scope: "content.read"));

        var content = await _client.GetStringAsync("/content/service");

        Assert.Equal("Service-only content", content);
    }

    private void UseBearerToken(string token)
    {
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }
}

public sealed class ApiServerFactory : WebApplicationFactory<Program>
{
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly string _publicKeyPath;

    public ApiServerFactory()
    {
        _publicKeyPath = Path.Combine(Path.GetTempPath(), $"auth-flow-lab-test-{Guid.NewGuid():N}.key");
        File.WriteAllText(_publicKeyPath, _rsa.ExportRSAPublicKeyPem());
        Environment.SetEnvironmentVariable("Jwt__PublicKeyPath", _publicKeyPath);
    }

    public string CreateToken(string subject, string tokenType, string? role = null, string? scope = null)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subject),
            new("token_type", tokenType)
        };

        if (role is not null)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        if (scope is not null)
        {
            claims.Add(new Claim("scope", scope));
        }

        var token = new JwtSecurityToken(
            issuer: "auth-flow-lab",
            audience: "api-server",
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(10),
            signingCredentials: new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:PublicKeyPath"] = _publicKeyPath
            });
        });
    }
}
