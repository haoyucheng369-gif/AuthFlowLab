using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
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
    public async Task Health_ReturnsHealthy()
    {
        var response = await _client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task UserContent_RequiresAuthenticatedCaller()
    {
        var response = await _client.GetAsync("/content/user");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task MeContent_ReturnsCurrentPrincipalClaims()
    {
        UseBearerToken(_factory.CreateToken("user", tokenType: "user", role: "User", scope: "content.read"));

        var response = await _client.GetAsync("/content/me");
        var content = await response.Content.ReadAsStringAsync();

        Assert.True(response.IsSuccessStatusCode, content);

        using var document = JsonDocument.Parse(content);
        var root = document.RootElement;
        Assert.True(root.GetProperty("authentication").GetProperty("isAuthenticated").GetBoolean());

        var claims = root.GetProperty("claims");
        Assert.Equal("user", claims.GetProperty(JwtRegisteredClaimNames.Sub).GetString());
        Assert.Equal("content.read", claims.GetProperty("scope").GetString());
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
    public async Task ReadContent_AllowsEntraStyleScopeClaim()
    {
        UseBearerToken(_factory.CreateToken("entra-user", tokenType: "user", scp: "access_as_user"));

        var response = await _client.GetAsync("/content/read");
        var content = await response.Content.ReadAsStringAsync();

        Assert.True(response.IsSuccessStatusCode, content);
        Assert.Equal("Content read allowed", content);
    }

    [Fact]
    public async Task ReadContent_AllowsEntraJwtBearerToken()
    {
        // 中文注释：这个 token 使用 Entra issuer/audience 和独立签名 key，只配置给 EntraJwt scheme。
        // 如果请求成功，说明 SmartBearer 正确分流到了 EntraJwt，而不是误走 LocalJwt。
        UseBearerToken(_factory.CreateEntraToken("entra-user", scp: "access_as_user"));

        var response = await _client.GetAsync("/content/read");
        var content = await response.Content.ReadAsStringAsync();

        Assert.True(response.IsSuccessStatusCode, content);
        Assert.Equal("Content read allowed", content);
    }

    [Fact]
    public async Task WriteContent_RejectsUserWithoutContentWriteScope()
    {
        UseBearerToken(_factory.CreateToken("user", tokenType: "user", role: "User", scope: "content.read"));

        var response = await _client.PostAsync("/content/write", content: null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task WriteContent_AllowsAdminWithContentWriteScope()
    {
        UseBearerToken(_factory.CreateToken("admin", tokenType: "user", role: "Admin", scope: "content.read content.write"));

        var response = await _client.PostAsync("/content/write", content: null);
        var content = await response.Content.ReadAsStringAsync();

        Assert.True(response.IsSuccessStatusCode, content);
        Assert.Equal("Content write allowed", content);
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

    [Fact]
    public async Task WriteContent_AllowsServiceWithContentWriteScope()
    {
        UseBearerToken(_factory.CreateToken("worker-service", tokenType: "service", scope: "content.read content.write"));

        var response = await _client.PostAsync("/content/write", content: null);
        var content = await response.Content.ReadAsStringAsync();

        Assert.True(response.IsSuccessStatusCode, content);
        Assert.Equal("Content write allowed", content);
    }

    [Fact]
    public async Task ApiKeyContent_RequiresApiKey()
    {
        var response = await _client.GetAsync("/content/api-key");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ApiKeyContent_RejectsInvalidApiKey()
    {
        _client.DefaultRequestHeaders.Add("X-Api-Key", "wrong-key");

        var response = await _client.GetAsync("/content/api-key");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ApiKeyContent_AllowsValidApiKey()
    {
        _client.DefaultRequestHeaders.Add("X-Api-Key", "test-api-key");

        var content = await _client.GetStringAsync("/content/api-key");

        Assert.Equal("API key content", content);
    }

    private void UseBearerToken(string token)
    {
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }
}

public sealed class ApiServerFactory : WebApplicationFactory<Program>
{
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly RSA _entraRsa = RSA.Create(2048);

    public ApiServerFactory()
    {
    }

    public string CreateToken(string subject, string tokenType, string? role = null, string? scope = null, string? scp = null)
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

        if (scp is not null)
        {
            claims.Add(new Claim("scp", scp));
        }

        var token = new JwtSecurityToken(
            issuer: "http://auth-flow-lab.test",
            audience: "api-server",
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(10),
            signingCredentials: new SigningCredentials(new RsaSecurityKey(_rsa)
            {
                KeyId = "test-key"
            }, SecurityAlgorithms.RsaSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string CreateEntraToken(string subject, string scp)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subject),
            new("scp", scp),
            new("name", "Entra Test User")
        };

        // 中文注释：这里模拟 Entra ID access token 的关键字段，重点覆盖 issuer、audience 和 scp。
        var token = new JwtSecurityToken(
            issuer: "https://login.microsoftonline.com/976c3c85-e425-4880-a658-3653df9cebf2/v2.0",
            audience: "api://b5b7fdde-0835-4e46-863d-463b1432e9f7",
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(10),
            signingCredentials: new SigningCredentials(new RsaSecurityKey(_entraRsa)
            {
                KeyId = "entra-test-key"
            }, SecurityAlgorithms.RsaSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseContentRoot(FindProjectDirectory("AuthFlowLab.ApiServer"));
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Authority"] = "http://auth-flow-lab.test",
                ["Jwt:Audience"] = "api-server",
                ["Jwt:RequireHttpsMetadata"] = "false",
                ["Jwt:Entra:Authority"] = "https://login.microsoftonline.com/976c3c85-e425-4880-a658-3653df9cebf2/v2.0",
                ["Jwt:Entra:Audience"] = "api://b5b7fdde-0835-4e46-863d-463b1432e9f7",
                ["Jwt:Entra:ClientId"] = "b5b7fdde-0835-4e46-863d-463b1432e9f7",
                ["Jwt:Entra:TenantId"] = "976c3c85-e425-4880-a658-3653df9cebf2",
                ["ApiKeys:Keys:0:Name"] = "test-tool",
                ["ApiKeys:Keys:0:Value"] = "test-api-key"
            });
        });

        builder.ConfigureServices(services =>
        {
            services.PostConfigure<JwtBearerOptions>("LocalJwt", options =>
            {
                var signingKey = new RsaSecurityKey(_rsa)
                {
                    KeyId = "test-key"
                };

                options.Configuration = new OpenIdConnectConfiguration
                {
                    Issuer = "http://auth-flow-lab.test"
                };

                options.Configuration.SigningKeys.Add(signingKey);
                options.TokenValidationParameters.IssuerSigningKey = signingKey;
                options.TokenValidationParameters.TryAllIssuerSigningKeys = true;
            });

            services.PostConfigure<JwtBearerOptions>("EntraJwt", options =>
            {
                var signingKey = new RsaSecurityKey(_entraRsa)
                {
                    KeyId = "entra-test-key"
                };

                // 中文注释：测试环境不访问 Microsoft discovery endpoint，直接注入模拟的 Entra JWKS 配置。
                options.Configuration = new OpenIdConnectConfiguration
                {
                    Issuer = "https://login.microsoftonline.com/976c3c85-e425-4880-a658-3653df9cebf2/v2.0"
                };

                options.Configuration.SigningKeys.Add(signingKey);
                options.TokenValidationParameters.IssuerSigningKey = signingKey;
                options.TokenValidationParameters.TryAllIssuerSigningKeys = true;
            });
        });
    }

    private static string FindProjectDirectory(
        string projectName,
        [CallerFilePath] string sourceFilePath = "")
    {
        var startDirectories = new[]
        {
            Directory.GetCurrentDirectory(),
            AppContext.BaseDirectory,
            Path.GetDirectoryName(sourceFilePath) ?? Directory.GetCurrentDirectory()
        };

        foreach (var startDirectory in startDirectories)
        {
            var directory = new DirectoryInfo(startDirectory);
            while (directory is not null)
            {
                var projectDirectory = Path.Combine(directory.FullName, "backend", projectName);
                if (File.Exists(Path.Combine(projectDirectory, $"{projectName}.csproj")))
                {
                    return projectDirectory;
                }

                directory = directory.Parent;
            }
        }

        throw new DirectoryNotFoundException($"Could not find project directory for {projectName}.");
    }
}
