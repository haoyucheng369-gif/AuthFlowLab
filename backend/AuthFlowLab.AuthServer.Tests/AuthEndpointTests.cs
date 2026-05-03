using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace AuthFlowLab.AuthServer.Tests;

public sealed class AuthEndpointTests : IClassFixture<AuthServerFactory>
{
    private readonly HttpClient _client;

    public AuthEndpointTests(AuthServerFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Login_Returns_UserToken()
    {
        var response = await _client.PostAsJsonAsync("/auth/login", new
        {
            username = "test-user",
            password = "user123"
        });

        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenResponse>();

        Assert.NotNull(token);
        Assert.Equal("Bearer", token.TokenType);
        Assert.Equal(600, token.ExpiresIn);
        Assert.Equal("content.read", token.Scope);
        Assert.False(string.IsNullOrWhiteSpace(token.AccessToken));
    }

    [Fact]
    public async Task Login_Returns_AdminWriteScope()
    {
        var response = await _client.PostAsJsonAsync("/auth/login", new
        {
            username = "test-admin",
            password = "admin123"
        });

        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenResponse>();

        Assert.Equal("content.read content.write", token?.Scope);
    }

    [Fact]
    public async Task Login_WithBadPassword_ReturnsInvalidGrant()
    {
        var response = await _client.PostAsJsonAsync("/auth/login", new
        {
            username = "test-user",
            password = "wrong"
        });

        var error = await response.Content.ReadFromJsonAsync<AuthErrorResponse>();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_grant", error?.Error);
    }

    [Fact]
    public async Task Token_WithClientCredentials_Returns_ServiceToken()
    {
        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "worker-service",
            ["client_secret"] = "worker-secret",
            ["scope"] = "content.read content.write"
        }));

        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenResponse>();

        Assert.NotNull(token);
        Assert.Equal("Bearer", token.TokenType);
        Assert.Equal("content.read content.write", token.Scope);
        Assert.False(string.IsNullOrWhiteSpace(token.AccessToken));
    }

    [Fact]
    public async Task Token_WithDisallowedScope_ReturnsInvalidScope()
    {
        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "worker-service",
            ["client_secret"] = "worker-secret",
            ["scope"] = "admin"
        }));

        var error = await response.Content.ReadFromJsonAsync<AuthErrorResponse>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_scope", error?.Error);
    }

    [Fact]
    public async Task Token_WithUnsupportedGrantType_ReturnsUnsupportedGrantType()
    {
        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "worker-service",
            ["client_secret"] = "worker-secret"
        }));

        var error = await response.Content.ReadFromJsonAsync<AuthErrorResponse>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("unsupported_grant_type", error?.Error);
    }

    [Fact]
    public async Task DeprecatedClientTokenEndpoint_ReturnsNotFound()
    {
        var response = await _client.PostAsJsonAsync("/auth/client-token", new
        {
            clientId = "worker-service",
            clientSecret = "worker-secret",
            scope = "content.read"
        });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Discovery_ReturnsMetadataForClientCredentials()
    {
        var document = await _client.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration");

        Assert.Equal("http://auth-flow-lab.test", document.GetProperty("issuer").GetString());
        Assert.Equal("http://auth-flow-lab.test/connect/token", document.GetProperty("token_endpoint").GetString());
        Assert.Equal("http://auth-flow-lab.test/.well-known/jwks.json", document.GetProperty("jwks_uri").GetString());
        Assert.Contains("client_credentials", document.GetProperty("grant_types_supported").EnumerateArray().Select(item => item.GetString()));
    }

    [Fact]
    public async Task Jwks_ReturnsPublicSigningKey()
    {
        var document = await _client.GetFromJsonAsync<JsonElement>("/.well-known/jwks.json");
        var key = document.GetProperty("keys").EnumerateArray().Single();

        Assert.Equal("auth-flow-lab-test-key", key.GetProperty("kid").GetString());
        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        Assert.Equal("RS256", key.GetProperty("alg").GetString());
        Assert.False(string.IsNullOrWhiteSpace(key.GetProperty("n").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(key.GetProperty("e").GetString()));
    }
}

public sealed class AuthServerFactory : WebApplicationFactory<Program>
{
    private readonly string _privateKeyPath;

    public AuthServerFactory()
    {
        using var rsa = RSA.Create(2048);
        _privateKeyPath = Path.Combine(Path.GetTempPath(), $"auth-flow-lab-test-{Guid.NewGuid():N}.key");
        File.WriteAllText(_privateKeyPath, rsa.ExportRSAPrivateKeyPem());
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseContentRoot(FindProjectDirectory("AuthFlowLab.AuthServer"));
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:PrivateKeyPath"] = _privateKeyPath,
                ["Jwt:Issuer"] = "http://auth-flow-lab.test",
                ["Jwt:KeyId"] = "auth-flow-lab-test-key",
                ["Auth:AccessTokenMinutes"] = "10",
                ["Auth:Users:0:Username"] = "test-admin",
                ["Auth:Users:0:Password"] = "admin123",
                ["Auth:Users:0:Role"] = "Admin",
                ["Auth:Users:0:Scopes:0"] = "content.read",
                ["Auth:Users:0:Scopes:1"] = "content.write",
                ["Auth:Users:1:Username"] = "test-user",
                ["Auth:Users:1:Password"] = "user123",
                ["Auth:Users:1:Role"] = "User",
                ["Auth:Users:1:Scopes:0"] = "content.read",
                ["Auth:Clients:0:ClientId"] = "worker-service",
                ["Auth:Clients:0:ClientSecret"] = "worker-secret",
                ["Auth:Clients:0:AllowedGrantTypes:0"] = "client_credentials",
                ["Auth:Clients:0:Scopes:0"] = "content.read",
                ["Auth:Clients:0:Scopes:1"] = "content.write"
            });
        });
    }

    private static string FindProjectDirectory(string projectName)
    {
        var directory = new DirectoryInfo(Directory.GetCurrentDirectory());

        while (directory is not null)
        {
            var projectDirectory = Path.Combine(directory.FullName, "backend", projectName);
            if (File.Exists(Path.Combine(projectDirectory, $"{projectName}.csproj")))
            {
                return projectDirectory;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException($"Could not find project directory for {projectName}.");
    }
}

public sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("scope")] string Scope);

public sealed record AuthErrorResponse(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string ErrorDescription);
