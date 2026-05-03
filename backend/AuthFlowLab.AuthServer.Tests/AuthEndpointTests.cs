using System.Net;
using System.Net.Http.Json;
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
            username = "user",
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
    public async Task Login_WithBadPassword_ReturnsInvalidGrant()
    {
        var response = await _client.PostAsJsonAsync("/auth/login", new
        {
            username = "user",
            password = "wrong"
        });

        var error = await response.Content.ReadFromJsonAsync<AuthErrorResponse>();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("invalid_grant", error?.Error);
    }

    [Fact]
    public async Task ClientToken_WithAllowedScope_Returns_ServiceToken()
    {
        var response = await _client.PostAsJsonAsync("/auth/client-token", new
        {
            clientId = "worker-service",
            clientSecret = "worker-secret",
            scope = "content.read"
        });

        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenResponse>();

        Assert.NotNull(token);
        Assert.Equal("Bearer", token.TokenType);
        Assert.Equal("content.read", token.Scope);
        Assert.False(string.IsNullOrWhiteSpace(token.AccessToken));
    }

    [Fact]
    public async Task ClientToken_WithDisallowedScope_ReturnsInvalidScope()
    {
        var response = await _client.PostAsJsonAsync("/auth/client-token", new
        {
            clientId = "worker-service",
            clientSecret = "worker-secret",
            scope = "admin"
        });

        var error = await response.Content.ReadFromJsonAsync<AuthErrorResponse>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_scope", error?.Error);
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
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:PrivateKeyPath"] = _privateKeyPath,
                ["Auth:AccessTokenMinutes"] = "10",
                ["Auth:Users:0:Username"] = "user",
                ["Auth:Users:0:Password"] = "user123",
                ["Auth:Users:0:Role"] = "User",
                ["Auth:Users:0:Scopes:0"] = "content.read",
                ["Auth:Clients:0:ClientId"] = "worker-service",
                ["Auth:Clients:0:ClientSecret"] = "worker-secret",
                ["Auth:Clients:0:Scopes:0"] = "content.read"
            });
        });
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
