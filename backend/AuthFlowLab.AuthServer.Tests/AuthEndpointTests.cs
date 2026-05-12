using System.Net;
using System.Net.Http.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace AuthFlowLab.AuthServer.Tests;

public sealed class AuthEndpointTests : IClassFixture<AuthServerFactory>
{
    private readonly HttpClient _client;

    public AuthEndpointTests(AuthServerFactory factory)
    {
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
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
        Assert.Equal("http://auth-flow-lab.test/connect/userinfo", document.GetProperty("userinfo_endpoint").GetString());
        Assert.Equal("http://auth-flow-lab.test/.well-known/jwks.json", document.GetProperty("jwks_uri").GetString());
        Assert.Contains("client_credentials", document.GetProperty("grant_types_supported").EnumerateArray().Select(item => item.GetString()));
        Assert.Contains("authorization_code", document.GetProperty("grant_types_supported").EnumerateArray().Select(item => item.GetString()));
        Assert.Equal("http://auth-flow-lab.test/connect/authorize", document.GetProperty("authorization_endpoint").GetString());
        Assert.Contains("openid", document.GetProperty("scopes_supported").EnumerateArray().Select(item => item.GetString()));
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

    [Fact]
    public async Task Authorize_WithPkce_RedirectsWithCodeAndState()
    {
        await SignInOnAuthServer();

        var verifier = "test-code-verifier-1234567890";
        var challenge = CreateS256Challenge(verifier);
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "demo-spa",
            ["redirect_uri"] = "http://127.0.0.1:5173/callback",
            ["scope"] = "openid profile content.read",
            ["state"] = "abc-state",
            ["nonce"] = "abc-nonce",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256"
        });

        var response = await _client.GetAsync(authorizeUrl);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);

        var callbackQuery = QueryHelpers.ParseQuery(response.Headers.Location.Query);
        Assert.Equal("abc-state", callbackQuery["state"]);
        Assert.False(string.IsNullOrWhiteSpace(callbackQuery["code"]));
    }

    [Fact]
    public async Task Authorize_WhenNotSignedIn_RedirectsToLoginPage()
    {
        var verifier = "test-code-verifier-1234567890";
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "demo-spa",
            ["redirect_uri"] = "http://127.0.0.1:5173/callback",
            ["scope"] = "openid profile content.read",
            ["state"] = "login-state",
            ["nonce"] = "login-nonce",
            ["code_challenge"] = CreateS256Challenge(verifier),
            ["code_challenge_method"] = "S256"
        });

        var response = await _client.GetAsync(authorizeUrl);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        var location = response.Headers.Location.ToString();
        Assert.StartsWith("/account/login", location);
        Assert.Contains("returnUrl=", location);
    }

    [Fact]
    public async Task Token_WithAuthorizationCodeAndPkce_ReturnsUserToken()
    {
        var verifier = "test-code-verifier-1234567890";
        var code = await CreateAuthorizationCode(verifier, "openid profile content.read", "oidc-nonce");

        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "demo-spa",
            ["code"] = code,
            ["redirect_uri"] = "http://127.0.0.1:5173/callback",
            ["code_verifier"] = verifier
        }));

        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenResponse>();

        Assert.NotNull(token);
        Assert.Equal("Bearer", token.TokenType);
        Assert.Equal("openid profile content.read", token.Scope);
        Assert.False(string.IsNullOrWhiteSpace(token.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(token.IdToken));

        var idToken = new JwtSecurityTokenHandler().ReadJwtToken(token.IdToken);
        Assert.Equal("http://auth-flow-lab.test", idToken.Issuer);
        Assert.Contains(idToken.Audiences, audience => audience == "demo-spa");
        Assert.Equal("test-user", idToken.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Sub).Value);
        Assert.Equal("oidc-nonce", idToken.Claims.Single(claim => claim.Type == "nonce").Value);
    }

    [Fact]
    public async Task Token_WithAuthorizationCode_GrantsOnlyUserAllowedScopes()
    {
        var verifier = "test-code-verifier-1234567890";
        var code = await CreateAuthorizationCode(verifier, "openid profile content.read content.write", "scope-nonce");

        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "demo-spa",
            ["code"] = code,
            ["redirect_uri"] = "http://127.0.0.1:5173/callback",
            ["code_verifier"] = verifier
        }));

        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenResponse>();

        Assert.NotNull(token);
        Assert.Equal("openid profile content.read", token.Scope);
        Assert.DoesNotContain("content.write", token.Scope);
    }

    [Fact]
    public async Task Token_WithAuthorizationCode_GrantsAdminWriteScope()
    {
        var verifier = "test-code-verifier-1234567890";
        var code = await CreateAuthorizationCode(
            verifier,
            "openid profile content.read content.write",
            "admin-scope-nonce",
            username: "test-admin",
            password: "admin123");

        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "demo-spa",
            ["code"] = code,
            ["redirect_uri"] = "http://127.0.0.1:5173/callback",
            ["code_verifier"] = verifier
        }));

        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenResponse>();

        Assert.NotNull(token);
        Assert.Equal("openid profile content.read content.write", token.Scope);
    }


    [Fact]
    public async Task UserInfo_WithAccessToken_ReturnsUserClaims()
    {
        var verifier = "test-code-verifier-1234567890";
        var code = await CreateAuthorizationCode(verifier, "openid profile content.read", "userinfo-nonce");
        var tokenResponse = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "demo-spa",
            ["code"] = code,
            ["redirect_uri"] = "http://127.0.0.1:5173/callback",
            ["code_verifier"] = verifier
        }));
        tokenResponse.EnsureSuccessStatusCode();
        var token = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token!.AccessToken);

        var response = await _client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var userInfo = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal("test-user", userInfo.GetProperty("sub").GetString());
        Assert.Equal("test-user", userInfo.GetProperty("name").GetString());
        Assert.Equal("User", userInfo.GetProperty("role").GetString());
    }

    [Fact]
    public async Task Token_WithWrongPkceVerifier_ReturnsInvalidGrant()
    {
        var code = await CreateAuthorizationCode("test-code-verifier-1234567890");

        var response = await _client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "demo-spa",
            ["code"] = code,
            ["redirect_uri"] = "http://127.0.0.1:5173/callback",
            ["code_verifier"] = "wrong-code-verifier"
        }));

        var error = await response.Content.ReadFromJsonAsync<AuthErrorResponse>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_grant", error?.Error);
    }

    private async Task<string> CreateAuthorizationCode(
        string verifier,
        string scope = "content.read",
        string? nonce = null,
        string username = "test-user",
        string password = "user123")
    {
        await SignInOnAuthServer(username, password);

        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "demo-spa",
            ["redirect_uri"] = "http://127.0.0.1:5173/callback",
            ["scope"] = scope,
            ["state"] = "token-test",
            ["nonce"] = nonce,
            ["code_challenge"] = CreateS256Challenge(verifier),
            ["code_challenge_method"] = "S256"
        });

        var response = await _client.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

        var callbackQuery = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        return callbackQuery["code"].ToString();
    }

    private async Task SignInOnAuthServer(string username = "test-user", string password = "user123")
    {
        var response = await _client.PostAsync("/account/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = username,
            ["password"] = password,
            ["returnUrl"] = "/"
        }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    private static string CreateS256Challenge(string verifier)
    {
        var hash = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier));
        return Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(hash);
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
                ["Auth:Clients:0:Scopes:1"] = "content.write",
                ["Auth:Clients:1:ClientId"] = "demo-spa",
                ["Auth:Clients:1:ClientSecret"] = "",
                ["Auth:Clients:1:AllowedGrantTypes:0"] = "authorization_code",
                ["Auth:Clients:1:Scopes:0"] = "openid",
                ["Auth:Clients:1:Scopes:1"] = "profile",
                ["Auth:Clients:1:Scopes:2"] = "content.read",
                ["Auth:Clients:1:Scopes:3"] = "content.write",
                ["Auth:Clients:1:RedirectUris:0"] = "http://127.0.0.1:5173/callback"
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

public sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("id_token")] string? IdToken = null);

public sealed record AuthErrorResponse(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string ErrorDescription);
