using System.Net;
using AuthFlowLab.Bff.Models;
using AuthFlowLab.Bff.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthFlowLab.Bff.Tests;

public sealed class BffEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    private readonly BffSessionStore _sessionStore;

    public BffEndpointTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        _sessionStore = factory.Services.GetRequiredService<BffSessionStore>();
    }

    [Fact]
    public async Task Health_ReturnsHealthy()
    {
        var response = await _client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Login_RedirectsToAuthServerAuthorizeEndpoint()
    {
        var response = await _client.GetAsync("/bff/login");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
        Assert.StartsWith("http://localhost:5001/connect/authorize", response.Headers.Location.ToString());
        Assert.Contains("client_id=demo-bff", response.Headers.Location.Query);
        Assert.Contains("code_challenge_method=S256", response.Headers.Location.Query);
    }

    [Fact]
    public async Task Session_WhenNotLoggedIn_ReturnsUnauthorized()
    {
        var response = await _client.GetAsync("/bff/session");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ReadContent_WhenNotLoggedIn_ReturnsUnauthorized()
    {
        var response = await _client.GetAsync("/bff/content/read");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("/bff/content/me")]
    [InlineData("/bff/userinfo")]
    public async Task ReadProxy_WhenNotLoggedIn_ReturnsUnauthorized(string path)
    {
        var response = await _client.GetAsync(path);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task WriteContent_WhenNotLoggedIn_ReturnsUnauthorized()
    {
        var response = await _client.PostAsync("/bff/content/write", null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Session_WhenLoggedIn_ReturnsCsrfTokenWithoutAccessToken()
    {
        var sessionId = CreateSession();
        using var request = CreateRequest(HttpMethod.Get, "/bff/session", sessionId);

        var response = await _client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"csrfToken\":", body);
        Assert.DoesNotContain("test-access-token", body);
    }

    [Fact]
    public async Task WriteContent_WithoutCsrfToken_ReturnsBadRequest()
    {
        var sessionId = CreateSession();
        using var request = CreateRequest(HttpMethod.Post, "/bff/content/write", sessionId);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task WriteContent_WithInvalidCsrfToken_ReturnsBadRequest()
    {
        var sessionId = CreateSession();
        using var request = CreateRequest(HttpMethod.Post, "/bff/content/write", sessionId);
        request.Headers.Add("X-CSRF-TOKEN", "invalid-token");

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Logout_WhenNotLoggedIn_ReturnsNoContent()
    {
        var response = await _client.PostAsync("/bff/logout", null);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    private string CreateSession()
    {
        // 测试直接创建 BFF session，只验证浏览器 cookie 和 CSRF 边界，不依赖真实 Auth Server。
        return _sessionStore.CreateSession(new TokenResponse(
            "test-access-token",
            "openid profile content.read content.write",
            300));
    }

    private static HttpRequestMessage CreateRequest(HttpMethod method, string path, string sessionId)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("Cookie", $"AuthFlowLab.Bff.Session={sessionId}");
        return request;
    }
}
