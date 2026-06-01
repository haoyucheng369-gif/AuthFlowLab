using System.Collections.Concurrent;
using System.Security.Cryptography;
using AuthFlowLab.Bff.Models;
using Microsoft.IdentityModel.Tokens;

namespace AuthFlowLab.Bff.Services;

public sealed class BffSessionStore
{
    private readonly ConcurrentDictionary<string, BffLoginState> _loginStates = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, BffSession> _sessions = new(StringComparer.Ordinal);

    public string CreateLoginState(string codeVerifier)
    {
        // state 把 callback 绑定到 BFF 发起的登录请求，同时在服务端关联 PKCE verifier。
        var state = CreateRandomValue();
        _loginStates[state] = new BffLoginState(codeVerifier, DateTimeOffset.UtcNow.AddMinutes(5));
        return state;
    }

    public bool TryConsumeLoginState(string state, out BffLoginState? loginState)
    {
        if (!_loginStates.TryRemove(state, out loginState))
        {
            return false;
        }

        return loginState.ExpiresAt > DateTimeOffset.UtcNow;
    }

    public string CreateSession(TokenResponse token)
    {
        // cookie 只保存随机 session id；真正的 access_token 和 CSRF token 保留在 BFF 服务端内存中。
        var sessionId = CreateRandomValue();
        _sessions[sessionId] = new BffSession(
            token.AccessToken,
            token.Scope,
            DateTimeOffset.UtcNow.AddSeconds(token.ExpiresIn),
            CreateRandomValue());
        return sessionId;
    }

    public bool TryGetSession(string? sessionId, out BffSession? session)
    {
        session = null;
        if (string.IsNullOrWhiteSpace(sessionId) || !_sessions.TryGetValue(sessionId, out var storedSession))
        {
            return false;
        }

        if (storedSession.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            _sessions.TryRemove(sessionId, out _);
            return false;
        }

        session = storedSession;
        return true;
    }

    public void RemoveSession(string? sessionId)
    {
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            _sessions.TryRemove(sessionId, out _);
        }
    }

    private static string CreateRandomValue()
        => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
}
