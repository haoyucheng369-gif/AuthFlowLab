namespace AuthFlowLab.AuthServer.Models;

public record ClientTokenRequest(string ClientId, string ClientSecret, string? Scope = null);
