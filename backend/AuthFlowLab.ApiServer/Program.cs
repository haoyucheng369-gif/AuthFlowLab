using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

var publicKeyPath = builder.Configuration["Jwt:PublicKeyPath"] ?? "../../keys/public.key";
publicKeyPath = Path.IsPathRooted(publicKeyPath)
    ? publicKeyPath
    : Path.GetFullPath(publicKeyPath, builder.Environment.ContentRootPath);

var publicKey = File.ReadAllText(publicKeyPath);
var rsa = RSA.Create();
rsa.ImportFromPem(publicKey);
var signingKey = new RsaSecurityKey(rsa);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"] ?? "auth-flow-lab",
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"] ?? "api-server",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            TryAllIssuerSigningKeys = true,
            RoleClaimType = ClaimTypes.Role
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ContentRead", policy => policy.RequireAssertion(context =>
    {
        return context.User.FindAll("scope")
            .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Contains("content.read", StringComparer.Ordinal);
    }));

    options.AddPolicy("ServiceOnly", policy => policy.RequireAssertion(context =>
    {
        return context.User.HasClaim(c => c.Type == "token_type" && c.Value == "service");
    }));
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

public partial class Program;
