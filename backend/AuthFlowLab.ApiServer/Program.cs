using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthFlowLab.ApiServer.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;

var builder = WebApplication.CreateBuilder(args);

const string FrontendCorsPolicy = "Frontend";
const string SmartBearerScheme = "SmartBearer";
const string LocalJwtScheme = "LocalJwt";
const string EntraJwtScheme = "EntraJwt";
const string DefaultEntraAudience = "api://b5b7fdde-0835-4e46-863d-463b1432e9f7";
const string DefaultEntraClientId = "b5b7fdde-0835-4e46-863d-463b1432e9f7";
const string EntraTenantId = "976c3c85-e425-4880-a658-3653df9cebf2";

builder.Services.AddCors(options =>
{
    options.AddPolicy(FrontendCorsPolicy, policy =>
    {
        var origins = builder.Configuration
            .GetSection("Cors:AllowedOrigins")
            .Get<string[]>() ?? ["http://127.0.0.1:5173", "http://localhost:5173"];

        policy.WithOrigins(origins)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "AuthFlowLab API Server",
        Version = "v1"
    });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Paste a JWT access token. The 'Bearer' prefix is optional."
    });

    options.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        Name = ApiKeyAuthenticationDefaults.HeaderName,
        Type = SecuritySchemeType.ApiKey,
        In = ParameterLocation.Header,
        Description = "Paste an API key for endpoints that use X-Api-Key authentication."
    });

    options.AddSecurityRequirement(document => new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecuritySchemeReference("Bearer", document),
            []
        }
    });

    options.AddSecurityRequirement(document => new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecuritySchemeReference("ApiKey", document),
            []
        }
    });
});

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = SmartBearerScheme;
        options.DefaultChallengeScheme = SmartBearerScheme;
    })
    .AddPolicyScheme(SmartBearerScheme, "Local AuthFlowLab or Entra ID bearer token", options =>
    {
        options.ForwardDefaultSelector = context =>
        {
            var authorization = context.Request.Headers.Authorization.ToString();
            if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return LocalJwtScheme;
            }

            var token = authorization["Bearer ".Length..].Trim();
            if (TryReadJwt(token, out var jwt) &&
                IsEntraToken(jwt, builder.Configuration["Jwt:Entra:Audience"] ?? DefaultEntraAudience))
            {
                return EntraJwtScheme;
            }

            return LocalJwtScheme;
        };
    })
    .AddJwtBearer(LocalJwtScheme, options =>
    {
        // Local IdP token validation uses discovery/JWKS from AuthFlowLab.AuthServer.
        options.MapInboundClaims = false;
        options.Authority = builder.Configuration["Jwt:Authority"] ?? "http://127.0.0.1:5001";
        options.Audience = builder.Configuration["Jwt:Audience"] ?? "api-server";
        options.RequireHttpsMetadata = builder.Configuration.GetValue("Jwt:RequireHttpsMetadata", false);
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = (builder.Configuration["Jwt:Authority"] ?? "http://127.0.0.1:5001").TrimEnd('/'),
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            RoleClaimType = ClaimTypes.Role
        };
    })
    .AddJwtBearer(EntraJwtScheme, options =>
    {
        // Entra ID token validation uses Microsoft's discovery/JWKS endpoint for this tenant.
        options.MapInboundClaims = false;
        options.IncludeErrorDetails = true;
        options.Authority = builder.Configuration["Jwt:Entra:Authority"]
            ?? "https://login.microsoftonline.com/976c3c85-e425-4880-a658-3653df9cebf2/v2.0";
        var entraAudience = builder.Configuration["Jwt:Entra:Audience"] ?? DefaultEntraAudience;
        options.Audience = entraAudience;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuers =
            [
                $"https://login.microsoftonline.com/{EntraTenantId}/v2.0",
                $"https://sts.windows.net/{EntraTenantId}/"
            ],
            ValidateAudience = true,
            ValidAudiences = [entraAudience, DefaultEntraClientId],
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            NameClaimType = "name",
            RoleClaimType = "roles"
        };
    })
    .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
        ApiKeyAuthenticationDefaults.AuthenticationScheme,
        options =>
        {
            builder.Configuration.GetSection("ApiKeys").Bind(options);
        });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ContentRead", policy => policy.RequireAssertion(context =>
    {
        // Local tokens use "scope"; Entra access tokens usually use "scp".
        return HasAnyScope(context.User, "content.read", "access_as_user");
    }));

    options.AddPolicy("ContentWrite", policy => policy.RequireAssertion(context =>
    {
        // Write access accepts the local write scope or the Entra delegated write scope.
        return HasAnyScope(context.User, "content.write", "write_as_user");
    }));

    options.AddPolicy("ServiceOnly", policy => policy.RequireAssertion(context =>
    {
        // Service endpoints require tokens produced by client_credentials.
        return context.User.HasClaim(c => c.Type == "token_type" && c.Value == "service");
    }));

    options.AddPolicy("ApiKeyOnly", policy =>
    {
        // API key authentication is a separate local scheme, not an OAuth2/OIDC grant type.
        policy.AuthenticationSchemes.Add(ApiKeyAuthenticationDefaults.AuthenticationScheme);
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("token_type", "api_key");
    });
});

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.UseCors(FrontendCorsPolicy);

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

static bool TryReadJwt(string token, out JwtSecurityToken jwt)
{
    jwt = null!;

    try
    {
        jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        return true;
    }
    catch (ArgumentException)
    {
        return false;
    }
}

static bool IsEntraToken(JwtSecurityToken jwt, string configuredAudience)
{
    if (jwt.Issuer.StartsWith("https://login.microsoftonline.com/", StringComparison.OrdinalIgnoreCase) ||
        jwt.Issuer.StartsWith("https://sts.windows.net/", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    return jwt.Audiences.Any(audience =>
        string.Equals(audience, configuredAudience, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(audience, DefaultEntraClientId, StringComparison.OrdinalIgnoreCase));
}

static bool HasAnyScope(ClaimsPrincipal user, params string[] requiredScopes)
{
    var scopes = user.FindAll("scope")
        .Concat(user.FindAll("scp"))
        .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    return scopes.Any(scope => requiredScopes.Contains(scope, StringComparer.Ordinal));
}

public partial class Program;
