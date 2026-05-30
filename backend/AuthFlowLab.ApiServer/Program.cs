using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthFlowLab.ApiServer.Authentication;
using AuthFlowLab.ApiServer.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;

var builder = WebApplication.CreateBuilder(args);

const string FrontendCorsPolicy = "Frontend";
const string SmartBearerScheme = "SmartBearer";
const string LocalJwtScheme = "LocalJwt";
const string EntraJwtScheme = "EntraJwt";
var entraJwtOptions = builder.Configuration.GetSection("Jwt:Entra").Get<EntraJwtOptions>()
    ?? new EntraJwtOptions();

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
builder.Services.AddHealthChecks();
builder.Services.AddOptions<EntraJwtOptions>()
    .Bind(builder.Configuration.GetSection("Jwt:Entra"))
    .Validate(options => !string.IsNullOrWhiteSpace(options.Authority), "Jwt:Entra:Authority is required.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.Audience), "Jwt:Entra:Audience is required.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.TenantId), "Jwt:Entra:TenantId is required.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.ClientId), "Jwt:Entra:ClientId is required.")
    .ValidateOnStart();

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
                IsEntraToken(jwt, entraJwtOptions))
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
        options.Authority = entraJwtOptions.Authority;
        options.Audience = entraJwtOptions.Audience;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuers = GetEntraValidIssuers(entraJwtOptions),
            ValidateAudience = true,
            ValidAudiences = GetEntraValidAudiences(entraJwtOptions),
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
    options.AddPolicy("ContentRead", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context =>
        {
            // Local tokens use "scope"; Entra access tokens usually use "scp".
            return HasAnyScope(context.User, "content.read", "access_as_user");
        });
    });

    options.AddPolicy("ContentWrite", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context =>
        {
            // Write access accepts the local write scope or the Entra delegated write scope.
            return HasAnyScope(context.User, "content.write", "write_as_user");
        });
    });

    options.AddPolicy("ServiceOnly", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context =>
        {
            // Service endpoints require tokens produced by client_credentials.
            return context.User.HasClaim(c => c.Type == "token_type" && c.Value == "service");
        });
    });

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

app.MapHealthChecks("/health");
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

static bool IsEntraToken(JwtSecurityToken jwt, EntraJwtOptions options)
{
    if (jwt.Issuer.StartsWith("https://login.microsoftonline.com/", StringComparison.OrdinalIgnoreCase) ||
        jwt.Issuer.StartsWith("https://sts.windows.net/", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    return jwt.Audiences.Any(audience =>
        string.Equals(audience, options.Audience, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(audience, options.ClientId, StringComparison.OrdinalIgnoreCase));
}

static string[] GetEntraValidIssuers(EntraJwtOptions options)
{
    var issuers = new List<string>
    {
        options.Authority.TrimEnd('/')
    };

    if (!string.IsNullOrWhiteSpace(options.TenantId))
    {
        issuers.Add($"https://login.microsoftonline.com/{options.TenantId}/v2.0");
        issuers.Add($"https://sts.windows.net/{options.TenantId}/");
    }

    return issuers.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
}

static string[] GetEntraValidAudiences(EntraJwtOptions options)
{
    return new[] { options.Audience, options.ClientId }
        .Where(value => !string.IsNullOrWhiteSpace(value))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
}

static bool HasAnyScope(ClaimsPrincipal user, params string[] requiredScopes)
{
    var scopes = user.FindAll("scope")
        .Concat(user.FindAll("scp"))
        .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    return scopes.Any(scope => requiredScopes.Contains(scope, StringComparer.Ordinal));
}

public partial class Program;
