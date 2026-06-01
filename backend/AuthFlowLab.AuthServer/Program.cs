using System.Security.Claims;
using AuthFlowLab.AuthServer.Options;
using AuthFlowLab.AuthServer.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

const string FrontendCorsPolicy = "Frontend";
const string EntraExternalScheme = "Entra";
// 启动时读取 Entra 外部登录配置；配置不完整时保持本地登录流程不变。
var entraExternalLoginOptions = builder.Configuration
    .GetSection("Auth:ExternalProviders:Entra")
    .Get<EntraExternalLoginOptions>() ?? new EntraExternalLoginOptions();

builder.Services.AddCors(options =>
{
    options.AddPolicy(FrontendCorsPolicy, policy =>
    {
        var origins = builder.Configuration
            .GetSection("Cors:AllowedOrigins")
            .Get<string[]>() ?? ["http://127.0.0.1:5173", "http://localhost:5173"];

        policy.WithOrigins(origins)
            .AllowAnyHeader()
            .AllowAnyMethod()
            // SPA 调用 /account/logout 时需要携带 Auth Server 的 HttpOnly cookie，后端才能删除登录会话。
            .AllowCredentials();
    });
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHealthChecks();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        //  Auth Server 用自己的登录 cookie 记录用户是否已经在 IdP 登录。
        options.LoginPath = "/account/login";
        options.Cookie.Name = "AuthFlowLab.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });

builder.Services.AddAuthorization();
builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection("Auth"));
builder.Services.Configure<EntraExternalLoginOptions>(builder.Configuration.GetSection("Auth:ExternalProviders:Entra"));
builder.Services.AddSingleton<RsaKeyService>();
builder.Services.AddSingleton<JwtService>();
builder.Services.AddSingleton<AuthorizationCodeStore>();

// 只有 SSO 配置完整时才注册 Entra OIDC handler，避免没有 Azure 配置时启动失败或误跳转。
if (IsEntraExternalLoginConfigured(entraExternalLoginOptions))
{
    builder.Services
        .AddAuthentication()
        .AddOpenIdConnect(EntraExternalScheme, options =>
        {
            // Entra 只负责外部认证，最终登录状态仍写入 Auth Server 自己的 cookie。
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.Authority = entraExternalLoginOptions.Authority;
            options.ClientId = entraExternalLoginOptions.ClientId;
            options.ClientSecret = entraExternalLoginOptions.ClientSecret;
            options.CallbackPath = entraExternalLoginOptions.CallbackPath;
            options.ResponseType = "code";
            options.SaveTokens = false;
            options.GetClaimsFromUserInfoEndpoint = false;

            // 请求 openid/profile/email 用来确认用户身份，业务 API scopes 仍由本地 Auth Server 发 token 时决定。
            options.Scope.Clear();
            foreach (var scope in entraExternalLoginOptions.Scopes)
            {
                options.Scope.Add(scope);
            }

            options.Events = new OpenIdConnectEvents
            {
                OnTokenValidated = context =>
                {
                    // Entra token 验证成功后，把外部用户映射成本地用户，再套用本地系统的权限模型。
                    var authOptions = context.HttpContext.RequestServices
                        .GetRequiredService<IOptions<AuthOptions>>()
                        .Value;
                    var externalOptions = context.HttpContext.RequestServices
                        .GetRequiredService<IOptions<EntraExternalLoginOptions>>()
                        .Value;

                    var externalUserName =
                        context.Principal?.FindFirstValue(externalOptions.UserNameClaim) ??
                        context.Principal?.FindFirstValue("email") ??
                        context.Principal?.FindFirstValue("name");

                    var user = authOptions.Users.FirstOrDefault(user =>
                        string.Equals(user.Username, externalUserName, StringComparison.OrdinalIgnoreCase));

                    // 没有本地用户映射就拒绝登录，避免任意 Entra 用户直接获得本地系统权限。
                    if (user is null)
                    {
                        context.Fail("The Entra user is not mapped to a local AuthFlowLab user.");
                        return Task.CompletedTask;
                    }

                    var claims = CreateLocalUserClaims(user);
                    claims.Add(new Claim("external_provider", "entra"));
                    if (!string.IsNullOrWhiteSpace(externalUserName))
                    {
                        claims.Add(new Claim("external_username", externalUserName));
                    }

                    // 把映射后的本地 claims 写入 cookie，后续 /connect/authorize 会基于这些 claims 发本地 token。
                    context.Principal = new ClaimsPrincipal(
                        new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));

                    return Task.CompletedTask;
                }
            };
        });
}

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.UseCors(FrontendCorsPolicy);

//  authorize 端点依赖 cookie 认证先还原 User，再决定是否跳登录页或发授权码。
app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/health");
app.MapControllers();

app.Run();

static List<Claim> CreateLocalUserClaims(AuthUser user)
{
    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, user.Username),
        new(ClaimTypes.Name, user.Username),
        new(ClaimTypes.Role, user.Role)
    };

    foreach (var scope in user.Scopes)
    {
        claims.Add(new Claim("scope", scope));
    }

    return claims;
}

static bool IsEntraExternalLoginConfigured(EntraExternalLoginOptions options)
{
    // SSO 入口默认关闭；只有配置齐全时才注册 Entra OIDC handler，方便本地无 Azure 配置时运行。
    return options.Enabled &&
        !string.IsNullOrWhiteSpace(options.Authority) &&
        !string.IsNullOrWhiteSpace(options.ClientId) &&
        !string.IsNullOrWhiteSpace(options.ClientSecret);
}

public partial class Program;
