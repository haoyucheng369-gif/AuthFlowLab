using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// 生成 OpenAPI JSON 和 Swagger UI，并声明受保护接口需要 Bearer JWT。
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

    options.AddSecurityRequirement(document => new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecuritySchemeReference("Bearer", document),
            []
        }
    });
});

// Authentication：验证 Bearer token 的签名、issuer、audience 和过期时间。
// 这里使用 Authority，JwtBearer 会读取 AuthServer 的 discovery document 和 JWKS 公钥。
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
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
    });

// Authorization：token 已可信后，根据 claims 判断能不能访问具体资源。
builder.Services.AddAuthorization(options =>
{
    // content.read 使用 OAuth2 scope claim 控制，多个 scope 用空格分隔。
    options.AddPolicy("ContentRead", policy => policy.RequireAssertion(context =>
    {
        return context.User.FindAll("scope")
            .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Contains("content.read", StringComparer.Ordinal);
    }));

    // content.write 是更细粒度的写权限，用于验证 read/write scope 的差异。
    options.AddPolicy("ContentWrite", policy => policy.RequireAssertion(context =>
    {
        return context.User.FindAll("scope")
            .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Contains("content.write", StringComparer.Ordinal);
    }));

    // ServiceOnly 通过自定义 token_type claim 区分 service token 和 user token。
    options.AddPolicy("ServiceOnly", policy => policy.RequireAssertion(context =>
    {
        return context.User.HasClaim(c => c.Type == "token_type" && c.Value == "service");
    }));
});

var app = builder.Build();

// Swagger UI 读取 /swagger/v1/swagger.json，提供浏览器里的 API 调试界面。
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

// 中间件顺序很重要：先 Authentication 解析并验证 token，再 Authorization 执行策略。
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

// WebApplicationFactory 集成测试需要可引用的 Program 类型。
public partial class Program;
