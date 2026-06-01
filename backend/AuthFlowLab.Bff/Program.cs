using AuthFlowLab.Bff.Options;
using AuthFlowLab.Bff.Services;

var builder = WebApplication.CreateBuilder(args);

const string FrontendCorsPolicy = "Frontend";

builder.Services.AddControllers();
builder.Services.AddHealthChecks();
builder.Services.Configure<BffOptions>(builder.Configuration.GetSection("Bff"));
builder.Services.AddSingleton<BffSessionStore>();

builder.Services.AddCors(options =>
{
    options.AddPolicy(FrontendCorsPolicy, policy =>
    {
        var origins = builder.Configuration
            .GetSection("Cors:AllowedOrigins")
            .Get<string[]>() ?? ["http://localhost:5173"];

        // 浏览器只携带 BFF 的 HttpOnly cookie，不直接接触 access_token。
        policy.WithOrigins(origins)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.AddHttpClient("AuthServer", (services, client) =>
{
    var options = services.GetRequiredService<Microsoft.Extensions.Options.IOptions<BffOptions>>().Value;
    // BFF 在服务端调用 Auth Server token endpoint，用授权码兑换 access_token。
    client.BaseAddress = new Uri(options.AuthServerBackchannelUrl);
});

builder.Services.AddHttpClient("ApiServer", (services, client) =>
{
    var options = services.GetRequiredService<Microsoft.Extensions.Options.IOptions<BffOptions>>().Value;
    // BFF 代理调用 API 时才附加 bearer token，浏览器本身不会拿到这个 token。
    client.BaseAddress = new Uri(options.ApiServerBackchannelUrl);
});

var app = builder.Build();

app.UseCors(FrontendCorsPolicy);

app.MapHealthChecks("/health");
app.MapControllers();

app.Run();

public partial class Program;
