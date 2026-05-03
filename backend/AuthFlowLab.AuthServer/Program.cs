using AuthFlowLab.AuthServer.Options;
using AuthFlowLab.AuthServer.Services;

var builder = WebApplication.CreateBuilder(args);

// 注册 Controller 和 Swagger，方便本地查看 AuthServer 的实验接口。
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// AuthOptions 对应 appsettings.json 的 Auth 节点，集中保存用户、客户端、scope 和 token 过期时间。
builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection("Auth"));

// RsaKeyService 统一管理私钥读取、JWT 签名凭证和 JWKS 公钥导出。
builder.Services.AddSingleton<RsaKeyService>();

// JwtService 负责把用户/client 信息转换成 claims，并生成 OAuth2 风格 token response。
builder.Services.AddSingleton<JwtService>();

var app = builder.Build();

// AuthServer 的 Swagger 主要用于调试登录、token endpoint、discovery 和 JWKS。
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

// 映射 /auth/login、/connect/token 和 /.well-known/* 等 Controller 路由。
app.MapControllers();

app.Run();

// WebApplicationFactory 集成测试需要可引用的 Program 类型。
public partial class Program;
