using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace AuthFlowLab.AuthServer.Services;

public sealed class RsaKeyService
{
    private readonly IConfiguration _configuration;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<RsaKeyService> _logger;
    private readonly Lazy<RSA> _rsa;

    public RsaKeyService(
        IConfiguration configuration,
        IWebHostEnvironment environment,
        ILogger<RsaKeyService> logger)
    {
        _configuration = configuration;
        _environment = environment;
        _logger = logger;
        _rsa = new Lazy<RSA>(LoadPrivateKey);
    }

    public string KeyId => _configuration["Jwt:KeyId"] ?? "auth-flow-lab-key-1";

    public SigningCredentials CreateSigningCredentials()
    {
        // 中文注释: 私钥只留在 Auth Server 内部，用来签名 access_token 和 id_token。
        var signingKey = new RsaSecurityKey(_rsa.Value)
        {
            KeyId = KeyId
        };

        return new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);
    }

    public JsonWebKey CreateJsonWebKey()
    {
        // 中文注释: 从同一把 RSA key 导出公钥参数，供 JWKS endpoint 返回给 API Server。
        var parameters = _rsa.Value.ExportParameters(includePrivateParameters: false);

        return new JsonWebKey
        {
            Kty = JsonWebAlgorithmsKeyTypes.RSA,
            Use = "sig",
            Kid = KeyId,
            Alg = SecurityAlgorithms.RsaSha256,
            N = Base64UrlEncoder.Encode(parameters.Modulus),
            E = Base64UrlEncoder.Encode(parameters.Exponent)
        };
    }

    private RSA LoadPrivateKey()
    {
        var privateKeyPath = _configuration["Jwt:PrivateKeyPath"]
            ?? string.Empty;

        privateKeyPath = Path.IsPathRooted(privateKeyPath)
            ? privateKeyPath
            : Path.GetFullPath(privateKeyPath, _environment.ContentRootPath);

        if (File.Exists(privateKeyPath))
        {
            return LoadPrivateKeyFromFile(privateKeyPath);
        }

        // 中文注释: Docker 或全新开发环境没有本地私钥时，生成临时签名密钥以便实验项目可直接启动。
        _logger.LogWarning("Private key file '{PrivateKeyPath}' was not found. Using an ephemeral RSA key for this process.", privateKeyPath);
        return RSA.Create(2048);
    }

    private static RSA LoadPrivateKeyFromFile(string privateKeyPath)
    {
        var privateKey = File.ReadAllText(privateKeyPath);

        var rsa = RSA.Create();
        rsa.ImportFromPem(privateKey);
        return rsa;
    }
}
