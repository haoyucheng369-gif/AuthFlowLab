using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace AuthFlowLab.AuthServer.Services;

public sealed class RsaKeyService
{
    private readonly IConfiguration _configuration;
    private readonly IWebHostEnvironment _environment;
    private readonly Lazy<RSA> _rsa;

    public RsaKeyService(IConfiguration configuration, IWebHostEnvironment environment)
    {
        _configuration = configuration;
        _environment = environment;
        _rsa = new Lazy<RSA>(LoadPrivateKey);
    }

    public string KeyId => _configuration["Jwt:KeyId"] ?? "auth-flow-lab-key-1";

    public SigningCredentials CreateSigningCredentials()
    {
        var signingKey = new RsaSecurityKey(_rsa.Value)
        {
            KeyId = KeyId
        };

        return new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);
    }

    public JsonWebKey CreateJsonWebKey()
    {
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
            ?? throw new InvalidOperationException("Private key path is missing.");

        privateKeyPath = Path.IsPathRooted(privateKeyPath)
            ? privateKeyPath
            : Path.GetFullPath(privateKeyPath, _environment.ContentRootPath);

        var privateKey = File.ReadAllText(privateKeyPath);

        var rsa = RSA.Create();
        rsa.ImportFromPem(privateKey);
        return rsa;
    }
}
