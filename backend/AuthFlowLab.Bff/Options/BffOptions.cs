namespace AuthFlowLab.Bff.Options;

public sealed class BffOptions
{
    // 浏览器访问 Auth Server 时使用公开地址；Docker 容器内部地址不能暴露给浏览器。
    public string AuthServerPublicUrl { get; init; } = "http://localhost:5001";

    // BFF 服务端兑换 token 时使用后端地址，本地和 Docker 环境可以分别覆盖。
    public string AuthServerBackchannelUrl { get; init; } = "http://localhost:5001";

    // BFF 代理 API 请求时使用后端地址，本地和 Docker 环境可以分别覆盖。
    public string ApiServerBackchannelUrl { get; init; } = "http://localhost:5002";

    // callback 必须和 Auth Server 中 demo-bff client 注册的 redirect_uri 完全一致。
    public string CallbackUrl { get; init; } = "http://localhost:5003/bff/callback";

    // 登录完成后回到前端页面，由前端读取 BFF 会话状态。
    public string FrontendUrl { get; init; } = "http://localhost:5173";

    // BFF 是 confidential client，client_secret 只能保存在服务端。
    public string ClientId { get; init; } = "demo-bff";
    public string ClientSecret { get; init; } = "bff-secret";

    // BFF 请求本地 Auth Server 发放的 API scopes。
    public string Scope { get; init; } = "openid profile content.read content.write";

    public string SessionCookieName { get; init; } = "AuthFlowLab.Bff.Session";
}
