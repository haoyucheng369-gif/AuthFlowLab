# AuthFlowLab

AuthFlowLab is a full-stack authentication and authorization reference implementation for modern identity flows across a custom authorization server, protected APIs, a React SPA, and Microsoft Entra ID. It focuses on standards-based token issuance, JWT validation, delegated user access, service-to-service authorization, and clear separation between identity provider, client, and resource server responsibilities.

## Capabilities

- Custom Auth Server with OAuth2 authorization code + PKCE, client credentials, OIDC discovery, UserInfo, and JWKS.
- API Server with JWT bearer validation for both locally issued tokens and Microsoft Entra ID access tokens.
- React SPA with local sign-in and MSAL-based Entra ID sign-in.
- Scope-based, role-based, service-only, and API-key authorization.
- RSA-backed JWT signing with public-key discovery through JWKS.
- Docker, local run commands, HTTP request files, backend tests, and frontend build verification.

## Architecture

```mermaid
flowchart LR
    Browser[React SPA] -->|Authorization Code + PKCE| LocalIdP[AuthFlowLab Auth Server]
    Browser -->|MSAL Authorization Code + PKCE| Entra[Microsoft Entra ID]
    LocalIdP -->|Discovery + JWKS| Api[AuthFlowLab API Server]
    Entra -->|Discovery + JWKS| Api
    Browser -->|Bearer access_token| Api
    Browser -->|Graph access token| Graph[Microsoft Graph /me]
```

The Auth Server signs local JWTs and publishes its public key through JWKS. The API Server loads signing keys from `Jwt:Authority` for local tokens and validates Entra ID tokens through `Jwt:Entra:Authority` and `Jwt:Entra:Audience`.

## Local vs Entra

| Concept | Local Auth Server | Microsoft Entra ID |
| --- | --- | --- |
| Identity provider | `AuthFlowLab.AuthServer` | Microsoft Entra ID tenant |
| Browser client | `demo-spa` in appsettings | SPA app registration |
| Protected API | `aud=api-server` configuration | API app registration |
| Token issuer | Local Auth Server URL | `login.microsoftonline.com` |
| Signing keys | Local JWKS | Microsoft JWKS |
| Scope claim | `scope` | `scp` |
| API validation scheme | `LocalJwt` | `EntraJwt` |

## Flows

Local authorization code + PKCE:

```mermaid
sequenceDiagram
    participant Browser as React SPA
    participant Auth as AuthFlowLab Auth Server
    participant Api as AuthFlowLab API Server

    Browser->>Auth: /connect/authorize with code_challenge
    Auth-->>Browser: Redirect to /callback with code
    Browser->>Auth: /connect/token with code_verifier
    Auth-->>Browser: access_token and id_token
    Browser->>Api: API request with local bearer token
    Api->>Auth: Load discovery metadata and JWKS
    Api-->>Browser: Authorized response
```

Entra authorization code + PKCE:

```mermaid
sequenceDiagram
    participant Browser as React SPA
    participant Entra as Microsoft Entra ID
    participant Api as AuthFlowLab API Server
    participant Graph as Microsoft Graph

    Browser->>Entra: MSAL loginRedirect with API scopes
    Entra-->>Browser: Redirect to /callback with auth result
    Browser->>Entra: MSAL acquires API access token
    Browser->>Api: API request with Entra bearer token
    Api->>Entra: Load discovery metadata and JWKS
    Api-->>Browser: Authorized response
    Browser->>Graph: /me with Graph access token
```

## Entra ID

The repository is configured for a protected API registration and a browser SPA registration:

| Purpose | Name | Client ID |
| --- | --- | --- |
| Protected API | `AuthFlowLab API` | `b5b7fdde-0835-4e46-863d-463b1432e9f7` |
| Browser SPA | `AuthFlowLab SPA` | `35b46efc-ba76-4940-bc2a-a4fa1b904dcb` |

| Setting | Value |
| --- | --- |
| Tenant | `976c3c85-e425-4880-a658-3653df9cebf2` |
| Redirect URI | `http://localhost:5173/callback` |
| API scopes | `access_as_user`, `write_as_user` |

The API accepts local `content.read` / `content.write` scopes and Entra `access_as_user` / `write_as_user` scopes for the corresponding read and write endpoints.

## Run

Docker:

```powershell
docker compose up --build
```

Local backend:

```powershell
dotnet run --project backend\AuthFlowLab.AuthServer\AuthFlowLab.AuthServer.csproj --urls http://127.0.0.1:5001
dotnet run --project backend\AuthFlowLab.ApiServer\AuthFlowLab.ApiServer.csproj --urls http://127.0.0.1:5002
```

Local frontend:

```powershell
cd frontend\AuthFlowLab.Web
npm install
npm run dev
```

Open `http://localhost:5173`.

## Development Credentials

| Type | Identifier | Secret | Access |
| --- | --- | --- | --- |
| User | `user` | `user123` | `content.read` |
| User | `admin` | `admin123` | `content.read content.write`, `Admin` role |
| Client | `worker-service` | `worker-secret` | `content.read content.write` |
| SPA | `demo-spa` | none | `openid profile content.read content.write` |
| API key | `internal-tool` | `dev-api-key-123` | `X-Api-Key` |

These are development credentials for the local environment. Do not use committed secrets for production systems.

## API Surface

| Endpoint | Authorization |
| --- | --- |
| `GET /content/public` | Anonymous |
| `GET /content/user` | Any valid bearer token |
| `GET /content/me` | Current authentication state and claims |
| `GET /content/admin` | `Admin` role |
| `GET /content/read` | Local `content.read` or Entra `access_as_user` |
| `POST /content/write` | Local `content.write` or Entra `write_as_user` |
| `GET /content/service` | `token_type=service` |
| `GET /content/api-key` | Valid `X-Api-Key` header |

HTTP request examples are available in:

- `backend/AuthFlowLab.http`
- `backend/AuthFlowLab.AuthServer/AuthFlowLab.AuthServer.http`
- `backend/AuthFlowLab.ApiServer/AuthFlowLab.ApiServer.http`

## Verify

```powershell
dotnet test backend\AuthFlowLab.sln

cd frontend\AuthFlowLab.Web
npm run build
```

## Code Map

Auth Server:

- `backend/AuthFlowLab.AuthServer/Controllers/AccountController.cs` owns the local sign-in page and HTTP-only login cookie.
- `backend/AuthFlowLab.AuthServer/Controllers/ConnectController.cs` owns `/connect/authorize`, `/connect/token`, UserInfo, PKCE validation, scope checks, and code exchange.
- `backend/AuthFlowLab.AuthServer/Controllers/DiscoveryController.cs` exposes OIDC discovery metadata and JWKS.
- `backend/AuthFlowLab.AuthServer/Services/JwtService.cs` signs user access tokens, service access tokens, and OIDC ID tokens.

API Server:

- `backend/AuthFlowLab.ApiServer/Program.cs` configures local JWT validation, Entra JWT validation, API-key authentication, and authorization policies.
- `backend/AuthFlowLab.ApiServer/Controllers/ContentController.cs` defines the protected endpoint matrix.
- `backend/AuthFlowLab.ApiServer/Authentication/ApiKeyAuthenticationHandler.cs` validates `X-Api-Key`.

Frontend:

- `frontend/AuthFlowLab.Web/src/auth.ts` handles local PKCE, callback exchange, nonce validation, MSAL login, and token acquisition.
- `frontend/AuthFlowLab.Web/src/App.tsx` coordinates login state, API calls, Graph calls, and logout.
- `frontend/AuthFlowLab.Web/src/config.ts` centralizes local URLs, client id, redirect URI, scopes, and storage keys.
