# AuthFlowLab

A minimal authentication and authorization lab for learning JWT bearer validation and OAuth2-style flows.

## Current Scope

- User login issues JWT access tokens.
- Client credentials-style service token issuing is available through a simplified JSON endpoint.
- API Server validates JWTs signed by Auth Server.
- API endpoints demonstrate anonymous, authenticated, role, scope, and service-only authorization.

## Architecture

Frontend -> Auth Server -> API -> Database

For the current lab stage:

- Auth Server signs JWTs with `keys/private.key`.
- API Server validates JWT signatures with `keys/public.key`.
- User accounts, client credentials, allowed scopes, and token lifetime are configured in `AuthFlowLab.AuthServer/appsettings.json`.

## Run Locally

From the repository root:

```powershell
dotnet run --project backend\AuthFlowLab.AuthServer\AuthFlowLab.AuthServer.csproj --urls http://127.0.0.1:5001
dotnet run --project backend\AuthFlowLab.ApiServer\AuthFlowLab.ApiServer.csproj --urls http://127.0.0.1:5002
```

## Test Users And Clients

Users:

| Username | Password | Role  | Scope        |
| --- | --- | --- | --- |
| `user` | `user123` | `User` | `content.read` |
| `admin` | `admin123` | `Admin` | `content.read content.write` |

Client:

| Client ID | Client Secret | Scope |
| --- | --- | --- |
| `worker-service` | `worker-secret` | `content.read content.write` |

These are lab credentials. Do not use committed secrets for real systems.

## Auth Server API

### Login

```http
POST http://127.0.0.1:5001/auth/login
Content-Type: application/json

{
  "username": "user",
  "password": "user123"
}
```

Response:

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 1800,
  "scope": "content.read content.write"
}
```

Invalid credentials return:

```json
{
  "error": "invalid_grant",
  "error_description": "The username or password is invalid."
}
```

### Client Credentials Token

```http
POST http://127.0.0.1:5001/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=worker-service
&client_secret=worker-secret
&scope=content.read content.write
```

The response shape is the same as login. Invalid clients return `invalid_client`; unsupported grant types return `unsupported_grant_type`; disallowed scopes return `invalid_scope`.

The old lab-only `/auth/client-token` endpoint has been removed. Service tokens now use the OAuth2-style `/connect/token` endpoint.

## API Server Endpoints

| Endpoint | Authorization |
| --- | --- |
| `GET /content/public` | Anonymous |
| `GET /content/user` | Any valid bearer token |
| `GET /content/admin` | `Admin` role |
| `GET /content/read` | `content.read` scope |
| `POST /content/write` | `content.write` scope |
| `GET /content/service` | `token_type=service` |

Example:

```http
GET http://127.0.0.1:5002/content/read
Authorization: Bearer <access_token>
```

## HTTP Examples

Use these files with Visual Studio, Rider, or the REST Client extension:

- `backend/AuthFlowLab.http` contains the full Auth Server + API Server flow.
- `backend/AuthFlowLab.AuthServer/AuthFlowLab.AuthServer.http` contains Auth Server requests.
- `backend/AuthFlowLab.ApiServer/AuthFlowLab.ApiServer.http` contains API Server requests.

Keep shared `.http` files token-free. If you want to store personal tokens locally, create a file such as `backend/AuthFlowLab.local.http`; `*.local.http` is ignored by Git.

## Tests

```powershell
dotnet test backend\AuthFlowLab.sln
```
