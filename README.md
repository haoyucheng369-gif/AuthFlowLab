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
| `admin` | `admin123` | `Admin` | `content.read` |

Client:

| Client ID | Client Secret | Scope |
| --- | --- | --- |
| `worker-service` | `worker-secret` | `content.read` |

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
  "scope": "content.read"
}
```

Invalid credentials return:

```json
{
  "error": "invalid_grant",
  "error_description": "The username or password is invalid."
}
```

### Service Token

```http
POST http://127.0.0.1:5001/auth/client-token
Content-Type: application/json

{
  "clientId": "worker-service",
  "clientSecret": "worker-secret",
  "scope": "content.read"
}
```

The response shape is the same as login. Invalid clients return `invalid_client`; disallowed scopes return `invalid_scope`.

## API Server Endpoints

| Endpoint | Authorization |
| --- | --- |
| `GET /content/public` | Anonymous |
| `GET /content/user` | Any valid bearer token |
| `GET /content/admin` | `Admin` role |
| `GET /content/read` | `content.read` scope |
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

## Tests

```powershell
dotnet test backend\AuthFlowLab.sln
```
