# CredsVerification API

This document summarizes the publicly available HTTP endpoints for the credential verification service.

## Base URL

The service is hosted as an ASP.NET Core Web API. All routes below are relative to the deployed host (for example, `https://localhost:5001`).

## Endpoints

### `GET /`
Returns a simple heartbeat response to confirm the service is running.

**Response**
- `200 OK` with JSON body similar to:
  ```json
  {"success":false,"message":"Login test app is currently running.."}
  ```

### `GET /login`
Lists the supported two-character state codes that can be passed to the verification endpoint.

**Response**
- `200 OK` with JSON listing the supported codes:
  ```json
  {
    "success": true,
    "message": "Login verification is available for the following state codes.",
    "states": ["ak", "al", "ar", "az", "ca", "co", "ct", "dc", "de", "fl", "ga", "hi", "ia", "id", "il", "in", "ks", "ky", "la", "ma", "md", "me", "mi", "mn", "mo", "ms", "mt", "nc", "nd", "ne", "nh", "nj", "nm", "nv", "ny", "oh", "ok", "or", "pa", "pr", "ri", "sc", "sd", "tn", "tx", "ut", "va", "vt", "wa", "wi", "wv", "wy"]
  }
  ```

### `POST /login`
Routes the provided credentials to the appropriate state-specific verification flow.

**Request body**

```json
{
  "username": "user@example",
  "password": "P@ssw0rd!",
  "state": "tx",
  "accountNumber": "optional-account-number",
  "pin": "optional-pin"
}
```

> `accountNumber` and `pin` are only required for states that prompt for them. All other states ignore them.

**Responses**
- `200 OK` with a JSON payload indicating success or failure. Each state returns a message that reflects the external system response (for example, invalid credentials, MFA required, or successful login).
- `400 Bad Request` if required fields are missing.

## Notes
- The service uses Playwright for browser-based flows and `HttpClient` for lightweight form posts. Browsers are pooled per process for efficiency.
- Swagger/OpenAPI metadata is enabled during development builds via `app.MapOpenApi()`.
