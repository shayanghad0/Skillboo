# 📤 Flask Login Form – Sensitive Data Exposure – AI Bug Bounty Skill

## Skill Name
`flask-data-exposure-login`

## Description
Focused detection of excessive or sensitive data exposure occurring during or as a result of the Python Flask login process. This skill analyses how the application handles user data after a successful or failed authentication attempt — in API responses, redirect parameters, JWT tokens, session cookies, and error messages. When the server returns more data than necessary (full user objects, password hashes, internal tokens, PII, or business logic details), attackers can harvest this information to escalate attacks, perform account takeover, or further compromise the application. The skill covers both direct exposure (visible in response bodies) and indirect exposure via unencrypted tokens or verbose front‑end logging.

## Affected Components
- **Login success responses** that include the entire user object:
  ```json
  {"status": "ok", "user": {"id":1, "username":"admin", "password_hash":"$2b$...", "api_key":"..."}}
  ```
- **JWT token payloads** that contain sensitive claims like `"is_admin": true`, `"ssn": "123-45-6789"`, or internal roles/IDs.
- **Flask session cookies** (signed but not encrypted) storing PII or access control data in plain sight when decoded.
- **Redirect-after-login (`next` parameter)** reflecting sensitive tokens or session IDs in the URL.
- **Login error responses** that echo back the submitted password or include stack traces with database connection strings.
- **Password reset / magic link flows** that return the newly generated token or a temporary password in the response.
- **“Remember me” tokens** stored in cookies or local storage without `HttpOnly` flag, accessible to JavaScript.
- **HTML5 localStorage / sessionStorage** after login that stores sensitive profile data or API keys.
- **Verbose logs** on the client side (console.log of user objects) or server side (access logs with JWT in URL).
- **API endpoints** that are called immediately after login (e.g., `GET /api/me`) and return excessive fields.

## Detection Patterns (Static & Dynamic)
### 1. Login Response Body Over‑Sharing
- **Heuristic**: The login endpoint returns more than just an authentication token or success flag; it includes a full user profile, role list, permissions, or even the password hash.
- **Dynamic test**: Capture the login response (JSON/HTML). Look for fields like `password`, `password_hash`, `hash`, `secret`, `token`, `key`, `ssn`, `credit_card`, `address`, `phone`, `email` (if not expected). If any such field is present beyond the minimal necessary data, data exposure exists.

### 2. JWT Token Payload Leakage
- Decode the JWT (Base64 of payload) and inspect its claims. Sensitive data like `"role":"admin"`, `"email":"user@example.com"`, `"internal_id":123`, or proprietary identifiers should not be stored in the token if not necessary. Also check if the token includes `"password"` or `"hash"`.

### 3. Session Cookie Data Leak
- Flask's default cookie is a signed, base64‑encoded JSON blob. Decode it and check for sensitive fields: `_user_id`, `role`, `email`, or custom fields that might have been set inadvertently.

### 4. Exposure via URL Parameters
- After login, if the server redirects to `next` parameter with a token appended: `https://target.com/dashboard?token=eyJ...`. This exposes the token in browser history, referrer headers, and server logs.

### 5. Error Message Data Dump
- A failed login returns `{"error": "db error", "debug": "could not connect to mysql://user:pass@localhost/db"}` or similar, exposing database credentials.

### 6. Client‑Side Exposure
- View page source after login; check for inline scripts that set variables like `var currentUser = {"id":1, "apiKey":"abc123"}`.

## Testing Methodology (AI Agent Steps)
1. **Capture Login Request/Response**
   - Intercept the HTTP exchange for a successful login. Save the response body.
   - If the response is JSON, pretty-print it and examine all keys.
   - If HTML, look for hidden inputs, meta tags, or inline scripts that contain data.

2. **Analyse JWT or Token**
   - If the login returns a JWT, decode the payload (e.g., using `jwt.io`). Look for claims beyond sub, exp, iat, and nbf. Sensitive claims often start with `user_`, `data_`, `profile_`.
   - If it's a custom token, check for Base64 patterns and decode.

3. **Decode Flask Session Cookie**
   - Take the session cookie, split on `.`, and Base64‑decode the first part. Inspect the decoded JSON for sensitive data.

4. **Test Other Auth Flows**
   - Password reset: request a reset and check if the response contains the token or a temporary password.
   - Registration (if present): does the response return the password in clear?
   - OAuth callback: inspect the URL and the token exchange response for scope or profile data that may be excessive.

5. **Inspect Client‑Side Storage**
   - After login, open browser DevTools → Application → Local Storage / Session Storage and Cookies. Look for keys like `user`, `profile`, `auth`, `token` that contain PII.

6. **Monitor for Logging**
   - Check if the application uses `console.log(userObject)` in JavaScript; if it does, any sensitive data in the user object is exposed to anyone with browser console access (or via XSS).

7. **Verify Impact**
   - Determine if the exposed data can be used to compromise accounts (e.g., password hashes that could be cracked, API keys that grant further access, PII that violates privacy regulations).

## Essential Payloads & Techniques (Data Exposure Detection)
### Login Response Inspection
- Expected minimal response: `{"token": "..."}` or just a session cookie.
- Excessive response example:
  ```json
  {
    "success": true,
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "password_hash": "$2b$12$...",
      "api_key": "sk_live_abc123"
    }
  }
  ```

### JWT Payload Example
- Decoded JWT:
  ```json
  {
    "sub": "1",
    "iat": 1516239022,
    "username": "admin",
    "is_admin": true,
    "email": "admin@example.com",
    "phone": "+1234567890"
  }
  ```
  (Exposes role and PII)

### Session Cookie Decode
```bash
echo "eyJfZnJlc2giOmZhbHNlLCJjc3JmX3Rva2VuIjoi...rest" | base64 -d
# Output: {"_fresh":false,"csrf_token":"...","user_id":1,"role":"admin","email":"admin@example.com"}
```

### URL‑Exposed Token
- After login, browser redirects to:
  ```
  https://target.com/dashboard?access_token=eyJhbGciOi...
  ```

### Debug Error Leak
- Send `' OR 1=1--` as username. Response:
  ```
  {"error": "SQL error: SELECT * FROM users WHERE username=''' OR 1=1--' ... (using password: 'mydbpassword')"}
  ```

## Secure Coding Recommendations
- **Principle of least data**: Return only the necessary data for the client to function (e.g., a session cookie or a token, maybe a user display name). Never return the full user object.
- **Filter sensitive fields before serialization**: Use serializers (Marshmallow, Pydantic) that explicitly whitelist fields for output.
- **JWT best practices**: Store only minimal, non‑sensitive claims. Avoid putting PII, roles (use server‑side checks instead), or internal IDs in the token. Keep the payload small.
- **Flask session**: Remember that the cookie is signed but not encrypted. Do not put sensitive data in the session; store a user ID and fetch the user object from the database on each request.
- **Avoid redirect‑based token passing**: Prefer cookies (`Set-Cookie` with `HttpOnly`, `Secure`, `SameSite`) over URL parameters for tokens.
- **Disable debug mode**: `app.debug = False` in production; use proper error handlers that return generic error messages.
- **Control client‑side exposure**: Do not embed user data in inline JavaScript or localStorage/sessionStorage unless absolutely necessary and never include secrets.
- **Hash passwords server‑side** and never return them in any response.
- **Monitor dependencies**: Ensure Flask, Werkzeug, and itsdangerous are up to date; use `SESSION_COOKIE_HTTPONLY=True` and `SESSION_COOKIE_SECURE=True`.

## Output Format (Bug Report)
```
Title: Sensitive Data Exposure – Full User Object Returned on Login
Severity: High (CVSS 7.5)
Endpoint: POST /login
Vulnerable Data: Password hash, API key, email
Description:
  The login API endpoint responds with the complete user object after a successful authentication, including the bcrypt password hash, API key, and email address. This exposes sensitive data that can be used for offline password cracking and further account compromise.
Proof of Concept:
  POST /login with valid credentials.
  Response JSON contains: {"user":{"password_hash":"$2b$...", "api_key":"sk_live_..."}}
Remediation: Modify the serialiser to only return a user ID and a session token. Never include password hashes or API keys in authentication responses.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with any authentication mechanism
- **Testing Type**: Black-box / Grey-box (requires ability to inspect HTTP traffic and decode tokens)
- **Dependencies**: None; AI can parse JSON/HTML, decode JWTs and cookies, and flag sensitive fields.