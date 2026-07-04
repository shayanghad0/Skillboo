# ⬆️ Flask Login Form – Privilege Escalation – AI Bug Bounty Skill

## Skill Name
`flask-login-privilege-escalation`

## Description
A combined detection and exploitation skill for all privilege escalation vectors that originate from, or are directly exploitable through, the Python Flask login form. This skill analyses how an attacker with either no account, a low‑privilege account, or an anonymous position can escalate privileges via the login process – gaining higher roles, administrative access, or impersonating other users. It covers parameter injection, session forgery, JWT tampering, IDOR chaining, brute‑force admin credentials, race conditions, and OAuth scope manipulation.

## Affected Components
- **Login form parameters** that bind to user privilege fields (role, is_admin, level, group, etc.) – mass assignment.
- **Flask session cookie** – secret key exposure allowing arbitrary session creation with elevated privileges.
- **JWT access tokens** – issued at login and subject to algorithm confusion, none algorithm, weak HMAC secret.
- **Password reset / magic link flows** – IDOR enabling takeover of high‑privilege accounts.
- **Account locking / rate limiting mechanisms** – bypass leading to brute‑force of admin passwords.
- **“Remember me” tokens** – weak token generation or exposure allowing impersonation of admin users.
- **OAuth2 / social login** – misconfigured redirect_uri, scope injection, or state manipulation that grants admin scopes.
- **Race condition** – simultaneous login attempts, coupon/promo code validation, or parallel requests that escalate a normal login into an admin session.
- **Default credentials** for administrative accounts, hidden admin login endpoints.

## Detection Patterns (Static & Dynamic)
### 1. Mass Assignment to Role / is_admin
- **Heuristic**: The server uses `User(**request.form)` or `User.query.filter_by(**request.form)` during login, or iterates over `request.form` and calls `setattr(user, key, value)`.
- **Dynamic test**: In the login POST, add a parameter like `role=admin` or `is_admin=true`. If the session or JWT then holds that value, escalation is possible.

### 2. Session Cookie Forgery
- **Heuristic**: Flask session secret is weak, predictable, or exposed (e.g., in a public repository, environment variable dump, or hardcoded in client‑side JavaScript).
- **Dynamic test**: If the secret is known, use `flask-unsign` or `itsdangerous` to craft a session cookie with `user_id` of an admin or `role=admin`. Submit it with any request; if it grants admin access, privilege escalation works.

### 3. JWT Token Manipulation
- **Heuristic**: Login endpoint returns a JWT; the decoding logic lacks algorithm verification (`jwt.decode(token, verify=False)`) or uses a weak secret.
- **Dynamic test**:
  - Change the `alg` header to `none` and remove the signature.
  - If the server accepts it, escalate by modifying `sub` or `role` claim to an admin user.
  - Brute‑force weak HMAC secrets with `jwt-cracker` or `hashcat` and then forge tokens.

### 4. IDOR in Password Reset (Targeting Admin)
- **Heuristic**: Password reset token generation includes a user‑supplied user ID, or the endpoint allows changing the target user ID.
- **Dynamic test**: Using own account’s valid reset token, modify the `user_id` parameter to an admin’s ID. If the password is changed, account takeover is achieved, leading to privilege escalation.

### 5. Brute‑Force on Admin Accounts
- **Heuristic**: No rate limiting or account lockout on the login form.
- **Dynamic test**: Enumerate valid admin usernames (e.g., `admin`, `administrator`, `root`), then perform a dictionary attack. If successful, high‑privilege access is gained.

### 6. Race Condition to Admin Session
- **Heuristic**: Login process has multiple steps (e.g., OTP verification after password) with a temporary session holding `pending_user_id`. By sending parallel requests, an attacker might swap the pending user ID to an admin’s ID during the window.
- **Dynamic test**: Login with own credentials, intercept the OTP step, and in parallel send a request that sets `pending_user_id=admin` just before the OTP is verified.

### 7. OAuth Scope Escalation
- **Heuristic**: The login flow with third‑party providers (Google, GitHub) requests only basic scopes, but the server trusts a client‑supplied `scope` parameter or does not validate the returned scopes. An attacker can manually add admin scopes to the authorisation request.
- **Dynamic test**: In the OAuth redirect, change `scope=openid email` to `scope=openid email admin`. If the server uses the returned scope claim to assign roles, escalation may occur.

## Testing Methodology (AI Agent Steps)
1. **Reconnaissance & Privilege Mapping**
   - Identify roles: low‑privileged user, moderator, admin, superadmin. Note the differences in accessible pages/functions.
   - Identify how privileges are stored: session, JWT, database column (`role`, `is_admin`).

2. **Test Direct Parameter Injection**
   - During login, inject `role=admin`, `is_admin=1`, `group=administrators`, etc. Check the response, subsequent session data (cookie or JWT payload).
   - If login returns a JWT, decode it to see if injected fields appear in the payload.

3. **Session Cookie Forgery**
   - Search for Flask secret key in source code, error messages, environment variables, or typical weak keys (`'secret'`, `'dev'`, `'CHANGE_ME'`).
   - Use `flask-unsign --sign --cookie "{'user_id':1,'role':'admin'}" --secret 'secret'` to craft cookie. Test on admin endpoints.

4. **JWT Attacks**
   - Decode the token, test `alg:none` with modified payload.
   - Try `alg:HS256` but with a weak secret; use `jwt_tool` or `jwt.io` to test.
   - If the server uses `RS256`, try to change the algorithm to `HS256` and sign with the public key (algorithm confusion).

5. **Admin Account Takeover via IDOR in Reset**
   - Trigger password reset for own account, capture the reset link. Change any user identifier in the link/request to an admin’s ID. If it resets admin’s password, you have escalated.

6. **Brute‑Force Admin Credentials**
   - Use a wordlist with common admin usernames and weak passwords (`admin:admin`, `root:password`, etc.).
   - Check for rate limiting: if none, automate. If there is lockout, try password spraying.

7. **Exploit Race Conditions**
   - Use Burp Intruder or a Python script to send two concurrent requests: one that continues your login and another that changes `session['user_id']` to an admin ID. Look for TOCTOU.

8. **OAuth Scope Manipulation**
   - During social login flow, manually modify the authorisation URL to include additional scopes. After callback, check the access level.

9. **Check for Hidden Admin Login Endpoints**
   - `/admin/login`, `/login/admin`, `/auth/admin` – might have weaker security or different authentication logic.

10. **Verify Escalation**
    - Access admin‑only functions: `/admin`, `/admin/users`, `/dashboard?role=admin`, etc.
    - Retrieve list of all users, change server configurations, etc.

## Essential Payloads (Flask Login Privilege Escalation)
### Mass Assignment (form‑encoded / JSON)
```
username=lowpriv&password=pass&role=admin
{"username":"lowpriv","password":"pass","is_admin":true}
```

### Flask Session Forging (with known secret)
```bash
flask-unsign --sign --cookie '{"_user_id":"1","role":"admin"}' --secret 'dev_secret'
```

### JWT None Attack
Header: `{"alg":"none","typ":"JWT"}`
Payload: `{"sub":"admin","role":"admin"}`
Send as `Authorization: Bearer <encoded_token_without_signature>`

### JWT Algorithm Confusion (RS256 to HS256)
If public key is available, convert it to HMAC secret and sign token with modified claims.

### IDOR in Password Reset
```http
POST /reset-password HTTP/1.1
...
user_id=123&new_password=AdminTakeover123&token=YOUR_VALID_TOKEN
```
(Change user_id to admin’s ID.)

### Brute‑Force List (usernames)
`admin`, `administrator`, `root`, `system`, `support`, `webmaster`

### Race Condition – Parallel Requests (example)
- Request 1: `POST /login/step2` with `user_id=attacker&otp=...`
- Request 2: `POST /login/set_pending_user` with `pending_user_id=admin` (if such endpoint exists)
Send simultaneously.

## Secure Coding Recommendations
- **Never trust client‑supplied privilege attributes** during login. Retrieve user role from the database after authentication.
- Use strong, random Flask secret keys, stored securely (environment variables, not source code). Rotate regularly.
- **JWT**: always specify the expected algorithm in `jwt.decode()`; never accept `"none"`. Use strong RSA keys for asymmetric signing.
- **Session management**: Regenerate session ID after login (`session.clear()` in Flask). Use `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_SAMESITE='Strict'`.
- Implement rate limiting (Flask-Limiter) and account lockout on login, but ensure lockout can’t be used for denial of service against admins.
- Password reset tokens must be random, stored server‑side, and associated with the session, not the user ID. Do not accept user ID in the reset request.
- Avoid race‑condition‑prone multi‑step login flows. Use atomic transactions.
- For OAuth, strictly validate the `redirect_uri` against a whitelist and only request minimal scopes; never trust client‑supplied scopes.

## Output Format (Bug Report)
```
Title: Privilege Escalation via Role Parameter Injection in Login Form
Severity: Critical (CVSS 9.8)
Endpoint: POST /login
Vulnerable Parameter: role (injected)
Description:
  The login endpoint accepts an extra `role` parameter and assigns it directly to the user's session without validation. A low‑privilege user can elevate to administrator by including `role=admin` in the login request.
Proof of Concept:
  curl -X POST https://target.com/login -d "username=lowpriv&password=pass&role=admin"
  Subsequent requests to /admin are successful.
Remediation: Only extract expected fields (username, password) from the login request; determine role server‑side after authentication.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with any authentication mechanism
- **Testing Type**: Black-box / Grey-box (requires multiple account levels or knowledge of admin account identifiers)
- **Dependencies**: None; AI can identify insecure patterns and generate escalation payloads.