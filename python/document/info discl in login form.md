# 🕵️ Flask Login Form – Information Disclosure – AI Bug Bounty Skill

## Skill Name
`flask-info-disclosure-login`

## Description
Systematic detection and exploitation of information disclosure vulnerabilities within Python Flask login forms. This skill analyses how the login process – including error messages, HTTP headers, timing differences, debug outputs, redirected parameters, and source code comments – may unintentionally reveal sensitive information to an attacker. The leaked data can range from user existence (usernames/emails), internal file paths, software versions, database schema, and secret keys to full environment variables and source code. Such information aids further attacks like credential brute-forcing, session hijacking, or even remote code execution by exposing hardcoded secrets.

## Affected Components
- **Login error messages**: differentiating "user not found" vs. "incorrect password".
- **Password reset / forgot password flows**: revealing whether an email is registered.
- **Flask debug mode** (`app.debug = True`) exposing Werkzeug debugger and interactive shell on errors.
- **Verbose error pages**: stack traces, database error messages, file paths, and code snippets when an exception occurs during authentication.
- **HTTP response headers**: `Server`, `X-Powered-By`, `Set-Cookie` attributes lacking `Secure` or `HttpOnly`.
- **HTML source code and client‑side comments** containing internal endpoints, test credentials, or developer notes.
- **Session cookie inspection**: unencrypted session data (Flask default is signed but not encrypted) reveals internal data structures, user IDs, roles if manually decoded.
- **Default error handling** for invalid HTTP methods or malformed requests that return server environment details.
- **Directory listing** on static folders or template directories that expose login template source.
- **Timing side‑channels**: measurable delay differences for valid vs. invalid usernames (e.g., bcrypt comparison takes longer for existing users).

## Detection Patterns (Static & Dynamic)
### 1. User Enumeration via Error Messages
- **Heuristic**: `return "Invalid username"` vs. `return "Wrong password"`.
- **Dynamic test**: Attempt login with a known/random username and a wrong password. If the error changes from “User not found” to “Password incorrect”, user enumeration is possible.

### 2. Verbose Stack Traces / Debug Mode
- **Heuristic**: `app.debug = True`, or no custom error handler for 500 errors.
- **Dynamic test**: Cause an error (e.g., send `' OR 1=1--` in username). If the response contains a full Python traceback with file paths and code lines, debug mode is enabled.

### 3. Flashed Messages / Session Content Leak
- **Heuristic**: Flask’s `flash()` messages that echo back user input or show internal data like `User ID: 123`.
- **Dynamic test**: Decode the Flask session cookie (Base64). It may contain unencrypted data like `{"_user_id": 1, "csrf_token": "..."}`. This reveals internal naming and possibly user IDs.

### 4. Password Reset Information Leak
- **Heuristic**: Forgot‑password endpoint returns different responses for existing vs. non‑existing emails, or returns the email in clear after a request.
- **Dynamic test**: Request reset for `admin@example.com` and `nonexistent@example.com`. If messages differ, enumeration is possible.

### 5. Source Code Disclosure via Parameters
- **Heuristic**: `render_template(request.args.get('template') + '.html')` without sanitisation (LFI leads to source disclosure). Reading `app.py`, `config.py`, or `.env` files.
- **Dynamic test**: (Covered by LFI, but also disclosure of sensitive files is information disclosure.)

### 6. Banner Grabbing / Server Header Leak
- **Heuristic**: Default Flask responses include `Server: Werkzeug/2.0.2 Python/3.9.7`. This reveals exact versions useful for known exploits.
- **Dynamic test**: Inspect response headers; if not stripped, information disclosure.

### 7. Hardcoded Secrets in JavaScript / HTML
- **Heuristic**: Comments in login HTML containing API keys, `<!-- TODO: change admin password to 'admin123' -->`, `const SECRET = '...'`.
- **Dynamic test**: View page source of login page.

### 8. Default Credentials / Backdoor Accounts
- **Heuristic**: Developer left test credentials in source or as comments.
- **Dynamic test**: Search source for `admin:admin`, `test:test`, etc.

## Testing Methodology (AI Agent Steps)
1. **Passive Reconnaissance**
   - Examine login page source for comments, hidden fields, inline JavaScript.
   - Inspect HTTP response headers (`Server`, `X-Powered-By`, `Set-Cookie` flags).
   - Decode Flask session cookie if present (split on `.`, take first part, Base64 decode) – it may leak user data or CSRF tokens.
   - Note any version strings in error pages or custom 404/500 pages.

2. **Active Probing – Error Message Analysis**
   - Submit login requests with varied inputs: valid username + invalid password, invalid username + any password.
   - Record exact error messages; if they differ, user enumeration is confirmed.
   - Use an automated tool or AI to differentiate subtle differences (e.g., “Login failed” vs. “Invalid credentials” might still be distinct in HTTP body length or CSS class).

3. **Password Reset Flow Enumeration**
   - Trigger password reset for known email and non‑existent email.
   - Check response content, HTTP status code, and timing. Even if message is the same (“If that email exists…”) but the response time differs (sending email in background), it’s a side‑channel.

4. **Exploit Debug Mode**
   - Force an unhandled exception: e.g., send malformed JSON, extremely long strings, or the SSTI probe `{{config}}` in username. If a Werkzeug debugger console appears (or a traceback with a PIN‑protected interactive shell), the server is in debug mode.
   - If the debugger is accessible, attempt to generate the console PIN using known algorithms (Werkzeug console PIN generation based on public machine info) and execute arbitrary code.

5. **File/Path Disclosure**
   - Trigger path traversal (if LFI suspected) to read `/etc/passwd` or `/proc/self/environ` to disclose environment variables (including secrets).
   - Cause template not found errors to reveal template directory structure.

6. **Timing Attack for User Enumeration**
   - Send many requests with random usernames and a fixed wrong password; measure response times. If a particular username consistently takes longer (due to bcrypt hash computation), it indicates a valid user.

7. **Configuration Disclosure via `config` Object**
   - If SSTI exists, dump `{{config}}`. If debug mode or a custom error page echoes config, secrets (SECRET_KEY, DATABASE_URL, API keys) will be leaked.

8. **Backup / Repository Exposure**
   - Check for common paths like `/.git/HEAD`, `/.env`, `/templates/login.html~`, `/backup/`. These may expose source code or configuration.

## Essential Payloads & Techniques (Information Disclosure)
### User Enumeration Payloads
- **Username list**: brute‑force with common admin users (`admin`, `root`, `test`) and observe error differences.
- **Password reset**: `POST /forgot-password` with `email=admin@target.com` vs. `email=invalid@target.com`.
- **Timing**: Python script that sends 10 requests per username, logs average response time.

### Debug Mode Trigger Payloads
- `username={{config}}` (SSTI) – if debug returns traceback, Flask config values may appear.
- `username=' OR 1=1--` (SQLi) – may cause SQL error revealing DB schema, table names.
- Send an array where a string is expected: `{"username": ["admin"]}` – may cause 500 error.
- Extremely long strings in any field to trigger `MemoryError` or `Request too large`.

### Session Cookie Decoding
```bash
# Split cookie by dot, take first segment, base64 decode
echo 'eyJfZnJlc2giOmZhbHNlLCJjc3JmX3Rva2VuIjoi...' | base64 -d
```
Often reveals `_fresh`, `_user_id`, `csrf_token`, `_permanent`.

### Path Probing for Config Files
- `GET /.env` (Flask‑dotenv)
- `GET /config.py`
- `GET /settings.py`
- `GET /.git/config`
- `GET /templates/login.html` (if directory listing enabled)

### HEAD Request for Banner Grabbing
- `HEAD /login HTTP/1.1` – observe `Server` header.

## Secure Coding Recommendations
- **Generic error messages**: Use identical, generic messages for login failures regardless of whether the user exists. E.g., “Invalid username or password.”
- **Disable debug mode in production**: `app.debug = False`. Set `FLASK_ENV=production`.
- **Custom error handlers**: Use `@app.errorhandler(500)` to return a generic error page without stack traces.
- **Remove/Suppress server headers**: `app.config['SERVER_NAME']` not directly controlling headers; use middleware or a reverse proxy to strip `Server` header, or start Flask with `app.run(debug=False, ...)`.
- **Secure session cookies**: `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE='Lax'`.
- **Avoid exposing secrets in client‑side code**: Never embed API keys, tokens, or credentials in HTML or JavaScript.
- **Rate‑limit login and password reset endpoints** to hinder user enumeration and brute‑force.
- **Regularly audit code and configurations** for hardcoded secrets.
- **Disable directory listing** on the web server.
- **Use consistent response times**: implement timing‑safe comparison for usernames/passwords (though complex) or add random delay to prevent timing side‑channels.

## Output Format (Bug Report)
```
Title: User Enumeration via Login Error Message
Severity: Medium (CVSS 5.3)
Endpoint: POST /login
Vulnerable Parameter: username / email
Description:
  The login form returns distinct error messages for "User not found" and "Incorrect password". An attacker can enumerate valid usernames/emails for further attacks.
Proof of Concept:
  1. POST /login with username=invalid_user&password=test → response: "User not found"
  2. POST /login with username=admin&password=test → response: "Incorrect password"
  This difference confirms admin user exists.
Remediation:
  Use a generic error message like "Invalid username or password" for all failed login attempts.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with default or custom authentication
- **Testing Type**: Black-box / Grey-box (with ability to inspect responses)
- **Dependencies**: None; AI can parse HTTP responses and perform pattern matching.