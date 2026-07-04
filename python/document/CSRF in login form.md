# 🔄 Flask Login Form – Cross-Site Request Forgery (CSRF) – AI Bug Bounty Skill

## Skill Name
`flask-csrf-login`

## Description
Specialised detection and exploitation of Cross-Site Request Forgery (CSRF) vulnerabilities affecting Python Flask login and logout endpoints. This skill examines whether the authentication forms are protected by anti-CSRF tokens, whether those tokens are properly validated, and whether session fixation or login CSRF can be used to hijack user actions, force login to an attacker-controlled account, or chain CSRF with other attacks to compromise user accounts and sensitive data.

## Affected Components
- **Login endpoint** (`/login`, `/signin`, `/auth`) that accepts POST requests without CSRF token validation.
- **Logout endpoint** (`/logout`) that performs state-changing action via GET or unprotected POST.
- **Password change / email update** endpoints that may lack CSRF protection (even if outside the login form per se, often part of auth workflows).
- **OAuth2 / third-party login callback endpoints** that process state-changing parameters without CSRF checks.
- **Any state-changing endpoints** accessible after login but protected only by session cookie (if combined with login CSRF, attacker can force victim to perform actions in their own account).
- **Flask-WTF CSRF protection** misconfiguration (e.g., `WTF_CSRF_ENABLED = False` in production, or `@csrf.exempt` on login route).
- **Custom CSRF implementations** using a hidden field (`csrf_token`) that is not validated on the server side or is predictable (e.g., based on timestamp).

## Detection Patterns (Static & Dynamic)
### 1. Missing CSRF Token in Login Form
- **Heuristic**: The HTML login form does not contain a hidden input field named `csrf_token`, `_csrf_token`, or similar. No `X-CSRFToken` custom header expected.
- **Dynamic test**: Submit a login request without any CSRF token parameter; if login succeeds, CSRF protection is absent.

### 2. Token Not Validated Server-Side
- **Heuristic**: Server accepts request even if the CSRF token is omitted, empty, or an arbitrary string.
- **Dynamic test**: Send request with `csrf_token=invalid` or without the field entirely; observe if the server still processes the login.

### 3. Weak/Predictable CSRF Token
- **Heuristic**: Token is a simple hash of the session ID, a timestamp, or sequential number.
- **Dynamic test**: Generate token externally (e.g., MD5 of known session) and see if accepted.

### 4. Login CSRF (Forced Login Attack)
- **Scenario**: Attacker creates an account, then crafts a hidden form on their malicious site that POSTs credentials to the target login endpoint with attacker's username/password. Victim is tricked into visiting the page, gets logged into the attacker's account, and unknowingly performs actions (like entering credit card info) that the attacker can later access.
- **Heuristic**: Login endpoint has no CSRF protection, and the application stores sensitive user-specific data viewable after login.
- **Dynamic test**: From a different origin, auto-submit a form with attacker credentials to the target login; check if the browser sets the session cookie and redirects to dashboard (with SameSite cookie attributes considered).

### 5. Logout CSRF
- **Heuristic**: Logout is triggered via a simple GET request or an unprotected POST.
- **Dynamic test**: Embed `<img src="https://target.com/logout">` on attacker page; visiting causes the victim to be logged out. This is often a low severity issue but can be used to force the user into a fresh login state for other attacks.

## Testing Methodology (AI Agent Steps)
1. **Map Authentication Endpoints**
   - Identify login URL, logout URL, password reset initiate/confirm URLs.
   - Determine HTTP methods used (GET/POST). Logout via GET is a red flag.
   - Note if `SameSite` cookie attribute is set (Lax/Strict/None).

2. **Inspect CSRF Defences**
   - View page source of login form: look for `<input type="hidden" name="csrf_token" ...>`.
   - If present, attempt to submit without it, with empty value, with another session's token.
   - Check response headers for `Set-Cookie` with `SameSite=Strict` or `Lax`.

3. **Exploit Login CSRF**
   - If no CSRF token is required:
     - Attacker registers a user (e.g., `attacker:password`).
     - Attacker crafts a proof-of-concept HTML page that auto-submits a POST form to the target's login URL with `username=attacker&password=password`.
     - Victim visits the page; if `SameSite` is not `Strict`, browser sends cookies, server logs victim into attacker's account.
     - After redirection, any sensitive data entered by the victim (e.g., search history, profile edits) is associated with the attacker's account, which the attacker can retrieve.
   - If `SameSite=Lax` is set, POST requests from cross-site contexts won't attach cookies by default. However, some browsers or configurations may still allow top-level navigations with GET (login via GET? rare). Login CSRF might still work if the server accepts GET with query parameters (misconfiguration).

4. **Exploit Logout CSRF**
   - Craft `<img>` or `<iframe>` pointing to `/logout`; check if user gets logged out.
   - If `SameSite` is not set, logout request sent with cookies, triggering logout.

5. **Chain CSRF with XSS / Other Bugs**
   - If login form is vulnerable to XSS, CSRF protection can be bypassed by reading the token via JavaScript (not CSRF per se, but worth noting).
   - If session fixation is possible, login CSRF can fixate session to attacker's known session.

6. **Bypass CSRF Protections**
   - **Token reuse across sessions**: Check if token is tied to user session. Use a token from a previous session; if accepted, protection is weak.
   - **Empty token bypass**: `csrf_token=` or parameter removal.
   - **Method override**: Use `_method` parameter or `X-HTTP-Method-Override` to change POST to GET; some frameworks only validate CSRF on POST. Login via GET might be accepted.
   - **Double-submit cookie pattern flaws**: If token is in both cookie and request, and server only checks equality, attacker can set a cookie via a different subdomain and forge request.

## Essential Payloads & Proof-of-Concept Templates
### Basic CSRF PoC (HTML auto-submit form)
```html
<html>
  <body>
    <form action="https://target.com/login" method="POST" id="csrf_form">
      <input type="hidden" name="username" value="attacker">
      <input type="hidden" name="password" value="attacker_pass">
    </form>
    <script>
      document.getElementById('csrf_form').submit();
    </script>
  </body>
</html>
```
### For Logout CSRF
```html
<img src="https://target.com/logout" width="1" height="1" style="display:none;">
```
### If Login Supports GET
```html
<img src="https://target.com/login?username=attacker&password=attacker_pass">
```

## Secure Coding Recommendations
- **Enable CSRF protection globally** using Flask-WTF or similar extension.
- **Include a unique CSRF token** in every state-changing form (hidden field) and validate it on the server.
- **Bind the CSRF token to the user's session**, and ensure it changes at login (regenerate after authentication to prevent session fixation + CSRF).
- **Use the `SameSite` cookie attribute**: `SESSION_COOKIE_SAMESITE='Lax'` or `'Strict'` prevents cookies from being sent in cross-origin POSTs (Lax still allows top-level GET navigations). Combine with CSRF tokens for defense-in-depth.
- **Re-authenticate for sensitive operations** (e.g., changing email/password) even with a valid CSRF token.
- **Do not use GET for state-changing endpoints**; logout should be POST.
- **Validate the Referer/Origin header** as an additional check (though not foolproof).

## Output Format (Bug Report)
```
Title: Login Cross-Site Request Forgery (Login CSRF)
Severity: Medium/High (risk depends on application functionality)
Endpoint: POST /login
Affected Users: All users
Description:
  The login form lacks CSRF protection. An attacker can create their own account and craft a malicious webpage that, when visited by a victim, logs the victim into the attacker's account without their knowledge. Any actions or data entered by the victim in that session are then accessible to the attacker.
Proof of Concept:
  (Provide HTML PoC)
Remediation:
  Implement anti-CSRF tokens (Flask-WTF) and set SameSite cookie attribute to Strict/Lax.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with standard login sessions
- **Testing Type**: Black-box/Grey-box (requires testing cross-origin requests)
- **Dependencies**: None; AI can generate PoC HTML and interpret session cookie behavior.