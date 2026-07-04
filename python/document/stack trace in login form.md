# 🪵 Flask Login Form – Stack Trace Information Disclosure – AI Bug Bounty Skill

## Skill Name
`flask-stack-trace-login`

## Description
Identification and exploitation of stack trace leakage originating from Python Flask login endpoints. When the application fails to handle exceptions gracefully, Flask returns a detailed backtrace containing server file paths, code snippets, environment variables, database connection strings, and even passwords. Attackers can trigger such exceptions via crafted input to the login form – malformed parameters, type confusion, or logic errors – and then harvest sensitive information to mount further attacks such as credential theft, source code reconstruction, and remote code execution. This skill addresses both debug-mode and production-level traceback disclosures.

## Affected Components
- Login route handlers (`@app.route('/login', methods=['GET','POST'])`) lacking `try/except` blocks or using overly broad exception catching.
- Flask app running with `PROPAGATE_EXCEPTIONS = True` or without a custom `@app.errorhandler(500)`.
- Debug mode enabled (`app.debug = True`, `FLASK_ENV=development`), which always returns the full Werkzeug debugger.
- The built-in Flask development server, which by default prints tracebacks to the client even if debug is off but `PROPAGATE_EXCEPTIONS` is set.
- Any code inside the login logic that can raise unhandled exceptions: database connections, ORM queries, password hash comparisons, template rendering, or external API calls.
- Jinja2 template rendering exceptions (e.g., `TemplateNotFound`, `UndefinedError`) if user input is passed directly to `render_template_string()`.
- Downstream libraries (SQLAlchemy, Redis, SMTP) whose exceptions are not caught and are propagated to the WSGI layer.
- Configuration files and secrets referenced in the traceback’s local variables.

## Detection Patterns (Static & Dynamic)
### 1. Verbose Error Pages on Invalid Input
- **Heuristic**: Sending a malformed request (e.g., wrong Content-Type, missing required fields, type mismatch) results in a 500 Internal Server Error with an HTML page containing a Python stack trace.
- **Dynamic test**: Submit a login attempt with deliberately broken JSON: `{"username": ["not", "a", "string"], "password": null}`. If the response shows `Traceback (most recent call last)`, the application is leaking stack traces.

### 2. Debug Mode Stack Trace vs. Production Trace
- In debug mode, the Werkzeug debugger returns an interactive HTML traceback with source code context, local variables, and a console prompt (PIN‑protected). This is a critical issue.
- Even if debug mode is off, some configurations still return plain‑text or simple HTML tracebacks when exceptions propagate. The existence of any traceback in responses is an information disclosure.

### 3. Leakage of Environment Variables
- Tracebacks often contain a dump of local variables. If the developer inadvertently loads sensitive values into local variables (e.g., `SECRET_KEY = os.environ['SECRET_KEY']` inside a view function), those values will appear in the traceback.

### 4. File Path Disclosure
- The traceback reveals the absolute path of the source file where the exception occurred (e.g., `/home/appuser/myapp/auth/views.py`). This can be used to map the server file system and discover configuration files.

### 5. Database Information Disclosure
- If a database query fails (e.g., `OperationalError` or `IntegrityError`), the traceback may include the connection string or the actual SQL query with embedded parameters.

## Testing Methodology (AI Agent Steps)
1. **Cause an Exception in the Login Flow**
   - Omit expected parameters: send an empty POST body or missing `password`.
   - Send invalid JSON when the endpoint expects form‑encoded data.
   - Inject unsupported data types: `{"username": 123, "password": false}` where strings are expected.
   - Trigger template errors: if `render_template_string` is used with user input, pass `{{ config }}` or invalid Jinja2 syntax.
   - Trigger database errors: send `' OR 1=1--` to cause SQL syntax error if no parameterisation is used.
   - Send a very long string (e.g., 1MB) to cause a `MemoryError` or `Request Entity Too Large` (less common).

2. **Analyse the Response**
   - Check for `500 Internal Server Error`.
   - Search for the string `Traceback (most recent call last)`.
   - If present, the stack trace is leaking. Document the full content.

3. **Extract Sensitive Information**
   - **Local variables**: Look for `SECRET_KEY`, `PASSWORD`, `API_KEY`, `DATABASE_URL`, `MAIL_PASSWORD`, etc.
   - **Code snippets**: Reveal application logic, including authentication bypass patterns or hardcoded credentials.
   - **File paths**: Reveal the operating system username (e.g., `/home/john/...`) and directory structure.
   - **Database queries**: May show table names, column names, and even query results if they are part of the exception message.
   - **Third‑party library names and versions**: Help an attacker find known vulnerabilities.

4. **Reconstruct the Application**
   - With file paths and code snippets, attackers can often guess other endpoints, locate configuration files, and plan further attacks such as LFI or path traversal.

5. **Escalate to Remote Code Execution**
   - If `SECRET_KEY` is leaked, session cookies can be forged to impersonate any user.
   - If database credentials are leaked, direct database access may be possible.
   - If debug mode is on (full debugger), attempt to calculate the console PIN using leaked machine‑specific data (see “Debug Mode” skill).

## Essential Payloads (Triggering Stack Traces in Flask Login)
### Malformed JSON / Wrong Content-Type
```http
POST /login HTTP/1.1
Content-Type: application/json

not a json
```
- Response: 400 Bad Request or 500 with traceback if not caught.

### Type Mismatch in Form Fields
```
username[]=admin&password=test
```
If the server uses `request.form.get('username')` and expects a string, but gets a list, it may raise an exception.

### Template Injection to Cause `TemplateSyntaxError`
```
username={{config}}&password=test
```
If `render_template_string` is used and `username` is embedded, this may cause a Jinja2 error revealing file paths and source code context.

### Null Byte Injection
```
username=admin%00&password=test
```
If the code fails to handle null bytes and passes them to `os.system` or a C‑based library, it may crash.

### Large Payload
```
username=AAAAAAAA... (many A's)
```
May cause `MemoryError` or `DatabaseError` (if field length is exceeded and not caught).

## Secure Coding Recommendations
- **Disable debug mode in production**: `app.debug = False`, `FLASK_ENV=production`.
- **Add a custom 500 error handler**: 
  ```python
  @app.errorhandler(500)
  def internal_error(e):
      return render_template('500.html'), 500
  ```
  This prevents Flask from returning a traceback. The original exception can be logged server‑side for debugging.
- **Use `app.config['PROPAGATE_EXCEPTIONS'] = False`** (default is `False`). Only enable if necessary behind a WSGI server that intercepts tracebacks.
- **Catch specific exceptions** in login logic: wrap database queries, password hashing, and external calls in try/except blocks and return a generic “Login failed” message.
- **Avoid storing secrets in local variables** of view functions. Keep them in `app.config` and access them via `current_app.config`, which is not displayed in tracebacks (only if the local variable `current_app` itself is leaked, but configuration values are not expanded).
- **Use a production WSGI server** (Gunicorn, uWSGI) with appropriate error logging. Configure the server to never send tracebacks to the client (e.g., Gunicorn with `--error-logfile` and no `--debug`).
- **Sanitise error messages**: Never include raw exceptions in responses. Log them and show a user‑friendly message.
- **Regularly review code** for unhandled exceptions, especially in authentication paths.

## Output Format (Bug Report)
```
Title: Stack Trace Disclosure via Malformed Login Request
Severity: Medium/High (depending on leaked data)
Endpoint: POST /login
Description:
  The login endpoint does not handle exceptions properly. Sending a malformed JSON body causes a 500 error that returns the full Python stack trace. The traceback includes the Flask secret key, database connection URI, and absolute file paths.
Proof of Concept:
  curl -X POST https://target.com/login -H "Content-Type: application/json" -d 'notjson'
  Response includes:
    Traceback (most recent call last):
      File "/home/appuser/auth.py", line 23, in login
        data = request.get_json()
      ...
      SECRET_KEY = 'supersecretkey'
      DATABASE_URL = 'postgresql://user:pass@localhost/db'
Remediation:
  Add a custom 500 error handler that returns a generic error page and logs the exception server‑side.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with any WSGI server
- **Testing Type**: Black-box / Grey-box (any interaction that may cause an error)
- **Dependencies**: None; AI can generate malformed requests and parse traceback data.