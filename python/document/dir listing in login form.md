# 📁 Flask Login Form – Directory Listing – AI Bug Bounty Skill

## Skill Name
`flask-dir-listing-login`

## Description
Detection and exploitation of directory listing vulnerabilities affecting Python Flask login forms. This skill analyses whether the web server (or Flask’s built‑in static file serving) is misconfigured to expose directory contents when no index file is present. Attackers can list directories related to the authentication flow – templates, configuration files, backup archives, version control directories – and obtain sensitive files such as login template source code, database credentials, API keys, Flask secret keys, and user data. This information dramatically aids credential brute‑forcing, session forgery, and code injection attacks against the login mechanism.

## Affected Components
- **Web server configuration** (Nginx, Apache) with `autoindex on` or `Options +Indexes` for the application’s root or sub‑directories.
- **Flask’s built‑in static file serving** (development server or `send_from_directory` without proper restrictions) that may expose directories if a directory path is requested.
- **Poorly structured project layout** where sensitive directories are served as static files: `/static/config/`, `/static/templates/`, `/backups/`, `/logs/`.
- **Login‑related directories** accessible from the web root:
  - `/templates/` – exposes Jinja2 login templates (`login.html`, `base.html`) revealing form structure, hidden fields, CSRF token names, client‑side validation, and sometimes hardcoded test credentials.
  - `/static/` – if directory listing is enabled, reveals JavaScript files that may contain login logic, API endpoints, or secrets.
  - `/config/`, `/settings/` – configuration files with `SECRET_KEY`, database URIs.
  - `/backup/`, `/old/` – backup copies of `app.py`, `auth.py`, or `.env` files.
  - `/.git/` – version control data that can be downloaded to reconstruct the full source.
  - `/login/` (if treated as a file path) – might list files if the login route handler mistakenly uses `send_from_directory` with a user‑controlled parameter.
- **Template loading by path** with user input (e.g., `?template=login`) may inadvertently be combined with directory traversal to list directories (covered in LFI, but if the server returns a directory listing as a response, that’s also a directory listing issue).

## Detection Patterns (Static & Dynamic)
### 1. Web Server Indexing Enabled
- **Heuristic**: Response for a directory URL (e.g., `/templates/`) returns an HTML page with a file list, not a 404 or 403.
- **Dynamic test**: Request common directory paths (see list below). If the response contains `<title>Index of /templates</title>` or similar auto‑index output, directory listing is active.

### 2. Development Server Directory Listing
- Flask’s development server (`app.run()`) does not serve directory listings by default; it returns 404. However, if the application defines a custom route that serves files with `send_from_directory` and the URL path maps to a directory, a listing may be returned depending on the operating system and how the call is made.

### 3. Misconfigured Reverse Proxy
- Nginx or Apache may be configured to serve static files from a directory that also contains sensitive files, and autoindex is enabled. This often affects `/static` or `/assets`.

### 4. Exposed Sensitive File Extensions
- Even if directory listing is disabled, certain files may be accessible individually: `.env`, `.git/config`, `login.html.bak`, `auth.py.swp`. Finding these often indicates a broader misconfiguration that may allow directory listing if requested without a file.

## Testing Methodology (AI Agent Steps)
1. **Enumerate Common Sensitive Directories**
   - Use a wordlist of known paths related to Flask authentication: `/templates`, `/static`, `/config`, `/settings`, `/backup`, `/db`, `/logs`, `/api`, `/admin`, `/login`, `/auth`, `/.git`, `/.svn`, `/venv`, `/env`, `/instance`.
   - For each path, request with a trailing slash to trigger directory listing: `GET /templates/ HTTP/1.1`.

2. **Inspect Response for Directory Index**
   - Look for typical auto‑index HTML tags: `<title>Index of /...</title>`, `<h1>Index of /...</h1>`, or Apache/Nginx default listing.
   - Check response status code: `200 OK` with a list of files; `403 Forbidden` if directory exists but listing is disabled; `404 Not Found` if directory does not exist.

3. **Examine Accessible Directory Contents**
   - If `/templates/` lists files, download `login.html`, `base.html`, `email.html` – they may contain hidden form fields, CSRF token names, validation patterns, and even developer comments with passwords.
   - If `/config/` is listed, look for `config.py`, `settings.py`, `production.py` – contain `SECRET_KEY`, `SQLALCHEMY_DATABASE_URI`, `MAIL_PASSWORD`.
   - If `/.git/` is exposed, use tools like `git-dumper` to download the repository and review the full source code, including commit history for removed secrets.
   - `/backup/` often contains `.sql` files with user tables, `.tar.gz` of the app, or `.env` files.

4. **Probe for Backup and Editor Temporary Files**
   - Even without directory listing, request common backup extensions of login templates:
     `login.html.bak`, `login.html~`, `login.html.swp`, `login.html.save`, `login.html.orig`.
   - If accessible, they contain the source code of the login page, possibly with differences that reveal older, vulnerable code or hardcoded credentials.

5. **Test for Directory Traversal Combined with Directory Listing**
   - If the server uses `send_from_directory('templates', request.args.get('file'))` and does not check for directory, requesting `?file=.` or `?file=/` might list the templates directory. This is both an LFI and directory listing issue.

6. **Analyse Impact**
   - If login template source is obtained, study for: CSRF token field name, hidden fields, client‑side validation bypass opportunities, hardcoded test accounts, comments revealing internal URLs or passwords.
   - If configuration files are downloaded, use the secret key to sign arbitrary Flask session cookies, connect to the database, or decrypt encrypted data.

## Essential Payloads & Paths (Flask Login Directory Listing)
### Common Sensitive Directories
```
/templates/
/templates/auth/
/static/
/static/js/
/static/css/
/config/
/settings/
/backup/
/db/
/logs/
/api/
/admin/
/login/
/auth/
/.git/
/.svn/
/venv/
/env/
/instance/
/__pycache__/
/tests/
/test/
/dev/
```

### Backup Files of Login Templates
```
/templates/login.html.bak
/templates/login.html~
/templates/login.html.swp
/templates/login.html.save
/templates/login.html.orig
/static/js/login.js.bak
/config.py.bak
/config.py~
/app.py.bak
/auth.py.bak
/views.py.bak
/.env.bak
```

### Check Directory Listing via Traversal (if file parameter exists)
```
?file=.
?file=../
?file=/
```

### Tool‑Based Scanning
Use `dirsearch`, `ffuf`, or `gobuster` with a wordlist tailored to Flask projects:
```bash
ffuf -u https://target.com/FUZZ/ -w /path/to/flask-dir-list.txt
```

## Secure Coding Recommendations
- **Disable directory listing in the web server**:
  - **Nginx**: Set `autoindex off;` (default is off) in all server/location blocks.
  - **Apache**: Remove `Options +Indexes` or set `Options -Indexes` in the directory context.
- **Serve static files via a dedicated location** (e.g., `/static/`) and restrict file types if possible. Do not place sensitive files (config, .git, templates) inside the document root.
- **Flask project structure**: Keep templates, configuration, and application code outside the static folder. The only publicly accessible directory should be `static/` for CSS, JS, images.
- **Use `send_from_directory` safely**: Always validate the requested file path, deny directory traversal (`..`, `/`), and ensure the resolved path stays within the intended directory.
- **Restrict access to version control directories**: Add `/.git` and `/.svn` to a deny rule in the web server or use `.htaccess` / Nginx location blocks to return 403.
- **Implement a web application firewall (WAF)** that can detect and block common directory listing requests.
- **Regularly audit exposed directories** with automated tools as part of the CI/CD pipeline.

## Output Format (Bug Report)
```
Title: Directory Listing Exposes Login Template and Configuration Files
Severity: High (CVSS 7.5)
Endpoint: GET /templates/
Description:
  The web server serving the Flask application has directory listing enabled. Accessing /templates/ lists all HTML templates, including login.html and base.html. The source code of the login form reveals the CSRF token field name, hidden parameters, and client‑side validation rules. Furthermore, /config/ is also listable, exposing SECRET_KEY and database credentials.
Proof of Concept:
  curl -v https://target.com/templates/
  Returns an HTML index page listing:
    - login.html
    - base.html
    - email.html
    - admin.html
  Downloading login.html reveals the form structure and CSRF token name.
Remediation:
  Disable directory listing in the web server configuration (Nginx: `autoindex off`, Apache: `Options -Indexes`). Ensure that sensitive directories like /templates are not served publicly.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with any web server (Nginx, Apache, Flask dev server)
- **Testing Type**: Black-box (directory fuzzing) / Grey-box (if source location known)
- **Dependencies**: Directory fuzzing wordlist; AI can generate common paths and interpret responses.