# 🧩 Flask Login Form – Mass Assignment / Parameter Binding – AI Bug Bounty Skill

## Skill Name
`flask-mass-assignment-login`

## Description
Focused detection and exploitation of Mass Assignment vulnerabilities within Python Flask login and authentication processes. This skill analyses whether user‑supplied parameters beyond the intended `username` and `password` are blindly bound to internal object models, database queries, or session data during login. Attackers can inject extra fields (e.g., `role`, `is_admin`, `is_verified`, `email`, `two_factor_enabled`, `account_status`) to escalate privileges, bypass account verification, overwrite sensitive attributes, or corrupt authentication logic.

## Affected Components
- **API‑style login endpoints** that accept JSON and directly instantiate or update a model:
  ```python
  data = request.get_json()
  user = User(**data)  # or User.query.filter_by(**data).first()
  ```
- **ORM object creation** using `Model(**request.form)` or `Model(**request.args)` without field filtering.
- **Flask‑RESTful `reqparse.RequestParser`** with `argument('...', location='json')` that catches all fields when strict mode is off.
- **`flask_restful` / `marshmallow` schemas** that allow unknown fields and then pass them to the domain layer (`User(**unknown_fields)`).
- **Dynamic attribute assignment** after failed login:
  ```python
  user = User.query.filter_by(username=request.form['username']).first()
  if not user:
      user = User(username=request.form['username'])  # and other supplied fields
      db.session.add(user)
  ```
- **Login‑coupled registration** (single form for sign‑in/sign‑up) that assigns attributes like `role` from hidden inputs.
- **“Remember me” / session customisation** that sets session data from arbitrary POST parameters (e.g., `session['theme'] = request.form.get('theme')` without restriction, leading to session poisoning or privilege escalation).
- **Forgot‑password flows** that allow setting a new password on a user object identified by a client‑supplied parameter and then also bind other supplied attributes (e.g., `email`, `security_question`).

## Detection Patterns (Static & Dynamic)
### 1. Model Constructor with Unfiltered Input
- **Heuristic**: `User(**request.form)` or `User(**request.get_json())` anywhere in the login route.
- **Dynamic test**: Add an extra field to the login request (e.g., `"role": "admin"`) and check if the user object or session is altered accordingly (e.g., `current_user.role` becomes `admin` after login).

### 2. ORM Filter Bypass via Extra Parameters
- **Heuristic**: `User.query.filter_by(**request.args)` used to authenticate a user. By supplying additional column names, an attacker might alter the filter logic.
- **Dynamic test**: Send `username=admin&password=anything&is_active=true` – if the filter includes `is_active=true`, it might bypass a disabled account check.

### 3. `setattr` / `update` on the User Object
- **Heuristic**: After fetching a user, the server iterates over `request.form.items()` and sets attributes:
  ```python
  for key, value in request.form.items():
      setattr(user, key, value)
  ```
- **Dynamic test**: Supply `role=admin` or `is_verified=true` and verify if those fields are now saved on the authenticated user.

### 4. Mass Assignment in Password Reset
- **Heuristic**: The password reset endpoint receives a user identifier and a new password, but also accepts other attributes that get assigned to the user (e.g., `email`, `role`).
- **Dynamic test**: When resetting password, include `role=admin` in the request; check if the user’s role is elevated after reset.

### 5. Session Data Tampering via Extra Fields
- **Heuristic**: `session['role'] = request.form.get('role')` during login.
- **Dynamic test**: Send a login request with `role=admin`; if the session stores this value and later used for authorisation, privilege escalation occurs.

## Testing Methodology (AI Agent Steps)
1. **Identify Login Request Structure**
   - Determine if the login accepts `application/x-www-form-urlencoded`, `multipart/form-data`, or `application/json`.
   - List all standard fields: typically `username`, `password`, `remember_me`, `csrf_token`.

2. **Inject Additional Parameters**
   - Add plausible model attribute names: `role`, `is_admin`, `admin`, `is_verified`, `verified`, `is_active`, `active`, `account_type`, `plan`, `tier`, `email`, `phone`, `two_factor_enabled`, `is_superuser`, `level`, `group_id`.
   - Try booleans (`true`, `1`, `True`), strings (`admin`), or integers.
   - Send request and observe response: does it succeed? Does the login return a user profile that reflects the injected attributes?

3. **Check for Persistent Changes**
   - After logging in with extra fields, re‑fetch the user profile (e.g., `GET /profile`) or log out and log back in normally to see if the injected role persists (i.e., stored in database).
   - If the application uses JWT, decode the token after login – injected fields may appear in the JWT payload, granting immediate elevated access.

4. **Test for Role/Privilege Escalation**
   - If you can inject `is_admin=true`, attempt to access admin endpoints.
   - If you can inject `plan=enterprise`, check if premium features become available.
   - Try to overwrite `email` to a different address – this may allow account takeover if verification is bypassed.

5. **Abuse Filter Injection**
   - Supply extra columns that exist in the user table (discovered via error messages or enumeration):
     `username=admin&password=anything&is_active=false` – if the query becomes `filter_by(username='admin', password='anything', is_active=False)`, login will fail, but this reveals the existence of the column. Try `is_active=true` to activate a disabled account.

6. **Multi‑step Mass Assignment**
   - In password reset, after receiving the reset token, the password change request might also bind other fields. Inject `role=admin` along with the new password.
   - In MFA setup, the verification step might accept extra parameters that modify user attributes.

7. **Bypass Validation/Schema Checks**
   - If the application uses Marshmallow with `unknown=INCLUDE` or `EXCLUDE` but then passes all data to the model, test with unknown fields.
   - If a schema is used but the loaded data is later merged with raw `request.json`, try to bypass the schema by sending additional fields that the schema does not define.

## Essential Payloads (Flask Login Mass Assignment)
### Basic Role Escalation
- Add to request body:
  ```json
  {"username": "attacker", "password": "pass", "role": "admin"}
  ```
  or in form‑encoded:
  ```
  username=attacker&password=pass&role=admin
  ```

### Boolean Attributes
- `is_admin=true`
- `is_verified=true`
- `is_active=true`
- `is_superuser=1`

### Account Tier/Plan Manipulation
- `plan=enterprise`
- `tier=premium`
- `account_type=moderator`

### Email/Contact Overwrite (Potential Account Takeover)
- `email=attacker@evil.com` (if login also updates email without verification)
- `phone=+1234567890`

### Multi‑Step Example (Password Reset)
- After obtaining a valid reset token for own account:
  ```
  POST /reset-password
  token=YOUR_TOKEN&new_password=NewPass123&role=admin
  ```
  The user’s role is upgraded during password reset.

## Secure Coding Recommendations
- **Never bind user‑supplied data directly to model constructors or `update()` methods.** Use an explicit allowlist.
- **Define a strict schema** (e.g., Marshmallow) with only the expected fields, and set `unknown=RAISE` or `EXCLUDE` and never pass unknown fields to the model.
- **Manually assign expected fields**:
  ```python
  username = request.form['username']
  password = request.form['password']
  # Do not do User(**request.form)
  ```
- **Separate login logic from profile updates.** Login should only authenticate; attribute changes should happen in dedicated, authorised endpoints.
- **Use Flask‑Login / session properly:** roles and permissions must not be controllable by the client.
- **Validate all inputs** against business rules, even if they are not supposed to be there.
- **Log and alert on unexpected parameters** in login requests as a possible attack indicator.

## Output Format (Bug Report)
```
Title: Mass Assignment Allows Privilege Escalation via Login Endpoint
Severity: Critical (CVSS 9.8)
Endpoint: POST /login
Vulnerable Parameter: JSON body (extra fields)
Description:
  The login endpoint accepts arbitrary JSON fields and uses them to update the authenticated user object. An attacker can supply `{"username":"attacker","password":"pass","role":"admin"}` and gain administrative privileges.
Proof of Concept:
  curl -X POST https://target.com/login -H "Content-Type: application/json" -d '{"username":"attacker","password":"pass","role":"admin"}'
  The response includes a session cookie; subsequent requests to /admin are authorised.
Remediation: Only extract `username` and `password` from the request; ignore or reject any extra fields. Use a strict schema.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with any authentication approach (custom, Flask-Login, Flask-Security, Flask-RESTful)
- **Testing Type**: Black-box / Grey-box (requires ability to send arbitrary parameters)
- **Dependencies**: None; AI can identify parameter binding patterns and suggest injection fields.