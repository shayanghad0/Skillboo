# 🔑 Flask Login Form – Insecure Direct Object Reference (IDOR) – AI Bug Bounty Skill

## Skill Name
`flask-idor-login`

## Description
Specialised detection and exploitation of Insecure Direct Object Reference (IDOR) vulnerabilities within Python Flask login and authentication flows. This skill analyses how user identifiers, tokens, or object references are used during login, password reset, magic link authentication, and multi‑step verification processes. When the server fails to properly validate that the authenticated (or authenticating) user owns the referenced object, an attacker can gain unauthorised access to other user accounts, reset their passwords, bypass two‑factor authentication, or exfiltrate sensitive pre‑login data.

## Affected Components
- **Passwordless / magic link login**: endpoints that accept a user‑identifying token directly, e.g. `GET /login/verify?token=<token>` or `GET /login/callback?user_id=123&code=...`, where `user_id` can be changed to another user's identifier.
- **Password reset flows**: steps that reference a user via a predictable ID (sequential integer, email, username) without session binding.
  ```python
  @app.route('/reset-password/<user_id>', methods=['POST'])
  def reset_password(user_id):
      new_pass = request.form['password']
      User.query.get(user_id).password = new_pass
      # No check that the requester owns this user_id or that a valid token was provided.
  ```
- **Multi‑factor authentication (MFA) bypass**: endpoint that verifies an OTP against `user_id` supplied in the request body instead of session.
  ```python
  user = User.query.get(request.form['user_id'])
  if user.otp == request.form['otp']: login_user(user)
  ```
- **Pre‑login data endpoints**: `GET /api/users/<id>/profile` that return user details (email, phone, avatar) before authentication, often used to pre‑fill login forms.
- **Account existence enumeration**: `POST /login/check-username` or `GET /api/user/exists?username=admin` that returns distinct statuses, coupled with direct object references in other calls.
- **“Remember me” token generation** that includes a user‑supplied user ID without integrity checks.
- **OAuth2 state/user binding** where the state parameter is linked to a user ID that can be tampered with.

## Detection Patterns (Static & Dynamic)
### 1. Predictable or Sequential Object IDs
- **Heuristic**: URLs or request bodies contain `user_id`, `id`, `uid`, `account`, `profile_id`, `customer_id` as integers, short hashes, or easily guessable strings.
- **Dynamic test**: Change the ID to another plausible value (e.g., 1 → 2, or add ±1) and observe if the response returns data belonging to a different user or performs an action on their behalf.

### 2. Missing Ownership Validation
- **Static code pattern**:
  ```python
  user = User.query.get(request.args.get('user_id'))
  # No check like: if current_user.id != user.id: abort(403)
  ```
- **Dynamic test**: While logged in as User A, manipulate the `user_id` in a password change or profile update request to target User B; if the operation succeeds, IDOR is confirmed.

### 3. Token/Payload Manipulation
- The login form sends a JSON payload like `{"user": 123, "password": "test"}`. Changing the `user` field to `124` might authenticate the attacker as user 124 if the password check is performed on the supplied ID rather than the session.
- **Heuristic**: The server trusts the `user` identifier from the client after authentication instead of retrieving it from a verified session.

### 4. Information Disclosure via IDOR
- An endpoint like `GET /login/user-photo?user_id=5` that serves the user's avatar; manipulating `user_id` reveals photos of other users (privacy issue).

### 5. Mass Assignment / Parameter Pollution
- The login form includes hidden fields like `role`, `is_admin`, or `user_level` that the server uses directly to create or update a user object.

## Testing Methodology (AI Agent Steps)
1. **Map Object Identifiers**
   - Crawl the login and related authentication flows. Record all request parameters that look like user references (`user_id`, `uid`, `account_id`, `id`, `email`, `phone`, `reset_token`, `session_id`).
   - Note the format: sequential integers, UUIDs, hashes, or encoded values. Try decoding base64 if applicable.

2. **Identify Sensitive Actions & Data**
   - Actions: password reset, OTP verification, magic link generation, account recovery, email change, MFA enrollment.
   - Data: pre‑filled login forms that show user’s email, phone, or profile picture.

3. **Baseline Behaviour**
   - Perform each action with your own account; capture the request and response.
   - Note any parameters that can logically be altered to refer to another user.

4. **Test for Horizontal IDOR**
   - Replace your user ID with another valid ID (e.g., increment by 1). If you gain access to another user’s data or can perform actions on their behalf, horizontal IDOR exists.
   - Repeat for all identified parameters and endpoints.

5. **Test for Vertical IDOR**
   - Check if any role or permission parameter is accepted. Try escalating privileges by changing `role=user` to `role=admin` in login or profile update requests.
   - Test if an unauthenticated user can supply a user ID to bypass authentication entirely (e.g., `GET /login?user_id=1&auto_login=true`).

6. **IDOR in Multi‑Step Processes**
   - For password reset: intercept the request where you submit the new password. Often the user ID or reset token is included. If the server doesn’t verify that the token belongs to the session, you can change the password for another user by using your own valid token but altering the user ID.
   - For magic links: copy the magic link and change the `user_id` query parameter; check if it logs you in as the victim.

7. **Bypassing Protections**
   - Some apps use hashed or encoded identifiers. If the hash is reversible (MD5, base64), decode it to discover the original ID, then encode a target ID.
   - UUIDs are generally not vulnerable unless the application leaks them (e.g., in password reset links that also accept an `id`).
   - If the app uses session‑scoped tokens but also accepts a user‑supplied ID, try removing the token header or cookie – some endpoints fall back to trusting the ID if the token is missing.

## Essential Payloads (Flask Login IDOR)
### Parameter Manipulation Examples
- **Password reset**:
  ```
  POST /reset-password HTTP/1.1
  ...
  user_id=2&new_password=Attacker123!
  ```
  If user_id=2’s password is changed, IDOR confirmed.

- **Magic link login**:
  ```
  GET /login/magic?user_id=2&token=VALID_TOKEN_FROM_ATTACKER_EMAIL
  ```
  (Attacker obtains own valid token, then replaces user_id to victim’s ID.)

- **MFA/OTP bypass**:
  ```
  POST /verify-otp
  user_id=2&otp=123456
  ```
  (If the server doesn’t check that user_id matches the session’s pending MFA user.)

- **Pre‑login data leakage**:
  ```
  GET /api/user/profile?user_id=2
  ```
  Returns victim’s email/phone.

### Fuzzing List for Common Parameter Names
- `user_id`
- `uid`
- `id`
- `user`
- `account`
- `customer_id`
- `profile_id`
- `email` (used as identifier)
- `phone`
- `token` (if predictable or tied to user)

## Secure Coding Recommendations
- **Never trust client‑supplied object identifiers for authentication‑critical operations.** Retrieve the current user from the session (`current_user` from Flask-Login) and use that as the target for actions (e.g., only the logged‑in user can change their own password).
- For password reset and magic link flows, generate a cryptographically secure random token and store it on the server mapped to the user. Do **not** include the user ID in the link; instead, look up the token server‑side.
- Implement resource ownership checks: `if target_user_id != current_user.id: abort(403)`.
- Use indirect object references (e.g., a random UUID instead of sequential integer) only if necessary, but still enforce ownership.
- Avoid exposing user data in pre‑login endpoints; if needed, only reveal minimal non‑sensitive information.
- Log and monitor for abnormal ID manipulation attempts.

## Output Format (Bug Report)
```
Title: IDOR in Password Reset Allows Unauthorised Password Change
Severity: Critical (CVSS 9.1)
Endpoint: POST /reset-password
Vulnerable Parameter: user_id
Description:
  The password reset endpoint accepts a `user_id` parameter alongside the new password, but does not validate that the requestor is authorised to reset that user’s password. An attacker with a valid password reset token (their own) can change the password of any other user by supplying their victim’s user_id.
Proof of Concept:
  1. Attacker initiates password reset for own account (user_id=5), receives token.
  2. Submits POST /reset-password with:
     user_id=6&password=AttackerPass123&token=ATTACKER_VALID_TOKEN
  3. Victim (user_id=6) can no longer log in with old password.
Remediation:
  Remove user_id from the request; derive the user from the token via server-side lookup. Ensure the token is single‑use and expires quickly.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with any authentication pattern (custom, Flask-Login, Flask-Security)
- **Testing Type**: Black-box / Grey-box (requires at least two valid user accounts)
- **Dependencies**: None; AI can manipulate identifiers and analyse responses.