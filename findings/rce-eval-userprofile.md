# Finding: Remote Code Execution — eval() in User Profile

| Field | Value |
|-------|-------|
| **File** | `routes/userProfile.ts` |
| **Line** | 65 |
| **Rule** | `javascript.lang.security.audit.eval-detected.eval-detected` |
| **Severity** | HIGH |
| **CWE** | CWE-94: Code Injection / RCE |
| **Runtime confirmed** | ✅ Yes |

## Vulnerable code

```typescript
if (utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
  if (username?.match(/#{(.*)}/) !== null) {
    req.app.locals.abused_ssti_bug = true
    const code = username?.substring(2, username.length - 1)
    try {
      if (!code) throw new Error('Username is null')
      username = eval(code) // eslint-disable-line no-eval
    } catch (err) {
      username = '\\' + username
    }
  }
}
```

## Source → Sink

**Source**: `user.username` read from the database (`UserModel.findByPk`)  
**Sink**: `eval(code)` — JavaScript code execution

## Why it's exploitable

The route reads the authenticated user's `username` from the database. If the username matches the pattern `#{...}`, the content between the braces is extracted and passed directly to `eval()`. An attacker who can set their username to `#{process.mainModule.require('child_process').execSync('id')}` would achieve server-side RCE.

The source is the database, so this requires the attacker to have already set a malicious username — exploitable via the profile update endpoint (which does not sanitize username).

**Attack chain**: `PUT /rest/users/me` with username `#{require('child_process').execSync('id')}` → `GET /profile` → RCE on the server.

## Proof of concept

1. Set username via `PUT /rest/users/me`: `{"username": "#{require('child_process').execSync('id').toString()}"}`
2. Load `GET /profile`
3. Server executes the command; return value rendered in profile page

**Confirmed in runtime** — attack chain executed end-to-end.

## Fix

Remove the `eval()` entirely. The SSTI challenge it implements should be served by a safer template mechanism. If the challenge must remain, use an allowlist of safe expressions rather than arbitrary code execution.
