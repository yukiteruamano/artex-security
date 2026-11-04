---
name: hunting-session
description: Load for session management specifics: cookie flags, fixation, rotation, logout invalidation, concurrent sessions, remember-me and cache handling.
---

# Hunting: session management

Sessions are the token that turns an authentication into an authorization. Most session bugs are cheap to test and are graded high because they bypass every credential control.

## 1. Capture the lifecycle
Log every change to the session identifier: before login, at login, after privilege change, after password change, at logout. The identifier must be **new** after an authentication event (fixation defence) and must be **invalidated server-side** at logout (a cookie cleared in the browser is not invalidation).

Prove invalidation, do not assume it: keep a copy of the old cookie and replay it after logout. If it still works, that is the finding.

## 2. Cookie and transport
For every auth cookie record: `HttpOnly`, `Secure`, `SameSite`, `Path`, `Domain`, expiry, and whether it is set over plaintext. Missing `Secure` on an HTTPS-only app is informational; `Domain` widened to a parent domain that hosts other services is not.

## 3. Concurrent sessions and revocation
Do old sessions survive a password change? Can two sessions exist for the same account after "log out everywhere"? Does revoking a role take effect on live sessions? A session that keeps an old authorization state after a downgrade is a privilege-escalation primitive.

## 4. remember-me and derived tokens
Look at how a persistent login works: separate token, signed value, or the password hashed into the cookie. Test whether it survives a password change, whether it is scoped to the user, and whether it can be forged with a recovered key.

## 5. Carriage and caching
Session tokens in URLs leak through referrers, logs and shared links: look for `jsessionid`, `?session=`, token in hash. Also check whether authenticated responses are cacheable (`Cache-Control: private`), because a shared proxy serving a cached authenticated page is a data leak.

## 6. Recording
- Report the exact sequence with the cookie values (they stay verbatim in the graph; masking happens in the report).
- The minimal proof is "cookie from time T still authenticates at time T+1 after event E". Include both requests.