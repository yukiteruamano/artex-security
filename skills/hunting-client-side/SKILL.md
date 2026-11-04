---
name: hunting-client-side
description: Load for XSS (reflected, stored, DOM), CSRF, open redirect, CORS, postMessage and client-side trust bugs.
---

# Hunting: client-side

The browser is the victim's execution environment. The bug is real when *another user's* browser runs your code, in *their* session - not when yours does.

## 1. Find the context, then the break
For every reflection, name the exact context: HTML text, attribute (quoted/unquoted), URL attribute, script block, JSON string, CSS, DOM sink (`innerHTML`, `document.write`, `eval`, `srcdoc`, framework-safe bypasses). The context decides the payload; a payload that "works" in your browser console proves nothing.
Test the encoding, not the payload list: quote breaking, angle brackets, entity decoding order, double decoding, unicode normalization, and whether the value is sanitized then re-encoded.

## 2. Prove execution in a second identity
Use a second browser context/profile, or a stored payload read by another test user. Record what executed (a callback, a DOM change, a stolen value), not what you expected to execute.
Run the two classic false-positive checks before reporting: it fires for an anonymous user in a clean profile, and it survives a hard reload (stored vs self-hosted).

## 3. DOM XSS
Trace source to sink in the JavaScript you can read: `location.*`, `document.referrer`, `postMessage`, `localStorage`, `hash`. A sink reachable only from the console is self-XSS; a sink reachable from a URL or a stored value is a finding.

## 4. CSRF
Only meaningful when there is a state change. Confirm: is there a token, is it validated server-side, does `SameSite` apply, does the endpoint accept JSON with a simple content type, can the action be triggered from a form or a link. Then demonstrate the cross-site request and the resulting state change - a form that requires re-authentication is a CSRF defence, not a bug.

## 5. Open redirect and CORS
- Open redirect alone is usually informational; it becomes real when chained (OAuth `redirect_uri`, SSO, password reset, script/stylesheet import).
- CORS: `Access-Control-Allow-Origin` reflecting an arbitrary origin **with credentials** and a readable response is the finding; wildcard without credentials is not.

## 6. postMessage and third-party scripts
Check origin validation on both sides (`addEventListener("message")` without origin check, `postMessage(..., "*")` with sensitive data), and whether a third-party script tag can be hijacked (jsonp, CDN with user-controlled path, prototype pollution reaching a gadget).

## 7. Recording
- Payload, context, victim identity, and the exact observable effect go in the fact.
- The finding needs the request that delivers the payload and the evidence that another identity executed it; a screenshot description is weaker than a callback or a stored value you can show again.
- Stored payloads must be cleaned up at the end and their location recorded.