---
name: hunting-auth-access
description: Load for authentication, session, authorization and access-control work: IDOR, privilege escalation, JWT, OAuth, SSO, password-reset flows and multi-tenant isolation.
---

# Hunting: authentication and access control

Access-control bugs pay more than injection in most real engagements, and they are invisible to scanners. The method is comparison, not payloads: a **control identity** and a **test identity** doing the same thing.

## 1. Build the identity matrix first
Before testing, write down the roles and objects you have: anonymous, the test user, a second test user, an admin, and - when present - two tenants. Then for each request ask three questions:
- Who is allowed to do this? (documented or implied)
- Who am I when I do it?
- Whose object am I touching?

A finding is when the answer to the third is "not mine" and the answer to the second is "not an admin".

## 2. Object-level authorization (IDOR)
Enumerate object identifiers from responses, not guesses: exports, invoice numbers, UUIDs in HTML/JS, sequential ids in redirects. Then replay the exact request with a different identity's session and with the identifier mutated by one step (n-1, n+1, uuid from the other tenant). Compare with a *legitimately public* object to avoid the classic false positive - "readable" is not "broken" when the data is public by design.
Escalate: from one object to a list endpoint, from read to write (PUT/PATCH/DELETE), from your tenant to another, from a sub-resource to its parent.

## 3. Function-level authorization
A hidden button is not a control. Call the admin endpoint directly with a low-privilege session, and also with the low-privilege session but an admin-only parameter (`role`, `is_admin`, `tenant_id`, `scope`). Mass assignment belongs here: add fields the UI never sends and see what changes.

## 4. Session and token handling
- Is the session id rotated at login and after privilege change?
- Does logout invalidate server-side, or only clear the cookie?
- Are cookies `HttpOnly`/`Secure`/`SameSite` consistent with the threat?
- JWT: check signature enforcement first (alg none, key confusion, weak HMAC secret offline), then claim trust (`sub`, `role`, `tenant`, `exp`). A token you can edit but not re-sign is not a finding; a token whose claims the server trusts after re-signing with a recoverable key is.
- OAuth/OIDC: `redirect_uri` validation (prefix, path traversal, subdomain), `state` absence, code reuse, implicit-flow leakage, and whether the client trusts an unverified email or `iss`.

## 5. Account lifecycle
Reset and invite flows are the highest-yield place for host-header and parameter poisoning: reset token binding to email vs to a field you control, token reuse, predictable tokens, host header influencing the reset link, invite acceptance without email verification, and re-registration of a deleted account.

## 6. Multi-tenant isolation
If the app has tenants/workspaces/companies, test the isolation boundary explicitly and record it as a route of its own: same request, token of tenant B, object of tenant A. Then the same for aggregate endpoints (search, export, dashboard counters) which often forget the tenant filter that the detail view has.

## 7. Recording
- The identity matrix, the two sessions used and the object ids are evidence: put them in the fact.
- A confirmed cross-identity read/write goes to `report_finding` with both requests - the control request and the violating one - so a reviewer can see the difference without trusting your prose.
- Credentials and tokens found on the way are assets: register them verbatim, then reuse them and record what they unlocked.