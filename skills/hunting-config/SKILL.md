---
name: hunting-config
description: Load for misconfiguration and information disclosure: headers, CORS, TLS, debug endpoints, exposed files and metadata, cloud storage, default credentials.
---

# Hunting: configuration and disclosure

Configuration bugs are graded on **what they unlock**, not on how untidy they look. A missing header is not a finding; an exposed backup with a database inside it is.

## 1. Disclosure with consequence
Walk the environment for artefacts that leak: `.git/` (reconstructable history), `.svn`, `.env`, backup and swap files (`.bak`, `.old`, `.zip`, `.sql`, `~swp`), editor and CI files (`.gitlab-ci.yml`, `.github/`), source maps, `/actuator`, `/debug`, `/metrics`, `/phpinfo`, `/server-status`, `/.well-known/`, directory listing, stack traces with environment variables, and error messages that print configuration.

For each one, ask: what does this give an attacker that changes their capability? Credentials, source with hard-coded secrets, session material, internal hostnames - that is a finding. "There is a debug page" alone is not.

## 2. Cloud and storage
Object storage buckets/CDN endpoints reachable from the app: list, read another tenant's object, write, or overwrite with a content type the app serves. Metadata endpoints reached through SSRF belong to the server-side skill; here you test direct exposure.

## 3. CORS, headers and transport
- CORS: reflecting an arbitrary origin with credentials and a readable body is real; wildcard without credentials is not.
- Headers: `Content-Security-Policy`, `HSTS`, `X-Frame-Options`/`frame-ancestors` missing are informational unless you can demonstrate the attack they would have stopped (clickjacking against a real action, script injection actually executing).
- TLS: only report when there is an exploitable consequence (accepted HTTP session cookie, certificate/HSTS gap across the redirect chain).

## 4. Default and weak credentials
Try defaults only where the product documents them and the target is in scope, plus a short, rate-capped list against the admin surface. A default credential is a finding; a "cacheable password policy" observation is not.

## 5. Infrastructure context
From headers, certificates, virtual hosts and error pages, extract the hosting and the edge (CDN, WAF vendor, load balancer). That context decides which bypasses are plausible - a parser differential only exists if a proxy parses first.

## 6. Recording
- Every exposed artefact is an asset (`insert_assets`) plus a fact with the exact URL and what it exposed.
- The finding must state the capability gained, not the misconfiguration alone.