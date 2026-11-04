---
name: recon-wstg
description: Load at the start of an engagement: build the attack surface systematically, map findings to OWASP WSTG ids, and record assets so coverage stays measurable.
---

# Reconnaissance (WSTG-aligned)

Recon is not "run tools until output appears". Its output is a **surface**: assets, endpoints, parameters, roles, and the trust boundaries between them - each one registered so the planner can reason and coverage can be measured.

## 1. Scope before packets
Read the operating constraints (and the engagement note) and restate them in your own words: hosts, ports, paths, excluded areas, rate limits, forbidden actions. If a discovered asset falls outside, register it as an out-of-scope fact and skip it. Discovering something is not authorization to touch it.

## 2. Passive first
Certificates, DNS, public code and docs, response headers, HTML/JS source, robots/sitemap, well-known files, error pages, technology fingerprints. This costs no stealth and often reveals the internal naming and the real API surface (bundled JS is the best API map you will get).

## 3. Then active, cheap and ordered
Virtual hosts and subdomains, then ports, then content discovery on confirmed hosts, then parameter discovery per endpoint. Keep the order: each step's output narrows the next one. Never brute-force paths on a host you have not confirmed exists; it burns noise budget for nothing.

## 4. Structure the surface
For each endpoint record: method(s), parameters (name, location, type), authentication required, roles that can reach it, and the data it returns. For each parameter note where it lands in the request and what the response does with it. This is what makes the hunting skills useful later - a payload table without context is guessing.

## 5. Roles and workflows
Register every role you can obtain and every multi-step flow you can see (registration, checkout, invite, approval). Most high-severity findings live at the intersection of a role and a workflow, and recon is the only phase where you can enumerate them cheaply.

## 6. WSTG mapping
Tag what you covered with the WSTG family so coverage is measurable and the report can cite it: INFO (information gathering), CONF (configuration), IDNT (identity), ATHN (authentication), ATHZ (authorization), SESS (session), INPV (input validation), ERRH (error handling), CRYP (cryptography), BUSL (business logic), CLNT (client-side). Example: reflected XSS is INPV-01/02, IDOR is ATHZ-04, a workflow skip is BUSL-01/02, a weak TLS setup is CRYP-01/03.

## 7. Recording discipline
- Assets (site, host, service, endpoint, parameter, credential, technology) go to `insert_assets`, with structured props. Credentials verbatim, with their source.
- Conclusions ("the API is versioned under /v2 and the v1 routes are still reachable without auth") go to `record_fact`, one aggregated fact, with the command and the lines that prove it.
- Skip already-registered duplicates: check `list_assets` first.