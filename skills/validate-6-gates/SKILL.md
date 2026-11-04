---
name: validate-6-gates
description: Load before writing a report or after any candidate finding: the six gates that separate a real vulnerability from a false positive, plus the usual patterns of self-deception.
---

# Validation: the six gates

A finding is a claim that someone else must be able to reproduce and defend in front of a client. These six gates are the bar. A candidate that fails one is fixed, downgraded or dropped - never written up "with a caveat".

## The gates
1. **Reproducible PoC** - a complete request (or command) that triggers it: method, URL, headers, body, parameters, in the order that matters. Prose is not a PoC.
2. **Evidence of effect** - the matching response or output that shows the vulnerability, not the tester's interpretation of it. Request without response fails; response without request fails.
3. **Impact demonstrated** - a concrete capability ("read the email of user B", "execute a command as the app user", "transfer funds from another account"), not "may lead to" or "could be abused". If you cannot demonstrate it, state the limit explicitly and grade it accordingly.
4. **In scope** - the endpoint, host and operation are inside the engagement's constraints, including any forbid-list. Out of scope is out of scope, regardless of severity.
5. **A real vulnerability** - not a best practice, not a missing header, not self-XSS, not a version number that matches a CVE, not an informational disclosure with no capability gained.
6. **Third-party reproducible** - another tester with the documented access can follow the steps with standard tools and see the same result. Race conditions with a 1-in-50 hit rate, private tooling or undocumented state need that stated in the reproduction.

## Patterns that are usually false positives
- XSS that only fires in the tester's own browser (extension, cached state, devtools).
- SQL "error" text that appears in normal flows (the app prints errors by design).
- SSRF where the connection is blocked by a firewall - no data flow, no impact.
- IDOR over data that is public by design (public profiles, shared content).
- CSRF on a flow that requires re-authentication (that *is* the defence).
- Self-XSS, or a payload that only works when pasted into your own console.
- Open redirect with no downstream consumer.
- Missing security headers with no demonstrated attack.
- Reflected input that is correctly encoded - the control is not missing.
- Timing-based injection whose delay is under the noise floor (measure a baseline first).
- "Version X is vulnerable" without triggering it (patch-diff-only findings are leads).

## Escalation instead of inflation
When a candidate fails gate 3, do not pad the impact - go back and try to **reach** the impact with a different route (another role, another endpoint, a chain to an existing finding). If that fails, record it as a lower-grade finding with an honest limit, or as an inferred fact for the planner.

## Verdicts
- **validated** - all six pass.
- **needs work** - fixable gap, and you name the exact missing evidence and the test that would close it.
- **rejected** - a gate fails permanently. Say which one, in one line.
Write the verdict with the evidence ids, so nobody has to trust the summary.