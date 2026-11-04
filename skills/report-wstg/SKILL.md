---
name: report-wstg
description: Load when writing or reviewing the final report: structure, severity discipline, remediation quality and the WSTG/OWASP references a client expects.
---

# Report writing

The report is the deliverable the client pays for. It is read by two audiences: an engineer who needs to reproduce and fix, and a manager who needs to prioritise. Write for both, and never let the prose claim more than the evidence shows.

## Structure per finding
- **Title**: location + weakness ("IDOR in /api/v2/invoices exposes any tenant's PDF"). No adjectives.
- **Severity**: CVSS 3.1 vector plus a sentence of reasoning. Severity follows demonstrated impact and required preconditions, not the vulnerability class name.
- **Affected scope**: assets, endpoints, parameters, versions, and the role/network position needed.
- **Reproduction**: numbered steps a third party can follow with standard tools, including preconditions and the expected observation at each step.
- **Evidence**: request and response excerpts (masked - the report is the only place masking happens), command output, and stable evidence ids.
- **PoC**: the complete runnable artefact, or an explicit statement that the reproduction steps are the PoC.
- **Root cause**: the actual defect (missing authorization check on the object, parameter concatenated into SQL, trust in a client-supplied price).
- **Remediation**: what to change, in this stack, ordered by effectiveness; then how to verify the fix; then the structural hardening if the same class is likely elsewhere.
- **References**: WSTG id, OWASP category (Web/API/LLM Top 10), CWE, and the internal evidence ids.

## Severity discipline
Grade the *finding you demonstrated*, then state what a stronger chain could reach. Do not inflate a low-grade bug into a high-grade one with hypotheticals, and do not deflate an access-control bug because it "only" read one record - the class is what the client must fix.

## Remediation quality
Bad: "sanitise input", "use parameterised queries", "add security headers".
Good: "in `InvoiceHandler.get` resolve the object through the caller's tenant scope before the lookup (the query currently filters by id only); add a regression test that requests another tenant's invoice with a valid session and expects 404".

## Coverage and methodology
Close the report with what was tested and what was not: WSTG families covered, roles used, surfaces excluded by the constraints, and the time window. A report that states its coverage honestly is worth more than one that claims completeness.

## Language and masking
- The output language comes from the system prompt; keep raw technical fragments (commands, payloads, URLs, excerpts) verbatim.
- Mask live secrets in the report text only, preserving shape (`Authorization: Bearer [MASKED-JWT len=412]`), and list them in a masked appendix that points to the evidence id holding the raw value.
- Never mask the proof: parameter names, hosts, payloads and the values that demonstrate the flaw stay readable.