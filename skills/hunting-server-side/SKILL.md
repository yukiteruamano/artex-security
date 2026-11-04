---
name: hunting-server-side
description: Load for SSRF, file upload, path traversal, deserialization, request smuggling, and any bug where the server acts on attacker-chosen resources.
---

# Hunting: server-side

Server-side bugs are about **what the server can reach that you cannot**. Prove reachability, then prove the effect.

## 1. SSRF: prove the request, not the string
A parameter that looks like a URL is not SSRF until the server makes the request. Prove it with a callback you control, then map the reach: localhost, RFC1918, link-local, and the cloud metadata endpoints. Then decide the shape of the impact:
- port scan by timing/response differential across localhost;
- protocol handling (gopher, file, dict) when the client supports it;
- response reflection vs blind (blind is still a finding, but say it is blind);
- credential exposure: metadata identity tokens, internal admin panels without auth.
Rotate past naive filters: DNS rebinding, decimal/octal/hex IP forms, IPv6 mapped, redirect chains, userinfo tricks, trailing dot, alternative schemes, URL parsing differentials between validator and fetcher (the classic bug: the validated string is not the fetched one).

## 2. File upload: where does it land and who executes it?
Answer in this order, and stop when an answer is bad: is the file stored under the web root, with which extension handling, is it served with a sniffable content type, is it parsed by anything (image lib, PDF, XML, office), is the filename used in a shell or path, can it overwrite an existing file? A shell that executes is the top of the ladder; a stored file that is served with an attacker-controlled content type can be equally fatal against other users (stored XSS).
Test the validation layer, not the form: content-type only, magic bytes only, extension blacklist, double extension, trailing dot/space, case, unicode normalization, archive-of-archives (zip slip, nested archive), and the path traversal in the filename.

## 3. Path traversal and file inclusion
Minimal pair: a path that works and one that escapes. Then escalate: read a known-bad file (config, key material), then reach a write or an include that executes. Encoding matters (`%2e%2e%2f`, double encoding, backslashes, truncation, absolute path) and so does the OS.

## 4. Deserialization
Find the sink first (cookie, hidden field, cache key, queue message, session store), name the format and the library, then decide if you can build a gadget chain. A class name you can only *guess* is a lead; a chain you actually triggered with a callback is a finding.

## 5. Request smuggling and desync
Only test if there is a proxy/CDN in front of the origin. Use a controlled backend of your own or the safest possible probe, and watch for the front-end/origin disagreement (CL.TE, TE.CL, TE.TE obfuscation). Smuggling tests can affect other users - rate-cap, never on production without explicit approval, and record the exact bytes of both requests.

## 6. Recording
- Internal hosts, ports and services discovered through SSRF are assets: `insert_assets`, then `record_fact` with how they were reached.
- The fact must contain the request that made the server act plus the observable proof (callback log line, response body, timing table).
- Danger checks belong in the finding: "this made a real state change" or "this was read-only" is the first thing a reviewer needs.