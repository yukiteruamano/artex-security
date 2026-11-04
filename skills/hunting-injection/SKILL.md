---
name: hunting-injection
description: Load before testing any input-handling surface: SQL/NoSQL injection, command injection, template injection, XML external entities and expression languages.
---

# Hunting: injection

An injection bug is a **trust boundary crossed by data**, not a payload that worked. Your job is to prove which data reaches which interpreter, and what an attacker can do with it.

## 1. Map the interpreter before you map the payload
For every input, answer: which component consumes it (SQL engine, shell, template engine, XML parser, expression language, log/CSV/PDF renderer), with which quoting and encoding, and at which depth (query, LIKE clause, ORDER BY, header, filename). The same string behaves differently in each position; a payload tuned for a WHERE clause usually fails in ORDER BY, and a header rarely accepts what a body accepts.

## 2. Establish a signal, then a differential
Use one parameter at a time and one observable: error text, status code, response length, response time, or an out-of-band callback. Then prove causality with a **minimal pair** - a benign value and the candidate that differ in exactly one character. Time-based claims need a latency baseline (median of 5 benign requests) and a delay far above it; anything close is jitter, not injection.

## 3. Escalate to impact
A signal is not a finding. Walk the ladder and record where you stop:
- read: data from another table/record/tenant (prove it, do not infer it);
- write: a change you can show, with a reversible artefact;
- files: read a known file, then a path you should not reach;
- execute: one harmless command (id, hostname) or an out-of-band callback you control;
- pivot: the same credential or session reused against another service.

## 4. Rotate before you close
When a filter blocks you, change **the layer**, not just the case: encoding (URL, double URL, unicode, base16/32/64), position (parameter, path, header, cookie, JSON key, multipart filename), syntax (comments, whitespace alternatives, keyword alternatives, stacked queries), type (string vs array vs object), and parser differentials (duplicate keys, content-type confusion, charset best-fit). Only after these is "not injectable" a fair conclusion - and then say which ones you tried.

## 5. Class-specific notes
- **SQL**: error-based first, then boolean, then time; UNION needs matching column count and types. Union and stacked syntax are also useful as *write-capable* proof (DML behind an injection), which is often a higher severity than the read.
- **NoSQL**: operators in JSON bodies (`$ne`, `$gt`, `$regex`, `$where`), type confusion string vs array, `$regex` blind extraction by prefix.
- **Command**: separators (`;`, `|`, `&&`, newline), argument injection without separators (`-o`, `--output`), blind via timing or a callback.
- **SSTI**: decide the engine by probing arithmetic and object access, then read config/env before trying execution.
- **XXE**: internal entity echo first, then external entity, then parameter entities when the body does not reflect.
- **Second-order**: the payload is stored now and executed later in another context (admin panel, export, PDF/CSV, log viewer). Track where it lands.

## 6. Recording
- Interpreters, positions and the exact payload that moved the signal go to `record_fact` (with the minimal pair).
- Only a reproduced escalation goes to `report_finding`, with the full request and the response that proves the effect.
- New endpoints, parameters or technologies learned on the way go to `insert_assets`.
- Load `pentest-toolbox` before reaching for any automated framework; a manual minimal pair always comes first.