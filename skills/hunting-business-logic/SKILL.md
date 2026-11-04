---
name: hunting-business-logic
description: Load for business logic flaws: workflow bypass, price and quantity manipulation, coupon abuse, race conditions, feature abuse and boundary values.
---

# Hunting: business logic

Logic flaws are unique to the application, invisible to scanners, and often the highest-impact finding. There is no payload list - there is a **model of what the application assumes** and a test for each assumption.

## 1. Model the business first
Write down, in one paragraph: what the app does, which operations move money or data, what the multi-step workflows are, and what the code must be assuming ("a user cannot set the price", "a coupon is used once", "step 3 only happens after step 2"). Each assumption is a test.

## 2. Workflow bypass
For every multi-step flow (cart, checkout, KYC, approval, invite, password reset): jump to a later step directly, replay an earlier step after completing a later one, submit a later step's data to an earlier endpoint, and repeat a step that should be single-use. Record the state transitions you observe, not just the HTTP status.

## 3. Value manipulation
- Price, quantity, currency: send `0`, negative, extremely large, decimal precision overflow, and a changed currency in a request that should use the server's.
- Discounts and coupons: reuse across users, stacking, expired, case/whitespace variants, coupons applied to ineligible items.
- Totals recomputed server-side? Prove it by breaking the arithmetic in the request and seeing what the invoice says.

## 4. Race conditions
Only where a limit should be atomic: redeem a coupon, spend a balance, claim a seat, vote, apply a referral, hit a rate limit. Fire the same request in parallel (a script with a barrier, not a loop) and count how many succeeded. Warn before testing anything with financial or real-user effect, and prefer the smallest useful concurrency. A race that succeeds at 1/50 attempts is still real - state the odds.

## 5. Feature abuse
Legitimate features used off-label: email sending (spam, reset to arbitrary addresses), file generation (SSRF, DoS), export (mass enumeration), referral self-credit, image/PDF processing (resource exhaustion), search endpoints (enumeration of hidden records), invite flows without email verification.

## 6. Boundaries and types
`0, -1, INT_MAX, 1e18, 0.000001, NaN, Infinity, null, ""`, very long strings, arrays where a scalar is expected and the reverse, duplicate keys, and empty vs missing fields. Type confusion is a logic bug that becomes an injection bug when the backend concatenates.

## 7. Chaining
A logic flaw is often graded low alone and high in a chain: IDOR plus export equals mass data theft; a race plus a coupon equals unlimited credit; a workflow skip plus a role field equals privilege escalation. Say the chain out loud in the finding and prove each link separately.

## 8. Recording
- The assumption, the expected result and the observed result go in the fact (three lines, no prose padding).
- The finding needs the request(s) and the observable outcome (balance, record, state), plus the smallest reproducible sequence.