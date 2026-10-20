---
name: skilllint
description: Use when a SKILL.md must be checked before it is trusted, installed, or listed - private lint of structure, triggers, secrets, prompt injection, broken references and unbounded autonomy.
---

# skilllint

Private lint of agent skills. Nothing leaves the machine.

## When to use
- A skill is about to be installed, listed, or given to an agent, and you need a verdict.
- You are choosing between several candidate skills from different registries.
- You need a reproducible hash so the verdict can be signed and verified later.

## Tools
- `lint_skill(path)` - verdict, score, sha256, findings[].
- `compare_skills(paths)` - rank candidates by verdict and evidence.
- `lint_rules()` - the rule table.

## Notes
- Severity: critical / high / medium / low. Verdict: PASS, WARN, FAIL.
- The sha256 is the input for a signed receipt (attest) and for an allowlist (drift).
- Locales: en, hi. India (Bharata) is supported from day one; legal claims require official sources, otherwise report pending.
