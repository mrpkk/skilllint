# skilllint

**Private lint of agent skills (SKILL.md).** Nothing leaves the machine.

Existing scanners (for example NVIDIA SkillSpector - 71 patterns, AST, YARA, CVE lookup) answer "is this artifact dangerous", and they ship the inspected content to their provider. We do something narrower and complementary:

- **privacy** - the check runs locally; only a verdict, a score and a hash go out;
- **reproducibility** - the verdict is bound to a sha256 of the file, so it can be signed and verified later;
- **comparison** - rank several candidates from different registries instead of scanning one artifact at a time.

## Rules

| id | severity | check |
|---|---|---|
| R-001 | critical | frontmatter missing |
| R-002 | high | `name` missing or invalid |
| R-003 | high | `description` missing or too long |
| R-004 | medium | no trigger ("when to use") in description |
| R-005 | medium | dead instructions (TODO / deprecated / placeholder) |
| R-006 | critical | secret-shaped literals |
| R-007 | critical | prompt-injection / exfiltration markers |
| R-008 | medium | references to files that do not exist |
| R-009 | low | file larger than 60 KB |
| R-010 | high | world-writable scripts |
| R-011 | medium | unbounded autonomy instructions |

Verdict: `PASS` (>=80, no critical) | `WARN` | `FAIL` (any critical).

## Use it

```bash
python3 mcp_server.py                            # stdio
python3 mcp_server.py --http 8191                # streamable http
npx -y mcp-remote https://rta.lat/skilllint/mcp  # hosted
```

Tools: `lint_skill(path)` | `compare_skills(paths)` | `lint_rules()`

## Signed verdicts

`lint_skill` returns `{verdict, score, sha256, findings[]}`. That hash is what attest signs and drift enforces as an allowlist - see [Verified Tool Registry](docs/VERIFIED-TOOL-REGISTRY.md).

Locales: en, hi. India (Bharata) is supported from day one; legal claims require official sources, otherwise report pending.

License: MIT
