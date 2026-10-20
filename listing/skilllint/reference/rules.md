# The 11 rules

Severity: `critical` (unsafe by itself) > `high` (blocks install) > `medium` (fix or
accept in writing) > `low` (style and cost).

| id | severity | fires when | how to fix |
|---|---|---|---|
| R-001 | critical | the `--- ... ---` frontmatter block is missing | add frontmatter with `name` and `description` |
| R-002 | high | `name` is empty or not `lowercase-with-dashes` | rename to `lowercase-with-dashes`, matching the folder |
| R-003 | high | `description` is missing or longer than the limit | write one sentence of what it is, plus when to use it |
| R-004 | medium | the description has no trigger wording ("use when ...") | add the situations that should pull the skill in |
| R-005 | medium | dead instructions are left in the text (`TODO`, `deprecated`, `placeholder`) | finish or delete the instruction |
| R-006 | critical | literals that look like secrets (API keys, private keys, tokens) | remove them; credentials belong in the environment, never in a skill |
| R-007 | critical | prompt-injection or exfiltration markers ("ignore previous instructions", "do not tell the user") | treat as hostile: do not install, report the marker |
| R-008 | medium | the skill references files that are not in the package | ship the referenced files or fix the path |
| R-009 | low | the file is larger than 60 KB | split the skill; every call pays for the whole file |
| R-010 | high | bundled scripts are writable by everyone | `chmod 644` the scripts, or ship them read-only |
| R-011 | medium | instructions grant unbounded autonomy ("without asking", "no confirmation") | require a confirmation step for consequential actions |

## Reading the findings

Each finding carries the rule id, the severity and the human-readable message. The
verdict is derived from the worst severity found:

- any `critical` or `high` finding -> `FAIL`
- only `medium` or `low` findings -> `WARN`
- nothing found -> `PASS`

The score (0-100) is a coarse ranking signal, useful when comparing candidates. It is
not a probability and should not be read as one.

## What a finding does not say

- R-008 only proves anything when the whole package was linted.
- R-006 and R-007 are pattern matches. A false positive is possible; a false negative is
  too. They raise the bar, they do not clear it.
- R-004 and R-009 are about cost and reach, not safety: a skill can be perfectly safe
  and still never fire, or fire on everything.
