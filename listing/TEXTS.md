# Agensi listing — skilllint (EN)

## Title
**skilllint - Vet Agent Skills Before You Install Them**

## Card description (short)
Private lint of agent skills: structure, trigger wording, dead instructions, embedded
secrets, prompt-injection markers, broken file references, unbounded autonomy. 11 rules,
offline, verdict with SHA-256.

## Long description
A skill is an instruction set that gets injected into an agent's context, and three
failures dominate - none of them announces itself.

It never fires: no trigger wording in the description, so the agent never reaches for the
capability. Nothing errors, you just never get it.

It fires everywhere: a vague description plus a 100 KB file means every relevant request
pays for the whole thing.

It carries something: a secret literal, an injection marker, or "act without asking".

This skill makes that check local, private and reproducible. The candidate's bytes are read
on your machine, nothing is uploaded anywhere, and the verdict comes with the SHA-256 of
exactly what was checked.

What the check covers:

- structure: frontmatter, name, description, trigger wording
- consistency: dead instructions (TODO/deprecated/placeholder), references to files that
  are not in the package, files over 60 KB
- safety: literals that look like secrets, prompt-injection and exfiltration markers,
  instructions that grant unbounded autonomy

The verdict is PASS / WARN / FAIL with a score, the findings (rule id, severity, message)
and the sha256 of the bytes that were checked - so the same file always produces the same
verdict, and a changed file changes the hash. The hash is the input for a signed receipt
and for an allowlist.

When several candidates are in play, compare_skills ranks them by verdict, then score,
then size, and shows the evidence side by side.

Runs fully offline with the bundled script (standard library only). The hosted MCP endpoint
is optional, not required.

## What's inside
- SKILL.md - the check loop the agent follows
- reference/rules.md - the 11 rules, what fires them, how to fix each
- reference/setup.md - local and hosted connection, how to read a verdict
- reference/candidates.md - comparing candidates, what to ask the author
- scripts/linter.py - the linter itself, standard library only

## Honest limits
- Static analysis: it reads bytes, never executes the skill and never runs its scripts.
  A skill can pass the lint and still be wrong.
- PASS means "structure is sound", never "safe". Eleven rules are an opinionated minimum,
  not a threat model.
- The "referenced file not found" check only means something when the whole package is
  present: lint the directory, not a lone file.
- The linter is opinionated and argues with itself in public: we lint our own skill with
  it, and we publish both our findings and our own false positives.

## Suggested category / price / tags
- Category: security (alternates: devtools, agents-orchestration)
- Price: one-time $19 (same as the drift skill)
- Tags: skill security, lint, SKILL.md, agent skills, prompt injection, secrets, supply chain, mcp, offline
