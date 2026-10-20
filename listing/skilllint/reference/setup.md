# Setup and how to read a verdict

## Option 1 - local (recommended)

The linter is one file with no dependencies beyond the Python standard library:

```
python3 scripts/linter.py path/to/SKILL.md
```

It prints JSON: `verdict`, `score`, `sha256`, `bytes`, `findings[]`. Lint the **directory**
when the skill ships reference files, so that the "referenced file not found" check can
actually see them.

Nothing is uploaded, no network is used, no telemetry, no account.

## Option 2 - hosted MCP endpoint

Same engine, served over MCP (streamable HTTP):

```
https://rta.lat/skilllint/mcp
```

MCP client configuration (Claude Code style):

```json
{
  "mcpServers": {
    "skilllint": {
      "type": "http",
      "url": "https://rta.lat/skilllint/mcp"
    }
  }
}
```

Tools:

| tool | what it returns |
|---|---|
| `lint_skill(path)` | verdict, score, sha256, findings for one skill |
| `compare_skills(paths)` | the same for several skills, ranked, with the evidence side by side |
| `lint_rules()` | the rule table itself - ids, severities, messages |

The hosted endpoint is optional. Everything works offline with the bundled script.

## Reading a verdict

```
{
  "skill": "my-skill",
  "verdict": "WARN",
  "score": 78,
  "sha256": "32f24e57...",
  "findings": [
    {"rule": "R-004", "severity": "medium", "message": "..."}
  ]
}
```

- `verdict` - `PASS`, `WARN` or `FAIL`; derived from the worst severity found.
- `score` - 0-100, a ranking signal for comparing candidates. Not a probability.
- `sha256` - of the exact bytes checked. Two runs on the same file agree forever; a
  changed file changes the hash. Attach it to your own report so a later version can be
  recognised as different.
- `findings[]` - rule id, severity, message. Report the ids, not just the prose.

## Reporting the result

State three things and nothing more: the verdict, the rule ids that drove it, and the
sha256. If you install a skill that produced `WARN`, say which findings you accepted
and why. If you reject a skill, name the rules - a rejection with rule ids is actionable
for the author, a rejection with adjectives is not.
