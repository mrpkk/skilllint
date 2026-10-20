---
name: skilllint
description: Vet an agent skill before you install, run or list it - private lint of structure, trigger wording, dead instructions, embedded secrets, prompt-injection markers, broken file references and unbounded autonomy. Returns a verdict, a score and the SHA-256 of exactly what was checked. Triggers - check a skill, vet a skill, lint SKILL.md, is this skill safe, audit an agent skill, review a skill before install, compare candidate skills, skill security scan, skill linting.
---

# skilllint - Vet Agent Skills Before You Trust Them

A skill is an instruction set that gets injected into an agent's context. Three failures
dominate, and none of them announce themselves:

- **It never fires.** No trigger wording in the description, so the agent never reaches
  for the capability. Nothing errors. You just never get it.
- **It fires everywhere.** A vague description plus a 100 KB file means every relevant
  request pays for the whole thing.
- **It carries something.** A secret literal, an injection marker, or "act without asking".

This skill makes that check **local, private and reproducible**: the candidate's bytes are
read on your machine, nothing is uploaded anywhere, and the verdict comes with the SHA-256
of exactly what was checked.

## The loop

1. **Get the candidate, do not install it.** A local path, a repository, a file someone
   sent you. Vet first; install second.
2. **Lint it.** Offline, standard library only, no network:

   ```
   python3 scripts/linter.py path/to/SKILL.md
   ```

   Or connect the hosted MCP endpoint (same engine, no install):

   ```
   https://rta.lat/skilllint/mcp
   ```

   Tools: `lint_skill`, `compare_skills`, `lint_rules`. Setup snippets for Claude Code,
   Cursor and generic MCP clients: `reference/setup.md`.
3. **Read the verdict.** `PASS` / `WARN` / `FAIL`, score 0-100, `findings[]` with rule ids
   and severities, and `sha256`. The rule table with what each id means and how to fix
   it: `reference/rules.md`.
4. **Decide and report.**
   - `FAIL` (a critical or high finding) - do not install. Name the rule ids to whoever
     sent the skill. Do not "fix it and continue" on your own: the fix is the author's.
   - `WARN` - install only if you understand each medium finding, and say which ones you
     accepted and why.
   - `PASS` - the structure is sound. That is a floor, not a ceiling: it is not a
     security audit and it does not prove the instructions work.
5. **Comparing several candidates?** Rank by verdict, then score, then size - a smaller
   file costs less context on every call. `compare_skills` does the ranking and shows
   the evidence side by side. How to run the comparison and what to ask the author:
   `reference/candidates.md`.
6. **Keep the sha256.** It is the input for a signed receipt and for an allowlist: the
   same bytes always produce the same verdict, and changed bytes change the hash. If a
   skill is re-published later, re-lint and compare hashes instead of trusting the name.

## Honest limits

- Static analysis only. It reads bytes; it never executes the skill and never runs its
  scripts. A skill can pass the lint and still be wrong.
- `PASS` means "structure is sound", never "safe". The linter has 11 rules, not a threat
  model.
- The "referenced file not found" check only means something when the whole package is
  present. Lint the **directory** when the skill ships reference files - a lone file
  will report its neighbours as missing.
- Private means private: the linter reads the file and writes the verdict. It does not
  call out, and the hosted endpoint is optional, not required.

## What's inside

- `SKILL.md` - the check loop the agent follows.
- `reference/rules.md` - the 11 rules, what fires them, and how to fix each.
- `reference/setup.md` - local and hosted connection, and how to read a verdict.
- `reference/candidates.md` - comparing candidates, and what to ask the author.
- `scripts/linter.py` - the linter itself, standard library only. Copy it anywhere.
