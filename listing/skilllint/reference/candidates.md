# Comparing candidates, and what to ask the author

## Ranking

1. **Verdict first.** Any `FAIL` among the candidates removes one from the running.
2. **Then score.** Higher is better; it is a coarse signal, not a probability.
3. **Then size.** A 4 KB skill costs less context on every call than a 60 KB one. Two
   skills with the same verdict and score are not equal in cost.
4. **Then the evidence.** Read the findings of the top candidate: if the only findings
   are `R-004` (no trigger wording) and `R-009` (too big), that is a fixable skill. If
   there is an `R-007` injection marker, the ranking is irrelevant.

`compare_skills(paths)` does steps 1-3 and shows the findings side by side.

## What to ask the author

- Which files does the skill reference, and are they all in the package? (R-008)
- Which of the findings did you already know about? (the ones they knew and did not fix
  are the interesting ones)
- What does the skill expect to exist at run time - a tool, a key, a network endpoint?
- Is the description written from the point of view of the agent that has to choose it,
  or from the point of view of the person who wrote it? The first says "use when X",
  the second says "this skill does X" - only the first can be discovered.

## When the author pushes back

- "The linter is too strict." Agree on the specific rule, not on the verdict. Rules are
  meant to be argued with one at a time.
- "It is fine, I wrote it." Then the sha256 is what matters: the same file always
  lints the same way, and the finding is reproducible for them too.
- "The missing file is generated at install time." Then lint the package after
  generation, not before. The check is about what the agent will actually load.

## If you install anyway

Keep the sha256 and the verdict in your own notes. When the skill is updated, re-lint
and compare hashes: a changed hash means you are running different instructions than
the ones you vetted.
