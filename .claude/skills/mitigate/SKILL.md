---
name: mitigate
description: Work the SERUM review backlog — take the top open criticism in docs/REVIEW_MITIGATION.md and actually resolve it (build the fix and experiment, or reframe the claim, or honestly acknowledge the limitation), keeping tests green and never overclaiming. Use after the `grill` skill or when the user says "mitigate", "fix the issues", or "address the review".
---

# Mitigate a SERUM review point

Resolve ONE open criticism per invocation, honestly.

## Procedure

1. Read `docs/REVIEW_MITIGATION.md`; pick the highest-severity **open** item.
2. Execute its tag:
   - **[FIX]** — build the code/experiment. Run it. Report the REAL number, even
     if it undercuts the claim. Add a test; keep `pytest` green.
   - **[REFRAME]** — adjust the claim in `paper/serum.tex` / `README.md` /
     `docs/RESEARCH.md` to what the evidence actually supports.
   - **[ACK]** — write the honest limitation into the paper's Limitations section.
3. **Grill your own mitigation**: did it work, or did it open a new hole (like R6
   → SR1/SR3)? If a fix fails to help, that is the finding — record it; do not
   pretend success.
4. Update the item's status in `docs/REVIEW_MITIGATION.md`, append the outcome to
   `docs/DEVLOG.md`, commit + push.

## Rules

- A failed fix honestly reported beats a fake success. If a [FIX] cannot beat the
  criticism, convert it to a [REFRAME] or [ACK] and say why.
- Never invent data or a favorable regime that doesn't exist. Re-run to verify.
- Keep the change minimal and scoped to the one item.
