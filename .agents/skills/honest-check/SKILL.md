---
name: honest-check
description: Anti-overclaim verifier for SERUM — given a stated result or claim, re-run the relevant experiment from scratch and confirm the number actually holds (right regime, enough trials, correct baseline, real p-value). Use before putting a number in the paper/README, or when the user asks to "verify", "check the result", or "make sure it holds".
---

# Honest-check a SERUM claim

Verify a specific claimed result by re-deriving it, not by trusting the doc.

## Procedure

1. Identify the exact claim (number, comparison, p-value) and the script/regime
   it came from (`scripts/*.py`, `results/*.json`).
2. Re-run it (`source .venv/bin/activate && python scripts/<x>.py <trials>`), ideally
   with MORE trials than the original, and a different base seed.
3. Check the honest questions:
   - Is the comparison against the *right* baseline (best fixed baseline, not a
     strawman; and note the ensemble-oracle result too)?
   - Is the regime the one the claim is stated in (budget, prevalence band,
     topology, real vs synthetic)?
   - Does the p-value survive with more trials? Is it corrected for multiplicity
     if it is one of many?
   - Does an ablation (e.g. `update_belief=False`, uniform prior) show the effect
     is from the stated cause and not a confound?
4. If the number holds — record the reproduction. If it does NOT — flag it loudly,
   correct the doc/paper/README, and note it in `docs/DEVLOG.md`.

## Rules

- The default assumption is that a claim might be wrong until re-derived.
- Report the number you actually observe, never the number you hoped for.
