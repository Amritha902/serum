---
name: grill
description: Hostile self-review of the SERUM project as a skeptical IEEE conference panel — list every attackable weakness (threat model, evaluation, novelty, theory, rigor, presentation), rank by severity, and propose a mitigation (fix / reframe / acknowledge) for each. Use before submission, after a batch of changes, or whenever the user asks to "grill", "bash", or "review as a panel".
---

# Grill SERUM (hostile panel review)

Act as a deliberately harsh IEEE S&P / CNS / IMC program committee. The goal is to
find real reasons to reject, not to praise. Be specific and cite `file:line` or a
concrete claim/result.

## Procedure

1. **Re-read the current state**, not memory: `docs/DEVLOG.md` (findings),
   `docs/RESEARCH.md` (claims), `docs/THEORY.md` (theorems), `README.md` and
   `results/*.json` (numbers), `paper/serum.tex` (the pitch).
2. **Attack across all axes:**
   - *Threat model & realism* — unearned assumptions (observability, inventory,
     attacker toy-ness, no emulation/real malware).
   - *Evaluation* — scale, semi-synthetic data, wrong topology, weak/absent
     baselines (esp. the closest real system), tiny margins, missing ablations.
   - *Novelty* — what is already known (percolation, group testing, immunization);
     is the headline actually the contribution?
   - *Theory* — idealized assumptions vs the experiments; missing guarantees.
   - *Rigor* — multiplicity/uncorrected p-values, seeds, time-dependent data.
   - *Focus & honesty* — overclaims, walked-back claims, kitchen-sink breadth.
3. **Rank** the criticisms existential → cosmetic.
4. For each, tag a mitigation: **[FIX]** (build/experiment), **[REFRAME]**
   (scope/positioning), or **[ACK]** (genuine limitation for a Limitations section).
5. **Append** the round to `docs/REVIEW_MITIGATION.md` (new dated round if one
   exists) and commit.

## Rules

- Never soften a valid criticism to protect the work. A weakness found here is
  cheaper than one found by a reviewer.
- If a prior mitigation opened a NEW weakness, say so explicitly (second-round
  penalties).
- Do not fix anything in this skill — only diagnose and record. Fixing is the
  `mitigate` skill's job.
