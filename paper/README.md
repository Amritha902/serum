# Paper

`serum.tex` — the SERUM paper draft (portable `article` preamble, compiles on
Overleaf or any TeX Live with no conference style file). `refs.bib` — verified
bibliography.

## Build

```bash
pdflatex serum.tex && bibtex serum && pdflatex serum.tex && pdflatex serum.tex
# or: latexmk -pdf serum.tex
```

Or upload `serum.tex` + `refs.bib` to Overleaf.

## Structure & sources

- Identifiability theory (§3) — proofs in [`../docs/THEORY.md`](../docs/THEORY.md),
  code in `serum/inference/identifiability.py`, validated by
  `scripts/identifiability.py` (100% agreement).
- Results (§5) — reproduce with `python scripts/run_experiment.py --real`
  (figures in `../results/`).
- Positioning / prior art — [`../docs/RELATED_WORK.md`](../docs/RELATED_WORK.md).
