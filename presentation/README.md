# SERUM — presentation

`SERUM_slides.pptx` — a 52-slide, fully-explanatory talk deck (16:9) with the
project's figures and result tables embedded, and **complete speaker notes on
every slide**. Open in PowerPoint / Keynote / Google Slides.

Structure (10 parts): the problem & the picky-germ intuition → thesis &
contributions → the containment POMDP → identifiability theory (with worked
examples) → the belief + content-aware policy → results (synthetic, real-topology
flagship, Pareto, closest-system head-to-head) → robustness → breadth (IoT,
learned policy) → positioning & honest limitations → outlook.

## Regenerate

```bash
pip install python-pptx           # see requirements.txt
python scripts/make_slides.py     # writes presentation/SERUM_slides.pptx
```

The deck is generated from the committed figures in `paper/figures/` and
`results/`; edit `scripts/make_slides.py` (source of truth) and regenerate rather
than editing the `.pptx` by hand if you want the change tracked. It stays in sync
with the paper's honest framing (leads with the real-topology result; online
inference and robustness are scoped, not oversold).
