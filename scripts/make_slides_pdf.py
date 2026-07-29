#!/usr/bin/env python
"""Render the SERUM deck to a self-contained PDF via matplotlib (opens anywhere).

Keynote/LibreOffice are not required. This produces presentation/SERUM_slides.pdf
with the same content and figures as the .pptx deck — a universally-openable copy.
"""
import os, textwrap
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.image as mpimg

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(ROOT, "paper", "figures")
RES = os.path.join(ROOT, "results")
OUT = os.path.join(ROOT, "presentation", "SERUM_slides.pdf")

NAVY = "#1F355E"; ACCENT = "#2E6FB0"; DARK = "#252B33"; GREY = "#5A636E"
LIGHT = "#F3F6FA"; BOX = "#EAF1F9"; GREEN = "#1B7F4B"; AMBER = "#B56A00"
W, H = 13.333, 7.5

# matplotlib's default font lacks a few glyphs; keep text portable.
def s(t):
    for a, b in [("⊆", "⊆"), ("∩", "∩"), ("⟺", " iff "), ("β", "beta"),
                 ("×10⁻⁷", "e-7"), ("×10⁻⁵", "e-5"), ("×10⁻⁴", "e-4"),
                 ("×10⁻²", "e-2"), ("⁷", "7"), ("⁵", "5"), ("⁴", "4"), ("²", "2"),
                 ("⁻", "-"), ("→", "->"), ("↓", "v"), ("↑", "^"), ("≈", "~="),
                 ("×", "x"), ("’", "'"), ("‘", "'"), ("“", '"'), ("”", '"'),
                 ("—", "--"), ("–", "-")]:
        t = t.replace(a, b)
    return t

pdf = PdfPages(OUT)
_pageno = [0]

def newfig(bgcolor="white"):
    fig = plt.figure(figsize=(W, H), dpi=150)
    fig.patch.set_facecolor(bgcolor)
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, W); ax.set_ylim(0, H)
    ax.axis("off"); ax.set_facecolor(bgcolor)
    return fig, ax

def save(fig, number=True):
    if number:
        _pageno[0] += 1
        fig.text(0.965, 0.03, str(_pageno[0]), ha="right", va="bottom",
                 fontsize=9, color=GREY)
    pdf.savefig(fig); plt.close(fig)

def wrap(ax, text, x, y, width_chars, size, color=DARK, weight="normal",
         style="normal", dy=0.34, bullet=False):
    for i, line in enumerate(textwrap.wrap(s(text), width_chars) or [""]):
        pre = ("•  " if (bullet and i == 0) else ("   " if bullet else ""))
        ax.text(x, y - i * dy, pre + line, fontsize=size, color=color,
                weight=weight, style=style, ha="left", va="top")
    return y - (len(textwrap.wrap(s(text), width_chars) or [""])) * dy

def header(ax, title, kicker=None):
    if kicker:
        ax.text(0.6, H - 0.5, s(kicker).upper(), fontsize=11, color=ACCENT, weight="bold")
    ax.text(0.6, H - 0.95, s(title), fontsize=23, color=NAVY, weight="bold", va="top")
    ax.add_patch(plt.Rectangle((0, H - 1.55), W, 0.05, color=ACCENT, lw=0))

# ---------- slide builders ----------
def title_slide():
    fig, ax = newfig(NAVY)
    ax.text(0.9, 5.4, "SERUM", fontsize=60, color="white", weight="bold", va="top")
    ax.text(0.9, 4.1, s("Content-Aware Agentic Containment of Malware Under an "
            "Unobserved Payload"), fontsize=21, color="#C7D6EC", va="top")
    ax.text(0.9, 3.3, "Semantic Epidemic Response under Unknown Malware",
            fontsize=13, color="#9FB4D4", style="italic", va="top")
    ax.text(0.9, 2.0, "Amritha S.", fontsize=18, color="white", weight="bold", va="top")
    ax.text(0.9, 1.5, "A defensive research testbed  ·  cybersecurity · network science · agentic AI",
            fontsize=12, color="#9FB4D4", va="top")
    save(fig, number=False)

def divider(num, title, sub=""):
    fig, ax = newfig(NAVY)
    ax.text(0.9, 5.0, f"PART {num}", fontsize=16, color="#8FA6C8", weight="bold", va="top")
    ax.text(0.9, 4.3, s(title), fontsize=34, color="white", weight="bold", va="top")
    if sub:
        wrap(ax, sub, 0.9, 3.2, 70, 17, color="#C7D6EC", style="italic")
    save(fig, number=False)

def bullets(title, items, kicker=None, size=15, lead=None):
    fig, ax = newfig()
    header(ax, title, kicker)
    y = H - 2.0
    if lead:
        y = wrap(ax, lead, 0.7, y, 96, 17, color=NAVY, weight="bold", dy=0.36) - 0.15
    for it in items:
        txt, isize, col = (it if isinstance(it, tuple) else (it, size, DARK))
        y = wrap(ax, txt, 0.75, y, int(104 * 15 / isize), isize, color=col, bullet=True, dy=0.34)
        y -= 0.16
    save(fig)

def worked(title, intro, steps, concl, kicker="Worked example"):
    fig, ax = newfig()
    header(ax, title, kicker)
    wrap(ax, intro, 0.7, H - 2.0, 100, 15, color=DARK)
    y = H - 2.9
    for lab, body, col in steps:
        ax.add_patch(plt.Rectangle((0.7, y - 0.55), 1.1, 0.6, color=col, lw=0))
        ax.text(1.25, y - 0.25, s(lab), fontsize=12, color="white", weight="bold",
                ha="center", va="center")
        ax.add_patch(plt.Rectangle((1.9, y - 0.55), 10.7, 0.6, color=LIGHT, lw=0))
        ax.text(2.1, y - 0.25, s(body), fontsize=12.5, color=DARK, va="center")
        y -= 0.78
    wrap(ax, concl, 0.7, y - 0.1, 100, 15.5, color=GREEN, weight="bold")
    save(fig)

def figure(title, img, howto, kicker="Results"):
    fig, ax = newfig()
    header(ax, title, kicker)
    im = mpimg.imread(img); ih, iw = im.shape[0], im.shape[1]; ar = iw / ih
    maxw, maxh = 10.6, 3.9
    dw, dh = maxw, maxw / ar
    if dh > maxh: dh, dw = maxh, maxh * ar
    iax = fig.add_axes([((W - dw) / 2) / W, (1.35 + (maxh - dh) / 2) / H, dw / W, dh / H])
    iax.imshow(im); iax.axis("off")
    ax.add_patch(plt.Rectangle((0.7, 0.25), 11.9, 1.0, color=BOX, lw=0))
    wrap(ax, "How to read it:  " + howto, 0.95, 1.12, 118, 12.5, color=DARK, dy=0.28)
    save(fig)

def table(title, headers, rows, note, kicker="Results", hi=None, col_x=None):
    fig, ax = newfig()
    header(ax, title, kicker)
    nc = len(headers)
    if not col_x:
        col_x = [0.9 + i * (11.5 / nc) for i in range(nc)]
    y = H - 2.2; rh = 0.5
    ax.add_patch(plt.Rectangle((0.75, y - rh + 0.05), 11.8, rh, color=NAVY, lw=0))
    for j, hh in enumerate(headers):
        ax.text(col_x[j], y - rh / 2 + 0.05, s(hh), fontsize=12.5, color="white",
                weight="bold", va="center")
    for i, row in enumerate(rows):
        yy = y - rh * (i + 1)
        hl = (hi is not None and i == hi)
        fc = "#E3F1E8" if hl else (LIGHT if (i + 1) % 2 else "white")
        ax.add_patch(plt.Rectangle((0.75, yy - rh + 0.05), 11.8, rh, color=fc, lw=0,
                                   ec="#D9E0E8"))
        for j, v in enumerate(row):
            ax.text(col_x[j], yy - rh / 2 + 0.05, s(str(v)), fontsize=11.5,
                    color=GREEN if hl else DARK, weight="bold" if hl else "normal",
                    va="center")
    by = y - rh * (len(rows) + 1) - 0.2
    ax.add_patch(plt.Rectangle((0.7, by - 1.15), 11.9, 1.15, color=BOX, lw=0))
    wrap(ax, "What it means:  " + note, 0.95, by - 0.12, 120, 12.5, color=DARK, dy=0.28)
    save(fig)

def closing():
    fig, ax = newfig(NAVY)
    ax.text(0.9, 5.0, "Defend what's spreading --", fontsize=36, color="white",
            weight="bold", va="top")
    ax.text(0.9, 4.15, "not just who's connected.", fontsize=36, color="#C7D6EC",
            weight="bold", va="top")
    wrap(ax, "Infer the unseen exploit from the shape of the outbreak, and defend the "
         "machines that can actually catch it.", 0.9, 3.1, 80, 16, color="#9FB4D4",
         style="italic")
    ax.text(0.9, 1.2, "SERUM  ·  Amritha S.  ·  Defensive research; no weaponizable attack code.",
            fontsize=12, color="#7F94B4", va="top")
    save(fig, number=False)

# ================= build the deck =================
title_slide()

divider(1, "The Problem", "Why containing malware is hard when you can't see the attack")
bullets("Malware spreads like an epidemic -- but a picky one", [
    "A self-propagating worm moves host to host, like a disease over a contact network.",
    "The malware twist: a worm exploiting vulnerability c can infect a neighbour ONLY IF "
    "that neighbour runs the vulnerable software (carries c).",
    "So a machine without the weakness is simply immune to THIS worm -- the germ bounces off.",
    ("Consequence: the worm travels only the SUB-network of machines that share its target "
     "weakness, not the whole network.", 15, ACCENT)], kicker="The Problem")
worked("The picky germ, concretely",
       "Think of each machine as 'wearing socks' -- the software it runs. The worm only infects one colour.",
       [("RED", "Machines running the vulnerable software (carry the target CVE) -- CAN catch it.", GREEN),
        ("BLUE", "Machines running something else -- the worm bounces off. Totally safe.", ACCENT),
        ("SPREAD", "The worm walks the network but only crosses into RED machines.", NAVY)],
       "So the 'real' network the worm uses = the RED sub-network, not the whole graph.")
bullets("The physical network is NOT the propagation graph", [
    "Physical topology: every machine and every link.",
    "Propagation graph: only the machines carrying the target CVE, and the links between them.",
    "These can look completely different -- the vulnerable machines might be scattered in a "
    "corner, not spread across the hubs.",
    ("A defender who confuses the two will defend the wrong thing.", 15, AMBER)],
    kicker="The Problem", lead="The network a worm actually traverses is a payload-specific SUB-graph.")
bullets("Why the usual defense wastes its budget", [
    "You never have enough budget to protect every machine -- you pick a few.",
    "Standard heuristics (degree, betweenness immunization) pick the network hubs.",
    "But a hub is irrelevant to THIS worm if it can't run the exploit -- a blue-socks machine. "
    "Every band-aid spent on it is wasted.",
    ("On real networks the vulnerable machines are often NOT the hubs -- so 'protect the hubs' "
     "barely helps.", 15, ACCENT)], kicker="The Problem")
bullets("The twist that makes it a real research problem", [
    "You don't get told the worm's target vulnerability -- no signature, no payload capture.",
    "You observe: the set of currently-infected machines, and your own asset inventory.",
    "So you must DEFEND the vulnerable sub-network without being told which sub-network it is.",
    ("This elevates it from 'SI on a subgraph' to a genuine inference problem.", 15, NAVY)],
    kicker="The Problem", lead="The defender NEVER observes the payload -- only who is infected.")
bullets("The clue hiding in plain sight", [
    "A machine can only be infected by spread if it was vulnerable to the worm.",
    "So each newly-infected machine is a hard CONSTRAINT: the true exploit lies in its software profile.",
    "Intersect those profiles across all infected machines -> the set of consistent exploits shrinks.",
    ("SERUM turns this into online Bayesian inference -- a POMDP whose hidden state is the "
     "exploit -- and acts under that belief.", 15, ACCENT)],
    kicker="The core idea", lead="Because spread is vulnerability-gated, every infected machine MUST carry the target CVE.")

divider(2, "Thesis & Contributions", "What we claim, and what we honestly do not")
bullets("Thesis", [
    ("A defender that reasons about WHAT is spreading -- the payload's target vulnerability -- "
     "contains a worm far more efficiently, with far less collateral disruption, than one that "
     "sees only network STRUCTURE.", 20, NAVY),
    ("...and this holds even when the payload is never directly observed -- it is inferred from "
     "the shape of the outbreak.", 16, GREY)], kicker="Thesis")
bullets("Honest from the start: what is and isn't new", [
    ("NOT novel (we claim none of this):", 16, NAVY),
    ("vulnerability-gated spread = multitype bond percolation; structure-only immunization "
     "baselines are classical; POMDP defense & group testing are established.", 14, GREY),
    ("Our contribution -- the COUPLING no prior work occupies:", 16, NAVY),
    "online inference of the unobserved exploit from a vulnerability-gated cascade, with a "
    "checkable identifiability condition on OBSERVABLE attributes, driving budgeted content-aware "
    "containment, on REAL NVD/CVE data. (The cell CyGym 2025 leaves open.)"],
    kicker="Positioning")
bullets("The four contributions (we lead with the finding)", [
    "C1 -- Content-aware containment: on a REAL topology it substantially beats every "
    "structure-only baseline (-28.4%, p=1.7e-7).",
    "C2 -- An identifiability CHARACTERIZATION: identifiable iff infected profiles intersect in "
    "a singleton; + a measured group-testing sample-complexity rate.",
    "C3 -- A REAL-DATA evaluation (NVD/CVE) with paired statistics and honest scope.",
    ("Robustness note -- attacking the inference backfires; poisoning is absorbed (graceful "
     "degradation, not a superiority claim).", 15, GREY)], kicker="Overview")

divider(3, "Problem Formulation", "The containment POMDP, precisely")
bullets("The SERUM POMDP -- the pieces", [
    "Hosts & profiles: graph G=(V,E); each host v carries X(v), the CVEs it is exploitable by.",
    "Hidden state: the worm's target c*. The defender never sees it.",
    "Vulnerable subgraph: carriers(c*) and their links -- the graph the worm can use.",
    "Observation each step: the infected set (not c*) + the static inventory.",
    "Actions (budget B/step): PATCH (immunize, keeps host online), ISOLATE (remove, costs "
    "availability), SEGMENT (cut a link)."], kicker="Method")
worked("How a single spread step works",
       "Infected u tries to infect susceptible neighbour w. Success is GATED:",
       [("CHECK", "Does w carry the target CVE c*?  (Is w red-socks?)", NAVY),
        ("NO", "w is immune to this worm. Nothing happens -- ever.", ACCENT),
        ("YES", "w gets infected with probability beta (transmissibility).", GREEN)],
       "Repeat over all infected->susceptible edges -> the outbreak grows within the red subgraph.")
bullets("The objective -- three things at once", [
    "Minimize final/peak INFECTION (how much of the fleet falls).",
    "Minimize AVAILABILITY loss (isolating machines takes them offline).",
    "Minimize TIME-TO-CONTAINMENT (stop it fast).",
    ("This is why PATCH vs ISOLATE matters: patching immunizes without downtime, but you only "
     "dare patch precisely once confident which machines are truly at risk.", 15, ACCENT)],
    kicker="Method", lead="Containment is multi-objective -- not just infection count.")

divider(4, "Theory -- Identifiability", "When can you actually figure out the exploit?")
bullets("The question the theory answers", [
    "If you can pin the exact CVE, you can defend its subgraph exactly.",
    "If two CVEs are indistinguishable from the infections seen, you must hedge across both.",
    "We want a CHECKABLE condition -- one a defender can evaluate in advance from its inventory.",
    ("It turns out to be a simple set-containment condition on observable attributes.", 15, NAVY)],
    kicker="Theory", lead="Given only who's infected, when is the hidden exploit uniquely recoverable?")
worked("Worked example: narrowing to the exploit",
       "supp = intersection of infected profiles. Watch the candidate set shrink as machines fall.",
       [("Host A", "infected. Runs {CVE-1, CVE-2, CVE-5}.  Candidates = {1,2,5}.", NAVY),
        ("Host B", "infected. Runs {CVE-2, CVE-5, CVE-9}.  {1,2,5} n {2,5,9} = {2,5}.", NAVY),
        ("Host C", "infected. Runs {CVE-5, CVE-7}.  {2,5} n {5,7} = {5}.", GREEN)],
       "Intersection collapsed to a single CVE -> the exploit is identified: it must be CVE-5.")
bullets("The identifiability theorem", [
    "'Saturating' = the outbreak has infected everything reachable in the vulnerable subgraph.",
    "Single-CVE intersection -> you know the attack exactly.",
    "Two or more -> those CVEs are 'confusable'; watching this outbreak can't separate them.",
    ("HONEST: the belief's support EQUALS this intersection by construction -- so it's a "
     "characterization of the observation model, not a deep theorem. The '100% validation' is a "
     "consistency check on the code, not a prediction.", 14, AMBER)],
    kicker="Theory", lead="c* is identifiable from a saturating outbreak over R  iff  intersection(profiles in R) = {c*}.")
bullets("Confusability = the subset order", [
    "If carriers(c) is a SUBSET of carriers(c'), every c-victim also carries c' -- so a "
    "c-outbreak can never rule c' out. c' is a confuser of c.",
    "A CVE is globally identifiable iff no other CVE's carrier set is a superset of its own.",
    ("Powerful for DEFENSE: even if you can't tell c from c', defending c''s (larger) subgraph "
     "OVER-COVERS the true victims -- you still protect them.", 15, GREEN)],
    kicker="Theory", lead="One CVE hides behind another exactly when its victims are a subset of the other's.")
bullets("It's group testing -- realized by contagion", [
    "Classic group testing: identify a defective by pooling and testing subsets.",
    "Here each infection is one 'positive test' whose profile-set is intersected into the "
    "running candidate set (Renyi separating systems; Kautz-Singleton cover-free families).",
    "Our twist: the 'tests' aren't designed -- they're the fleet's given software profiles -- "
    "and outcomes are produced by an adversarial, graph-constrained spread, observed online.",
    ("So identification inherits the group-testing log2(K) bit-bound.", 15, ACCENT)],
    kicker="Theory", lead="The whole inference is online, graph-induced, adversarial group testing.")
figure("Confusability structure (real NVD networks)", os.path.join(FIG, "confusability.png"),
       "left: most CVEs have ZERO confusers (identifiable). middle: identifiable fraction decays "
       "as the CVE universe K grows. right: a drawn slice of the confusability graph.", kicker="Theory")
figure("Sample complexity -- how fast you identify the exploit", os.path.join(FIG, "sample_complexity.png"),
       "distribution of infections until the candidate set collapses to one CVE. Median ~= 5 "
       "infections ~= 1.02 x log2(K) -- essentially the information-theoretic minimum. Real profile "
       "correlation bends the rate TOWARD the optimum.", kicker="Theory")

divider(5, "The Method", "The belief, and the content-aware policy")
worked("The belief update, step by step",
       "The agent keeps a probability over which CVE is the attack, and sharpens it each step.",
       [("PRIOR", "Start from CVE prevalence (or a CVSS/LLM threat-intel prior for cold start).", NAVY),
        ("OBSERVE", "New infections arrive. Each one must carry the true CVE.", ACCENT),
        ("UPDATE", "Down-weight (soft) or eliminate (hard) CVEs inconsistent with new victims.", ACCENT),
        ("ACT", "Take the expectation of the defense score over the current belief.", GREEN)],
       "Early: belief broad -> hedge. Later: belief sharp -> commit. It acts under uncertainty.")
bullets("Soft vs hard likelihood -- why soft wins", [
    "HARD consistency eliminates any CVE absent from an infected host's profile -- exact, but a "
    "single false-positive detection can wrongly eliminate the TRUE CVE.",
    "SOFT likelihood DOWN-WEIGHTS instead -- one bad observation can't exclude the truth.",
    ("Soft is robust to noisy detection and to deliberate belief-poisoning, and is what we deploy "
     "in every deployment-facing experiment.", 15, GREEN)],
    kicker="Method", lead="Real detection is noisy -- hard elimination is brittle, soft is robust.")
bullets("The content-aware policy -- the scoring rule", [
    "For a host v: how many neighbours are (a) still susceptible AND (b) exploitable by a CVE the "
    "belief thinks is live? Average that over the belief = v's expected onward infections.",
    "Defend the highest-scoring hosts. It generalizes 'degree' immunization to the uncertain-"
    "payload regime, reducing to plain degree when everything is vulnerable.",
    ("While uncertain -> ISOLATE (blunt but certain). Once the belief's support collapses -> "
     "PATCH (immunize precisely, keep hosts online).", 15, ACCENT)],
    kicker="Method", lead="Score each frontier host by its belief-weighted EXPOSED-VULNERABLE DEGREE.")

divider(6, "Results", "Synthetic, real-topology, and real-data -- with honest scope")
bullets("Experimental design -- why it's trustworthy", [
    "Paired design: same graph, target CVE, seeds, and infection coin-flips for every defender in "
    "a trial -- slashes variance, makes deltas real.",
    "Randomized target CVE per trial -- no cherry-picked attack.",
    "Real vulnerabilities from NVD/CVE; per-CVE transmissibility from CVSS.",
    ("Paired Wilcoxon + Holm-Bonferroni correction on headline claims; we report per-trial WIN "
     "RATES, not just means.", 15, NAVY)], kicker="Results")
table("Headline -- synthetic networks, real CVEs",
      ["Defender", "Infected", "Availability", "Contain@step"],
      [["No defense", "36.6%", "100%", "14.2"],
       ["Best structural (degree/betweenness)", "3.4%", "95.5%", "4.5"],
       ["SERUM -- content-aware (ours)", "1.8%", "98.5%", "3.0"],
       ["Oracle (is told the exploit)", "1.1%", "100%", "2.0"]],
      "Beats the best structural baseline on infection AND availability AND speed -- without being "
      "told the attack. Honest: the absolute gap here is small; the decisive gap is on real topology.",
      hi=2, col_x=[0.95, 7.4, 9.2, 11.1])
table("Flagship -- a REAL organisational network",
      ["Defender", "Infected", "Availability"],
      [["No defense", "20.1%", "100%"],
       ["Degree immunization", "18.8%", "92.2%"],
       ["Betweenness (best structural)", "17.6%", "92.5%"],
       ["SERUM -- content-aware (ours)", "11.7%", "97.5%"],
       ["Content-aware oracle (bound)", "9.1%", "100%"]],
      "SNAP email-Eu-core: 1004 REAL hosts, 42 REAL departments as software zones, real NVD CVEs. "
      "Structure-only BARELY helps (17.6% vs 20.1%) -- vulnerable departments aren't the hubs. "
      "Content-aware cuts to 11.7%: -28.4%, p=1.7e-7. The result we lead with.",
      hi=3, col_x=[0.95, 8.6, 10.7])
figure("Flagship -- infection over time (real topology)", os.path.join(FIG, "flagship_infection_curves.png"),
       "structure-only curves sit on top of no-defense; the content-aware curve is far below, hugging "
       "the oracle. The gap between them is the value of content-awareness.", kicker="Results")
bullets("The lead result is NOT a fragile minority effect", [
    ("20 / 20 paired outbreaks WON on the real topology -- vs betweenness AND the ensemble oracle "
     "(p=8.8e-5). 37/40 in a budget-8 replication.", 17, GREEN),
    "On the small synthetic margins, content-aware wins only a MINORITY of trials -- a fair critic "
    "would pounce. On the REAL topology it wins essentially EVERY outbreak, by 5.9pp absolute.",
    ("Honest boundary: on hub-aligned or near-universal-exploit regimes the edge is small or "
     "vanishes. We say so.", 15, AMBER)], kicker="Results")
figure("Pareto dominance -- infection vs availability", os.path.join(FIG, "pareto.png"),
       "each point = one defender at one budget; down-and-right is better. Content-aware sits in the "
       "bottom-right corner at EVERY budget -- lower-infection AND higher-availability than every "
       "structural baseline.", kicker="Results")
figure("The advantage scales with outbreak severity", os.path.join(RES, "prevalence_curve.png"),
       "relative reduction vs the best structural baseline across prevalence bands -- it grows with "
       "severity. Honest: in low-prevalence bands content-aware wins a MINORITY of trials and one "
       "band isn't significant.", kicker="Results")
table("Head-to-head vs the CLOSEST prior systems",
      ["Defender (of this class)", "Infected", "vs ours"],
      [["DAVA-style -- data-aware, exploit-blind", "1.70%", "+43.8% · p=2.8e-4"],
       ["CyGym-style -- static prior, no update", "1.15%", "+16.6% · p=1.1e-2"],
       ["SERUM -- content-aware (ours)", "0.95%", "--"]],
      "We beat BOTH nearest systems. DAVA even underperforms plain degree -- vaccinating exposed-"
      "but-non-exploitable hosts wastes budget, i.e. the thesis. Honest: these are faithful "
      "reimplementations of each system's STANCE, not the full originals.",
      hi=2, col_x=[0.95, 7.6, 9.7])
bullets("When does the ONLINE inference actually matter?", [
    "Under a GOOD prior, online updating beats a frozen prior by only +0.19pp -- consistent with "
    "our ablation that freezing the belief costs almost nothing.",
    "It earns its keep when the prior is WRONG: under a misleading prior the edge roughly DOUBLES "
    "to +0.44pp (p=1.8e-2).",
    ("So online inference is a refinement that matters most under bad threat intel -- NOT the main "
     "source of the win. We say this plainly.", 15, AMBER)],
    kicker="Analysis", lead="Content-AWARENESS is the driver; the online UPDATE is a smaller refinement.")

divider(7, "Robustness", "Can an attacker defeat the defender by attacking its inference?")
bullets("Attacking the inference BACKFIRES", [
    "A confusable exploit's victims are a SUBSET of its confuser's victims.",
    "So even a hedged belief that can't tell them apart still DEFENDS the true victims -- they're "
    "inside the set it protects.",
    "Empirically the content-aware edge is LARGER under an evasive attacker (+22.4%) than a random "
    "one (+17.7%).",
    ("Inference-evasion is not a winning strategy -- a structural guarantee, not luck.", 15, GREEN)],
    kicker="Robustness", lead="An attacker who picks a hard-to-identify payload does not help itself.")
bullets("Belief poisoning, and the honest limit", [
    "Fix: a RobustAgent audits its belief vs the real spread and hedges to structure when they "
    "diverge -- poisoning is one-shot, the real worm keeps revealing the truth.",
    "Against a white-box, audit-AWARE adaptive poisoner it holds up to 6% of the fleet; only at an "
    "extreme 10% does the attacker gain a small edge (which fails multiple-comparison correction).",
    ("HONEST: this is GRACEFUL DEGRADATION, not a win. Under poisoning the content-aware advantage "
     "evaporates and the agent falls back to -- never below -- structure. A safety net.", 14, AMBER)],
    kicker="Robustness", lead="A stronger attacker plants FAKE infections to mislead the belief.")
bullets("Two more robustness stresses", [
    ("Imperfect detection sensors: model missed detections + persistent false alarms. Content-aware "
     "degrades GRACEFULLY (positive edge at 9 of 10 noise points); false alarms are the sensitive "
     "channel. Not a new significant win.", 15, DARK),
    ("Is the win a manufactured artifact? We sweep the monoculture 'homophily' knob 0->0.8. The "
     "edge is significant even at 0 (no monoculture, +0.26pp, p=6.5e-4). So it's NOT a knob "
     "artifact -- homophily only controls spatial clustering. (This rebuts the knob worry, not the "
     "semi-synthetic-data limitation.)", 15, GREEN)], kicker="Robustness / threats to validity")

divider(8, "Breadth & Honesty", "Generalization, positioning, and the limits we own")
bullets("Breadth -- application & learned policy", [
    "IoT botnet (Mirai-style): device-firmware monoculture; host value = uplink Mbps, so blast "
    "radius = DDoS capacity conscripted. Content-aware cuts DDoS blast -8.71pp vs degree (20/20 wins).",
    "Learned policy: a cross-entropy-method policy over belief features MATCHES the hand-designed "
    "agent and beats degree/betweenness -- and independently learns to weight the belief features "
    "most, validating the design (learning UNDER exploit uncertainty, not vanilla GNN-RL)."],
    kicker="Breadth")
table("The three nearest systems -- cite, then differentiate",
      ["Prior work", "Shares with SERUM", "The gap SERUM fills"],
      [["CyGym (2025)", "vuln-gated spread + cost model", "STATIC prior; no online update"],
       ["SCENARIOID (KDD'23)", "infer mechanism from cascade", "OFFLINE; no ID guarantee"],
       ["Hoffmann (ICML'20)", "identifiability from cascades", "LATENT edges (harder setting)"]],
      "We cite all three prominently and state each delta in the same breath -- including, honestly, "
      "that our observable-attribute setting is in some ways EASIER than Hoffmann's, not strictly "
      "stronger.", col_x=[0.95, 4.0, 8.4])
bullets("Honest limitations (several load-bearing)", [
    "L1 -- Not yet validated on real HOST-LEVEL data (measured per-host inventories are "
    "proprietary). The single most important gap.",
    "L2 -- Online inference is a REFINEMENT, not the driver. L3 -- host<->CVE mapping is MODELED.",
    "L4 detection noise, L5 adaptive adversary, L6 multiplicity -- addressed (with caveats).",
    "L7 -- Abstract model: no packet-level malware, scanning, or C2 layer."],
    kicker="Honesty", lead="We state these plainly -- a paper is stronger for owning them.")
bullets("L1 -- ready to close in ONE command", [
    "We will NOT fabricate a real inventory, and another synthetic model wouldn't satisfy L1.",
    "We ship a TESTED pipeline (serum/data/real_inventory.py, scripts/validate_real_inventory.py) "
    "that builds the network from a real scan (measured host,CVE findings) + a topology edge list, "
    "taking each host's vulnerabilities VERBATIM from the scan.",
    ("So L1 is gated on DATA ACCESS, not on method or engineering. One command away.", 15, GREEN)],
    kicker="Honesty", lead="We can't close L1 without proprietary data -- but we made it ready for the instant it exists.")
bullets("What holds up under grilling", [
    "Pareto dominance; real-topology flagship (-28.4%, p=1.7e-7, wins 20/20).",
    "Beats the closest prior systems (CyGym-style, DAVA-style) head-to-head.",
    "Survived FIVE rounds of hostile self-review.",
    ("Every headline number is backed by a committed result file and guarded by a test; experiments "
     "reproduce bit-for-bit; the paper compiles clean; 141 tests green.", 15, GREEN)], kicker="Summary")

divider(9, "Outlook", "")
bullets("Future work", [
    "Validate on a real host-level enterprise inventory (L1) -- the highest-value next step.",
    "A jointly-adaptive adversary (payload + timing + placement together).",
    "End-to-end containment for polymorphic (multi-exploit) worms.",
    "A learned GNN policy; an LLM tool-use agent reading structured threat intel.",
    "An emulation bridge (packet-level) from the abstract model."], kicker="Outlook")
closing()

pdf.close()
print(f"saved {OUT}  ({_pageno[0]} numbered content pages + title/dividers/closing)")
