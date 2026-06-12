# Figures Guide for the FLARE Paper

The paper (`flare_paper.tex`) contains **5 figures**. Four come straight out of
the Colab run (C1–C4) and one is a diagram you generate with Gemini /
draw.io / PowerPoint (G1). Each figure in the `.tex` is currently a framed
placeholder with a commented `\includegraphics` line right above it — drop the
file into your Overleaf project, uncomment the line, and delete the
`\figplaceholder` line.

---

## Part A — Figures to take from Colab (the experiment outputs)

Run the notebook (`notebooks/FLARE_Colab.ipynb`, **Runtime → Run all**). The
optional Section 11 cell (`!python scripts/run_experiments.py --outdir figures`)
writes all four PNGs to `/content/project_flare/figures/`.

### How to download them from Colab
**Option 1 (Files pane):** click the 📁 folder icon in Colab's left sidebar →
`project_flare/figures/` → right-click each PNG → *Download*.

**Option 2 (terminal/cell):** run this in a new cell:

```python
from google.colab import files
for f in ["01_attack_no_defense.png", "02_detection_timeline.png",
          "03_forecast.png", "04_mitigation.png"]:
    files.download(f"/content/project_flare/figures/{f}")
```

### Mapping to the paper

| ID | Colab file | Rename to (for Overleaf) | Paper figure | LaTeX label |
|----|------------|--------------------------|--------------|-------------|
| C1 | `figures/01_attack_no_defense.png` | `fig_attack_no_defense.png` | Fig. 2 — LOFT attack on undefended switch | `fig:attack` |
| C2 | `figures/02_detection_timeline.png` | `fig_detection_timeline.png` | Fig. 3 — detection timeline + anomaly score | `fig:timeline` |
| C3 | `figures/03_forecast.png` | `fig_forecast.png` | Fig. 4 — time-to-overflow forecast | `fig:forecast` |
| C4 | `figures/04_mitigation.png` | `fig_mitigation.png` | Fig. 5 — mitigation effect | `fig:mitigation` |

**Important:** make sure your Colab cloned the **latest commit** before
exporting (Runtime → Disconnect and delete runtime, then re-run all), otherwise
figure C3 will show the old, noisy forecast. The clean version shows a single
curve hugging the 361 s line.

*Tip for print quality:* before exporting you can bump matplotlib DPI in a cell:
`import matplotlib as mpl; mpl.rcParams['figure.dpi'] = 200` — or just use the
`run_experiments.py` outputs, which are already saved at 130 DPI (fine for a
two-column figure).

---

## Part B — Figure to generate with Gemini (or draw.io / PowerPoint)

### G1 — FLARE architecture diagram (Fig. 1, label `fig:arch`)
File name expected by the `.tex`: `fig_architecture.pdf` (or `.png`).

**Paste this prompt into Gemini (or use it as a spec to draw it yourself in
draw.io — for a paper, a hand-drawn vector diagram usually looks cleaner than a
generated image):**

> Create a clean, flat, publication-quality system architecture diagram for an
> IEEE two-column paper, white background, no gradients, no 3D, no decorative
> icons, sans-serif labels.
>
> Layout, left to right:
> 1. A box labeled "SDN switch (flow table, capacity C, idle timeout T)" with
>    a small note "per-window counters: occupancy, misses, installs, expiries,
>    packets".
> 2. An arrow to a box labeled "Feature extraction (1 s windows)" listing:
>    "occupancy ratio, growth g_t, miss rate, install rate, expiry rate,
>    short-lived rate, traffic per flow".
> 3. From feature extraction, four parallel arrows into a column of four boxes
>    stacked vertically:
>    - "Early-warning detector — probing churn + low-occupancy gate"
>    - "Core detector — CUSUM drift + directional z-scores, freeze-on-alarm"
>    - "Time-to-overflow forecaster — gated linear trend, ETA"
>    - "Explainer — top-k feature attribution → plain-language reason"
> 4. Arrows from the early-warning and core detector boxes converge into a box
>    labeled "k-of-n persistence + alert", which feeds a final box
>    "Mitigation — selective eviction + timeout hardening", which has a dashed
>    feedback arrow back to the SDN switch box.
>
> Use a restrained two-color palette (dark blue boxes, orange accent for the
> alert path). Output as a wide rectangular image suitable for a single-column
> figure (about 3.5 inches wide).

If Gemini's output looks fuzzy, recreate the same layout in **draw.io**
(File → Export as → PDF, crop to content) — vector output scales perfectly in
LaTeX and looks more professional than raster AI images. The prompt above is
the exact spec.

---

## Part C — Checklist before submission

1. **Compile**: upload `flare_paper.tex` + `references.bib` + the 5 figure
   files to Overleaf, compiler = pdfLaTeX. Compile twice (BibTeX pass).
2. **Swap placeholders**: for each figure, uncomment the `\includegraphics`
   line and delete the `\figplaceholder` line.
3. **Fix the FloRa reference**: the `flora2024` entry in `references.bib` is a
   stub — fill in the real author list, venue, volume, and pages from IEEE
   Xplore. The paper cites it in four places; everything else in the .bib is a
   real, well-known publication (still spot-check page numbers).
4. **Author block**: add co-authors/supervisor in the `\author` block (marked
   with a TODO).
5. **Page budget**: the paper is written to land at ~8 pages in IEEEtran
   two-column format including references. If it runs long after figures go
   in, the Discussion subsections are the safest place to trim.
6. **Numbers**: all results quoted in the paper (361 s overflow, 209/210 s
   FLARE alarms, 336 s baseline, 150 s vs 30 s median leads, 10 s median
   forecast error, 0 % FPR over 20 seeds) come from the current code at this
   commit — if you change detector parameters, re-run
   `python scripts/run_experiments.py` and the 20-seed sweep and update
   Tables II–III accordingly.
