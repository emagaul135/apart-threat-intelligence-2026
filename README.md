# Map the Controls to the Threats

**Apart Research — Threat Intelligence & Threat Modelling Sprint, 4–6 December 2026**
(Submission deadline: Sun 6 Dec 2026, 11:59 PM AoE = Mon 7 Dec 2026, 18:59 WIB)

**Question:** Taking the SL5 Standard's 60 controls and RAND's ~38 attack vectors
against AI model weights, can an LLM map each control to the vectors it
addresses — and which vectors does no control cover?

**Method (sprint weekend, 4–6 Dec):** run an LLM mapping pass (each SL5 control →
RAND vectors addressed, with a one-line justification citing the control text),
repeat it 3× to measure run-to-run agreement, and hand-check a random sample
of 30 mappings against the source texts to report an error rate. Outputs: a full
mapping table, a gap list (vectors with no covering control), and agreement +
error-rate statistics.

**Author:** Diden Rahmadian (solo).

## Status

Pre-sprint scaffolding only (prepared 19 Nov 2026 — see **Preexisting work**
below). The mapping runs, evaluation, analysis and report are sprint-weekend
work (4–6 Dec 2026) and do not exist yet.

## Repository layout

```
├── README.md
├── LICENSE                     # MIT
├── PREP-REPORT.md              # pre-sprint prep report (what was verified)
├── data/
│   ├── SOURCES.md              # where every source file came from + retrieval date
│   ├── sl5-controls.csv        # 60 SL5 controls (id, family, title, NIST statement,
│   │                           #   SL5 guidance, SL5 parameters, source)
│   ├── rand-vectors.csv        # 38 RAND attack vectors (id, category, name,
│   │                           #   description, source)
│   └── raw/                    # source documents + machine-readable inputs
│       ├── sl5-profile.json            # SL5 Standard OSCAL profile v0.1.3
│       ├── sl5-sr13-catalog.json       # OSCAL catalog for SR-13 (SP 800-161)
│       ├── NIST_SP-800-53_rev5_catalog.json   # NIST SP 800-53 Rev. 5.2.0 OSCAL catalog
│       ├── sl5-standard.txt            # arXiv:2605.08449 text dump (cross-check only)
│       ├── rand-report.txt             # RAND RR-A2849-1 text dump (Table 5.1 source)
│       └── *.pdf                       # NOT committed (see SOURCES.md for fetch commands)
├── scripts/
│   ├── extract_sl5.py          # PREEXISTING: profile + catalogs -> sl5-controls.csv
│   └── extract_rand.py         # PREEXISTING: RAND Table 5.1 + Appendix A -> rand-vectors.csv
├── results/                    # sprint-weekend outputs (mapping, gaps, agreement, handcheck)
└── report/                     # sprint-weekend report source + final PDF
```

## Reproduce the extraction (pre-sprint step)

```bash
python3 scripts/extract_sl5.py    # expects data/raw/sl5-profile.json + NIST catalogs
python3 scripts/extract_rand.py   # expects data/raw/rand-report.txt (pdftotext -layout)
```

Both scripts use only the Python standard library (`extract_rand.py` also uses
the `pdftotext` command-line tool if the `.txt` dump is missing). They print a
verification summary and refuse to write output unless the counts are exact:
**60 SL5 controls, 38 RAND vectors.**

## Preexisting work (prepared BEFORE the sprint weekend)

Per the sprint rules, only the weekend's work is judged, and pre-sprint work
must be stated clearly. The following were prepared before Fri 4 Dec 2026:

- This repo scaffold (README, folders, licence, `.gitignore`).
- `scripts/extract_sl5.py` and `scripts/extract_rand.py` (the extraction scripts).
- The source documents in `data/raw/` and the extracted tables
  `data/sl5-controls.csv` (60 controls) and `data/rand-vectors.csv` (38 vectors).
- The sprint plan and prep report (kept outside this repo).

**Not** done before the sprint: the control→vector mapping runs, any evaluation
or agreement measurement, any hand-checking, any analysis, any report writing.
All of that happens during the sprint weekend (4–6 Dec 2026) and will be
committed then, in `results/` and `report/`.

## Sources

- SL5 Standard for AI Security, v0.1.3 — Thiergart et al. 2026
  (arXiv:2605.08449; https://standard.sl5.org). The 60 controls are enumerated
  by the machine-readable OSCAL profile
  (https://standard.sl5.org/sl5-profile.json): 59 controls from NIST SP 800-53
  Rev. 5 plus SR-13 from NIST SP 800-161.
- Nevo et al. 2024, *Securing AI Model Weights*, RAND Corporation, RR-A2849-1
  (DOI 10.7249/RRA2849-1). The 38 attack vectors are enumerated in Table 5.1
  (Chapter 5, p. 12); descriptions come from Appendix A.
- Full provenance, retrieval dates and re-fetch commands: `data/SOURCES.md`.

## Licence

MIT — see `LICENSE`.
