# Data sources

All files retrieved 2026-11-19. Everything here is public data; no paywall,
no login, no payment was involved.

## The 60 SL5 controls — `sl5-controls.csv`

Authoritative enumeration: the **SL5 Standard OSCAL profile v0.1.3**,
`data/raw/sl5-profile.json` (50 KB),
https://standard.sl5.org/sl5-profile.json

Its `imports` list exactly 60 unique control IDs: 59 from NIST SP 800-53
Rev. 5 plus SR-13 from NIST SP 800-161. Its `modify.alters` (43 entries)
carry the SL5 supplemental guidance per control; `modify.set-parameters`
(26 entries) carry SL5 parameter assignments (19 controls have values).

Control titles and NIST statement text come from the catalogs the profile
imports:

- `data/raw/NIST_SP-800-53_rev5_catalog.json` (10.4 MB) — NIST SP 800-53
  Rev. 5.2.0 OSCAL catalog, the exact file the profile imports:
  https://raw.githubusercontent.com/usnistgov/oscal-content/78650f02ad9321bb7b817846f8fbd4f2bcd620de/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
- `data/raw/sl5-sr13-catalog.json` (8 KB) — OSCAL catalog for SR-13
  (SP 800-161): https://standard.sl5.org/catalogs/NIST_SP-800-161r1-upd1_sr-13_catalog.json

Cross-check source (not used for the enumeration):
`data/raw/sl5-standard.txt` — text dump of Thiergart et al. 2026,
*SL5 Standard for AI Security*, arXiv:2605.08449 (submitted 8 May 2026),
https://arxiv.org/abs/2605.08449 (PDF: https://arxiv.org/pdf/2605.08449).

**Important version note:** the arXiv paper is an older snapshot. Its
section 3 lists only 42 control headings and has no Incident Response (IR)
or Risk Assessment (RA) families. The live Standard (updated 13 Nov 2026)
has 60 controls across 12 families (AC 7, CM 2, IA 1, IR 1, PE 6, PM 1,
PS 3, RA 1, SA 5, SC 15, SI 7, SR 11) — that is what the OSCAL profile
enumerates, and that is what `sl5-controls.csv` contains. The mapping work
must use the 60-control list, not the 42 headings in the paper.

Re-fetch:
```bash
cd data/raw
curl -sL -o sl5-profile.json https://standard.sl5.org/sl5-profile.json
curl -sL -o NIST_SP-800-53_rev5_catalog.json "https://raw.githubusercontent.com/usnistgov/oscal-content/78650f02ad9321bb7b817846f8fbd4f2bcd620de/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
curl -sL -o sl5-sr13-catalog.json https://standard.sl5.org/catalogs/NIST_SP-800-161r1-upd1_sr-13_catalog.json
curl -sL -o sl5-standard-arxiv-2605.08449.pdf https://arxiv.org/pdf/2605.08449
pdftotext -layout sl5-standard-arxiv-2605.08449.pdf sl5-standard.txt
```

## The 38 RAND attack vectors — `rand-vectors.csv`

Source: Nevo, Lahav, Karpur, Bar-On, Bradley & Alstott, *Securing AI Model
Weights: Preventing Theft and Misuse of Frontier Models*, RAND Corporation,
RR-A2849-1, May 2024 (revised June 2024). DOI 10.7249/RRA2849-1.
https://www.rand.org/pubs/research_reports/RRA2849-1.html

The authoritative enumeration is **Table 5.1, "Summary of Attack Vectors"**
(Chapter 5, p. 12): nine categories, 4+4+4+3+5+3+7+3+5 = **exactly 38**
vectors. Descriptions are the first sentence of each vector's Appendix A
subsection ("Detailed List of Attack Vectors", pp. 37+).

`data/raw/rand-report.txt` is a text dump of the report PDF, produced with
`pdftotext -layout`.

**One gap, stated honestly:** Table 5.1 vector V17, "Intentional ML supply
chain compromise", has **no dedicated Appendix A subsection** — the phrase
does not appear in Appendix A at all (it is only mentioned in passing
elsewhere in the report). Its `description` field is therefore empty in
`rand-vectors.csv`. The sprint must either describe it from the Table 5.1
context or leave the field empty and say so in the report — not invent a
description.

Re-fetch (the RAND PDF needs a browser User-Agent + Referer; a plain curl
gets HTTP 403 from CloudFront):
```bash
cd data/raw
curl -sL -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36" \
  -H "Referer: https://www.rand.org/pubs/research_reports/RRA2849-1.html" \
  -H "Accept: application/pdf,*/*" \
  -o rand-securing-ai-model-weights-RRA2849-1.pdf \
  "https://www.rand.org/content/dam/rand/pubs/research_reports/RRA2800/RRA2849-1/RAND_RRA2849-1.pdf"
pdftotext -layout rand-securing-ai-model-weights-RRA2849-1.pdf rand-report.txt
```

**Note on the RAND PDF:** the report states it is provided for noncommercial
use and that unauthorised posting online is prohibited. The PDF itself is
therefore NOT committed to this repo (see `.gitignore`); only the extracted
table data (facts: vector names and categories) and the first-sentence
descriptions are included, with full citation.

## Extraction scripts

- `scripts/extract_sl5.py` → `sl5-controls.csv` (60 rows, 12 families;
  43 rows with SL5 guidance, 19 with SL5 parameter values).
- `scripts/extract_rand.py` → `rand-vectors.csv` (38 rows; 37 with an
  Appendix A description, 1 empty — see above).

Both scripts print a verification summary and refuse to write output unless
the counts are exact. Re-run with:
```bash
python3 scripts/extract_sl5.py
python3 scripts/extract_rand.py
```
