# Pre-sprint prep report — Apart Threat Intelligence & Threat Modelling 2026

Prepared: 2026-11-19. **Pre-sprint scaffolding only.** Nothing was registered,
nothing was submitted, no account was created, no mapping/evaluation/analysis
was run, no report content was written.

Sprint: Fri 4 – Sun 6 Dec 2026 (fixed window). Submission deadline: Sun 6 Dec
2026, 11:59 PM AoE = Mon 7 Dec 2026, 18:59 WIB. Prize: $5,000 (1st $2,500,
2nd $1,250, 3rd $750, 4th $250, 5th $250). Free, global, solo.
Organiser page: https://apartresearch.com/sprints/threat-intelligence-threat-modelling-2026
Full sprint plan: `~/workspace/research_notes/apart-threat-intelligence-plan.md`
(kept outside this repo).

Topic: **"Map the controls to the threats"** — map the SL5 Standard's 60
controls to RAND's ~38 attack vectors against AI model weights; report
coverage %, hand-checked error rate (sample of 30), run-to-run agreement.

## What was scaffolded

- Repo scaffold at `~/workspace/apart-threat-intelligence/`: README.md (with a
  PREEXISTING-work statement), MIT LICENSE, `.gitignore`, folders `data/raw/`,
  `data/processed/`, `scripts/`, `results/`, `report/`.
- Extraction scripts: `scripts/extract_sl5.py`, `scripts/extract_rand.py`
  (Python stdlib only; `extract_rand.py` also uses the `pdftotext` CLI if the
  text dump is missing).
- Source documents in `data/raw/` (see `data/SOURCES.md` for provenance and
  re-fetch commands).

## Extraction counts (verified)

### SL5 controls: 60 — exact

- Authoritative enumeration: the SL5 Standard OSCAL profile v0.1.3
  (`sl5-profile.json`) — its imports list exactly **60 unique control IDs**
  (59 from NIST SP 800-53 Rev. 5 + SR-13 from NIST SP 800-161).
- Families (12): AC 7, CM 2, IA 1, IR 1, PE 6, PM 1, PS 3, RA 1, SA 5,
  SC 15, SI 7, SR 11.
- Titles + NIST statements resolved for all 60 from the NIST SP 800-53
  Rev. 5.2.0 OSCAL catalog (1,196 entries) and the SR-13 local catalog.
  Zero empty titles, zero empty statements.
- SL5 supplemental guidance present for 43 of 60 controls (from the
  profile's `modify.alters`); SL5 parameter values present for 19 controls
  (from `modify.set-parameters`, all 26 mapped, none unmapped).
- Output: `data/raw/sl5-controls.csv` (+ copy at `data/sl5-controls.csv`).

**Key finding — use the OSCAL profile, not the arXiv paper.** The arXiv
paper (Thiergart et al. 2026, arXiv:2605.08449, May 2026) is an older
snapshot: its section 3 lists only **42 control headings** and has no IR or
RA families. The live Standard (updated 13 Nov 2026) has 60 controls across
12 families. The mapping must use the 60-control list.

### RAND attack vectors: 38 — exact

- Authoritative enumeration: **Table 5.1** (Chapter 5, p. 12) of Nevo et
  al. 2024, RAND RR-A2849-1: nine categories, 4+4+4+3+5+3+7+3+5 = **38**.
- Per-category counts verified against the table: Running Unauthorized Code 4,
  Compromising Existing Credentials 4, Undermining the Access Control System
  Itself 4, Bypassing Primary Security System Altogether 3, AI-Specific
  Attack Vectors 5, Nontrivial Access to Data or Networks 3, Unauthorized
  Physical Access to Systems 7, Supply Chain Attacks 3, Human Intelligence 5.
- Descriptions: first sentence of each vector's Appendix A subsection —
  present for **37 of 38**.
- Output: `data/raw/rand-vectors.csv` (+ copy at `data/rand-vectors.csv`).

**One honest gap:** V17, "Intentional ML supply chain compromise", has **no
dedicated Appendix A subsection** — the phrase does not occur in Appendix A
at all. Its description field is empty. Do not invent a description during
the sprint; either describe it from the Table 5.1 context or leave it empty
and say so in the report.

## What worked

- SL5 Standard site (`standard.sl5.org`) serves the full standard as
  server-rendered HTML plus the machine-readable OSCAL profile
  (`/sl5-profile.json`) — no login, no JS execution needed.
- NIST SP 800-53 Rev. 5.2.0 OSCAL catalog downloads cleanly from the pinned
  raw.githubusercontent.com URL in the profile.
- SR-13 local catalog downloads cleanly from `standard.sl5.org/catalogs/`.
- RAND report PDF downloads with a browser User-Agent + Referer header
  (plain curl gets HTTP 403 from CloudFront).
- Both extraction scripts are deterministic and re-runnable; they refuse to
  write output unless the counts are exact (60 / 38).

## What failed / could not be verified

1. **Official report template: NOT fetchable without a Google login.**
   The template link is a Google Docs "copy" URL
   (`docs.google.com/document/d/1vbJBxspRtoSvn95dPYdXSqHtHKhTSDRU8t-h_lz-kRw/copy?usp=sharing`)
   that redirects to a Google sign-in page. Per instructions, no login was
   attempted. **Must be fetched at sprint start** — the parent has a Google
   Docs connector as a fallback.
2. **RAND PDF fetch needs headers** (see SOURCES.md for the working curl
   command). Plain curl returns 403.
3. **SL5 website family pages** (`/controls/ac`, etc.) were confirmed to
   contain rendered control text, but were not needed: the OSCAL profile +
   NIST catalog already give titles, statements, guidance and parameters.
   They remain a fallback if a control's text looks wrong.
4. **Registration flow, payout method, Discord invite** — not attempted in
   this prep round (human-only / sprint-time steps). The sprint plan lists
   them as open items.

## GitHub

- `gh` CLI is authenticated as **emagaul135** (token scopes: gist,
  read:org, repo).
- Repo created: **https://github.com/emagaul135/apart-threat-intelligence-2026**
  (public, MIT), scaffold pushed on 2026-11-19.

## What sprint Day-1 morning must confirm first

1. Fetch the official report template (Google Docs) and confirm its
   page/section structure — without it, the report cannot be formatted.
2. Re-run both extraction scripts and confirm the counts are still 60 / 38
   (in case the live Standard or the RAND page changed).
3. Confirm the SL5/RAND data loads end-to-end into the mapping runner's
   input format (60 controls + 38 vectors, each with source citation).
4. If extraction fails on Day 1 → switch to Backup 1 ("A profile with
   receipts", Salt Typhoon) by Fri 4 Dec ~12:00 WIB (see sprint plan §3).
5. Register for the sprint + join Discord (human step if it needs the
   user's own accounts).
