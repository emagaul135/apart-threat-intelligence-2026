#!/usr/bin/env python3
"""Extract the SL5 Standard's 60 controls into a structured CSV.

PREEXISTING work (written before the sprint weekend, 4-6 Dec 2026).
Sources (all public, downloaded 2026-11-19):
  - data/raw/sl5-profile.json
      SL5 Standard OSCAL profile v0.1.3, https://standard.sl5.org/sl5-profile.json
      This is the AUTHORITATIVE enumeration of the 60 controls: its imports list
      59 controls from NIST SP 800-53 Rev. 5 plus SR-13 from NIST SP 800-161.
      Its `modify.alters` carry the SL5 supplemental guidance per control and
      `modify.set-parameters` carry SL5 parameter assignments.
  - data/raw/NIST_SP-800-53_rev5_catalog.json
      NIST SP 800-53 Rev. 5.2.0 OSCAL catalog (the exact file the profile imports),
      https://raw.githubusercontent.com/usnistgov/oscal-content/78650f02ad9321bb7b817846f8fbd4f2bcd620de/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
      Gives each control's title and NIST statement text.
  - data/raw/sl5-sr13-catalog.json
      Local OSCAL catalog for SR-13 (SP 800-161), https://standard.sl5.org/catalogs/NIST_SP-800-161r1-upd1_sr-13_catalog.json

Why the OSCAL profile and not the arXiv paper: the arXiv paper (Thiergart et al.
2026, arXiv:2605.08449, May 2026) is an older snapshot. Its section 3 lists only
42 control headings and has no Incident Response (IR) or Risk Assessment (RA)
families. The live Standard (updated 13 Nov 2026) has 60 controls across 12
families; the OSCAL profile v0.1.3 is its machine-readable form and enumerates
exactly 60 unique control IDs.

Output: data/raw/sl5-controls.csv (and a copy at data/sl5-controls.csv)
Columns: id, family, title, nist_statement, sl5_guidance, sl5_parameters, source

Usage: python3 scripts/extract_sl5.py [--root .]
Requires only the Python standard library.
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def statement_prose(control):
    """Join the 'statement' part prose of an OSCAL control (base or enhancement).

    OSCAL parameter-insertion markers such as
    "{{ insert: param, ac-02_odp.01 }}" are rendered as "[param: ac-02_odp.01]"
    so the text reads cleanly; the parameter id is preserved.
    """
    out = []
    for part in control.get("parts", []) or []:
        if part.get("name") == "statement":
            prose = part.get("prose", "")
            if prose:
                out.append(prose)
            for sub in part.get("parts", []) or []:
                if sub.get("prose"):
                    out.append(sub["prose"])
    text = " ".join(out)
    text = re.sub(r"\{\{\s*insert:\s*param,\s*([^}]+?)\s*\}\}", r"[param: \1]", text)
    return text


def walk_catalog_controls(controls, family, index):
    for c in controls or []:
        cid = c.get("id", "").lower()
        if cid:
            index[cid] = {
                "family": family,
                "title": c.get("title", ""),
                "statement": re.sub(r"\s+", " ", statement_prose(c)).strip(),
            }
        walk_catalog_controls(c.get("controls", []), family, index)


def build_catalog_index(catalog):
    """id -> {family, title, statement} for every control/enhancement."""
    index = {}
    for group in catalog.get("groups", []) or []:
        fam = (group.get("id") or "").lower()
        walk_catalog_controls(group.get("controls", []), fam, index)
        for subgroup in group.get("groups", []) or []:
            sfam = (subgroup.get("id") or fam).lower()
            walk_catalog_controls(subgroup.get("controls", []), sfam, index)
    for c in catalog.get("controls", []) or []:
        walk_catalog_controls([c], "", index)
    return index


def param_to_control(param_id):
    """Map an OSCAL set-parameter id like 'ac-04_odp' or 'sc-07.10_odp' to a control id.

    Returns the dotted/lowercase control id, or None if it cannot be mapped.
    """
    base = param_id.split("_")[0].lower()
    m = re.match(r"^([a-z]{2})-0*(\d+)(?:\.0*(\d+))?$", base)
    if not m:
        return None
    cid = f"{m.group(1)}-{m.group(2)}"
    if m.group(3):
        cid += f".{m.group(3)}"
    return cid


def main():
    ap = argparse.ArgumentParser(description="Extract the 60 SL5 controls to CSV.")
    ap.add_argument("--root", default=".", help="Repo root (default: current dir).")
    args = ap.parse_args()
    root = Path(args.root)
    raw = root / "data" / "raw"

    profile = load_json(raw / "sl5-profile.json")["profile"]
    nist_catalog = load_json(raw / "NIST_SP-800-53_rev5_catalog.json")["catalog"]
    sr13_catalog = load_json(raw / "sl5-sr13-catalog.json")["catalog"]

    # 1. Authoritative ordered list of 60 control ids from the profile imports.
    ordered_ids = []
    for imp in profile.get("imports", []) or []:
        for inc in imp.get("include-controls", []) or []:
            ordered_ids.extend(i.lower() for i in inc.get("with-ids", []) or [])
    if len(ordered_ids) != 60 or len(set(ordered_ids)) != 60:
        print(f"ERROR: profile imports {len(ordered_ids)} ids "
              f"({len(set(ordered_ids))} unique), expected exactly 60 unique.",
              file=sys.stderr)
        sys.exit(1)

    # 2. Title + NIST statement text from the catalogs.
    index = build_catalog_index(nist_catalog)
    index.update(build_catalog_index(sr13_catalog))
    # The SR-13 local catalog groups its control under a "sr-161" group id;
    # the control belongs to the SR family.
    if "sr-13" in index:
        index["sr-13"]["family"] = "sr"
    missing = [cid for cid in ordered_ids if cid not in index]
    if missing:
        print(f"ERROR: {len(missing)} profile ids not found in catalogs: {missing}",
              file=sys.stderr)
        sys.exit(1)

    # 3. SL5 supplemental guidance (alters) and parameter values (set-parameters).
    guidance = {}
    for alter in profile.get("modify", {}).get("alters", []) or []:
        cid = (alter.get("control-id") or "").lower()
        prose_bits = []
        for add in alter.get("adds", []) or []:
            for part in add.get("parts", []) or []:
                if part.get("prose"):
                    prose_bits.append(part["prose"])
        if prose_bits:
            guidance[cid] = re.sub(r"\s+", " ", " ".join(prose_bits)).strip()

    parameters = {}
    unmapped_params = []
    for sp in profile.get("modify", {}).get("set-parameters", []) or []:
        cid = param_to_control(sp.get("param-id", ""))
        vals = sp.get("values", []) or []
        if cid is None:
            unmapped_params.append(sp.get("param-id"))
            continue
        parameters.setdefault(cid, []).extend(vals)

    # 4. Write the CSV.
    rows = []
    for cid in ordered_ids:
        entry = index[cid]
        rows.append({
            "id": cid,
            "family": entry["family"].upper(),
            "title": entry["title"],
            "nist_statement": entry["statement"],
            "sl5_guidance": guidance.get(cid, ""),
            "sl5_parameters": " | ".join(parameters.get(cid, [])),
            "source": "SL5 Standard v0.1.3 OSCAL profile (standard.sl5.org/sl5-profile.json); "
                      "NIST SP 800-53 Rev. 5.2.0 OSCAL catalog"
                      + ("; NIST SP 800-161 Rev. 1 Upd. 1 SR-13 catalog" if cid == "sr-13" else ""),
        })

    out_paths = [raw / "sl5-controls.csv", root / "data" / "sl5-controls.csv"]
    for out in out_paths:
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    # 5. Verification summary.
    fams = {}
    for r in rows:
        fams[r["family"]] = fams.get(r["family"], 0) + 1
    print(f"SL5 controls extracted: {len(rows)} (expected 60)")
    print(f"Families ({len(fams)}): {dict(sorted(fams.items()))}")
    print(f"With SL5 supplemental guidance: {sum(1 for r in rows if r['sl5_guidance'])}")
    print(f"With SL5 parameter values: {sum(1 for r in rows if r['sl5_parameters'])}")
    print(f"Unmapped set-parameters: {unmapped_params or 'none'}")
    print(f"Wrote: {', '.join(str(p) for p in out_paths)}")


if __name__ == "__main__":
    main()
