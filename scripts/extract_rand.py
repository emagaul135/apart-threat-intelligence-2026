#!/usr/bin/env python3
"""Extract RAND's attack vectors against AI model weights into a structured CSV.

PREEXISTING work (written before the sprint weekend, 4-6 Dec 2026).
Source (public, downloaded 2026-11-19):
  - data/raw/rand-securing-ai-model-weights-RRA2849-1.pdf
      Nevo, Lahav, Karpur, Bar-On, Bradley & Alstott, "Securing AI Model Weights:
      Preventing Theft and Misuse of Frontier Models", RAND Corporation,
      RR-A2849-1, May 2024 (revised June 2024). DOI 10.7249/RRA2849-1.
      https://www.rand.org/pubs/research_reports/RRA2849-1.html
  - data/raw/rand-report.txt
      Plain-text dump produced with: pdftotext -layout <pdf> rand-report.txt

Method:
  The authoritative enumeration is Table 5.1 ("Summary of Attack Vectors",
  Chapter 5, p. 12): nine categories, each with a bullet list of vectors.
  This script parses that table (category anchors + bullet items), then
  cross-checks every vector against its Appendix A subsection heading and
  takes the first sentence of that subsection as the description.
  Expected result: exactly 38 vectors (4+4+4+3+5+3+7+3+5 across the nine
  categories). Anything else is reported as a failure, not silently fixed.

Output: data/raw/rand-vectors.csv (and a copy at data/rand-vectors.csv)
Columns: id, category, name, description, source

Usage: python3 scripts/extract_rand.py [--root .]
Requires only the Python standard library plus the `pdftotext` command-line
tool (poppler-utils) to regenerate rand-report.txt if it is missing.
"""

import argparse
import csv
import re
import subprocess
import sys
from pathlib import Path

CATEGORIES = [
    "Running Unauthorized Code",
    "Compromising Existing Credentials",
    "Undermining the Access Control System Itself",
    "Bypassing Primary Security System Altogether",
    "AI-Specific Attack Vectors",
    "Nontrivial Access to Data or Networks",
    "Unauthorized Physical Access to Systems",
    "Supply Chain Attacks",
    "Human Intelligence",
]

EXPECTED_COUNTS = {
    "Running Unauthorized Code": 4,
    "Compromising Existing Credentials": 4,
    "Undermining the Access Control System Itself": 4,
    "Bypassing Primary Security System Altogether": 3,
    "AI-Specific Attack Vectors": 5,
    "Nontrivial Access to Data or Networks": 3,
    "Unauthorized Physical Access to Systems": 7,
    "Supply Chain Attacks": 3,
    "Human Intelligence": 5,
}

SOURCE = ("Nevo et al. 2024, RAND RR-A2849-1, Table 5.1 (p. 12) / Appendix A")


def clean(text):
    """De-hyphenate line wraps, collapse whitespace, strip footnote markers."""
    text = re.sub(r"-\n\s*", "", text)          # hyphenated line breaks
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s+([,.;:])", r"\1", text)
    return text.strip(" \t\n\r•")


def norm(text):
    return re.sub(r"\s+", " ", text.lower()).strip()


def parse_table_51(text):
    """Return {category: [vector names]} parsed from Table 5.1.

    pdftotext -layout renders the table as two columns: the category name in
    the left column (cols 0-41, wrapped across lines) and the bullet list in
    the right column (bullets start at col 42 with '•', wrapped across lines).
    The first bullet of a category shares a line with the category heading's
    FIRST fragment, so assignment is two-pass: first locate every heading's
    first-fragment line, then assign each bullet to the latest heading at or
    before its line.
    """
    start = text.find("TABLE 5.1")
    if start < 0:
        raise ValueError("TABLE 5.1 marker not found in text")
    end = text.find("a Zero-days are vulnerabilities", start)
    if end < 0:
        end = text.find("Key Conclusions About the Attack Vector Landscape", start)
    lines = text[start:end].splitlines()

    # Pass 1: heading lines. A heading may wrap over two left-column lines;
    # record the line of its FIRST fragment.
    headings = []  # (line_no, category)
    cat_buf = ""
    buf_start = None
    for i, raw_line in enumerate(lines):
        left = raw_line[:42].strip()
        if not left:
            continue
        candidate = (cat_buf + " " + left).strip() if cat_buf else left
        if candidate in CATEGORIES:
            headings.append((buf_start if buf_start is not None else i,
                             candidate))
            cat_buf, buf_start = "", None
        elif any(c.startswith(candidate) for c in CATEGORIES):
            if buf_start is None:
                buf_start = i
            cat_buf = candidate
        else:
            cat_buf, buf_start = "", None

    # Pass 2: bullets -> latest heading at or before the bullet's line.
    result = {cat: [] for cat in CATEGORIES}
    current_cat = None
    current_vec = None

    def flush_vec():
        nonlocal current_vec
        if current_vec is not None and current_cat is not None:
            name = clean(current_vec)
            # Table footnote marker 'a' attaches to the last word
            # ("zero-daysa" -> "zero-days").
            name = re.sub(r"zero-daysa$", "zero-days", name)
            result[current_cat].append(name)
        current_vec = None

    for i, raw_line in enumerate(lines):
        right = raw_line[42:].strip()
        if not right:
            continue
        if right.startswith("•"):
            flush_vec()
            # Latest heading whose first-fragment line is <= this line.
            cat = None
            for hline, hcat in headings:
                if hline <= i:
                    cat = hcat
                else:
                    break
            current_cat = cat
            current_vec = right[1:].strip()
        elif current_vec is not None:
            current_vec += " " + right
    flush_vec()
    return result


def _prefix_regex(name, cut):
    """Regex matching the first `cut` chars of `name` at a line start,
    tolerating line wraps. Appendix A subsection headings sit alone on
    their own line(s), so the match is anchored to a line start."""
    frag = name[:cut]
    parts = re.split(r"\s+", frag.strip())
    return re.compile(r"(?m)^[ \t]*" +
                       r"\s*".join(re.escape(p) for p in parts if p),
                       flags=re.IGNORECASE)


def first_sentence_after_heading(appendix_text, vector_name):
    """Find the vector's Appendix A subsection and return its first sentence.

    Returns (sentence, matched_heading) or ("", None) if not found.
    Two vectors in Table 5.1 have no dedicated Appendix A subsection
    ('Intentional ML supply chain compromise', 'Model distillation') — they
    are only mentioned in passing elsewhere, so they return "" honestly.
    """
    target = norm(vector_name)
    # Try progressively shorter prefixes of the name (headings wrap / differ
    # slightly in punctuation, e.g. trailing parentheticals).
    for cut in (45, 35, 25):
        key = target[:cut]
        if norm(appendix_text).find(key) < 0:
            continue
        m = _prefix_regex(vector_name, cut).search(appendix_text)
        if not m:
            continue
        rest = appendix_text[m.end():]
        body_lines = rest.splitlines()
        # Drop the remainder of the heading line itself (empty, or the tail
        # of a wrapped heading such as "Software)" / "attacks)").
        if body_lines:
            body_lines = body_lines[1:]
        # Drop any further short heading-continuation lines (end with ')',
        # no sentence-ending period outside "i.e."/"e.g.").
        while body_lines:
            line = body_lines[0].strip()
            probe = line.replace("i.e.", "").replace("e.g.", "")
            if line and len(line) < 60 and line.endswith(")") and "." not in probe:
                body_lines = body_lines[1:]
            else:
                break
        body = clean(" ".join(body_lines))
        if not body:
            continue
        sent = re.split(r"(?<=[.!?])\s+", body, maxsplit=1)[0]
        if len(sent) > 40:
            return sent[:600], vector_name[:cut]
    return "", None


def main():
    ap = argparse.ArgumentParser(description="Extract RAND's 38 attack vectors.")
    ap.add_argument("--root", default=".", help="Repo root (default: current dir).")
    args = ap.parse_args()
    root = Path(args.root)
    raw = root / "data" / "raw"

    txt = raw / "rand-report.txt"
    pdf = raw / "rand-securing-ai-model-weights-RRA2849-1.pdf"
    if not txt.exists():
        if not pdf.exists():
            print(f"ERROR: neither {txt} nor {pdf} exists.", file=sys.stderr)
            sys.exit(1)
        subprocess.run(["pdftotext", "-layout", str(pdf), str(txt)], check=True)
    text = txt.read_text(encoding="utf-8", errors="replace")

    table = parse_table_51(text)
    total = sum(len(v) for v in table.values())
    print(f"Table 5.1 vectors parsed: {total} (expected 38)")
    for cat in CATEGORIES:
        got = len(table[cat])
        exp = EXPECTED_COUNTS[cat]
        flag = "" if got == exp else f"  <-- MISMATCH (expected {exp})"
        print(f"  {cat}: {got}{flag}")
    if total != 38:
        print("ERROR: vector count is not 38; refusing to write output.",
              file=sys.stderr)
        sys.exit(1)

    appendix_start = text.find("APPENDIX A")
    appendix_text = text[appendix_start:] if appendix_start >= 0 else ""

    rows = []
    unmatched = []
    n = 0
    for cat in CATEGORIES:
        for name in table[cat]:
            n += 1
            desc, _ = first_sentence_after_heading(appendix_text, name)
            if not desc:
                unmatched.append(name)
            rows.append({
                "id": f"V{n:02d}",
                "category": cat,
                "name": name,
                "description": desc,
                "source": SOURCE,
            })

    out_paths = [raw / "rand-vectors.csv", root / "data" / "rand-vectors.csv"]
    for out in out_paths:
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    print(f"Vectors with an Appendix A description: "
          f"{sum(1 for r in rows if r['description'])}/{len(rows)}")
    if unmatched:
        print(f"WARNING: no Appendix A subsection matched for: {unmatched}")
    print(f"Wrote: {', '.join(str(p) for p in out_paths)}")


if __name__ == "__main__":
    main()
