#!/usr/bin/env python3
import argparse
import json
import re
import sys
from typing import List, Tuple, Optional

CPF_REGEX = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
SSN_REGEX = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

def cpf_digits(s: str) -> Optional[str]:
    d = re.sub(r"\D", "", s)
    if len(d) != 11:
        return None
    if d == d[0] * 11:
        return None
    return d

def cpf_valid(d: str) -> bool:
    def calc(slice_digits: str, factor_start: int) -> int:
        total = 0
        factor = factor_start
        for ch in slice_digits:
            total += int(ch) * factor
            factor -= 1
        r = (total * 10) % 11
        return 0 if r == 10 else r

    c1 = calc(d[:9], 10)
    c2 = calc(d[:10], 11)
    return (c1 == int(d[9])) and (c2 == int(d[10]))

def merge_spans(spans: List[Tuple[int,int]]) -> List[Tuple[int,int]]:
    if not spans:
        return []
    spans.sort(key=lambda x: (x[0], x[1]))
    out = [spans[0]]
    for s,e in spans[1:]:
        ls, le = out[-1]
        if s <= le:
            out[-1] = (ls, max(le, e))
        else:
            out.append((s,e))
    return out

def find_builtin(text: str) -> List[Tuple[int,int]]:
    spans: List[Tuple[int,int]] = []
    for m in CPF_REGEX.finditer(text):
        d = cpf_digits(m.group(0))
        if d and cpf_valid(d):
            spans.append((m.start(), m.end()))
    for m in SSN_REGEX.finditer(text):
        spans.append((m.start(), m.end()))
    return merge_spans(spans)

def find_custom(text: str, pat: str) -> List[Tuple[int,int]]:
    try:
        rx = re.compile(pat)
    except re.error as e:
        print(f"[py] bad custom regex: {e}", file=sys.stderr)
        return []
    spans = [(m.start(), m.end()) for m in rx.finditer(text) if m.start() != m.end()]
    return merge_spans(spans)

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--custom-regex", default="", help="If non-empty, ONLY this regex is used; CPF/SSN are skipped.")
    args = ap.parse_args()

    try:
        text = open(args.infile, "r", encoding="utf-8", errors="ignore").read()
    except Exception as e:
        print(f"[py] read failed: {e}", file=sys.stderr)
        print(json.dumps({"score": 0.0, "threshold": float(args.threshold), "spans": []}))
        return 0

    if args.custom_regex:
        spans = find_custom(text, args.custom_regex)
        mode = "custom_regex"
    else:
        spans = find_builtin(text)
        mode = "builtin_cpf_ssn"

    score = 1.0 if spans else 0.0
    out = {
        "score": float(score),
        "threshold": float(args.threshold),
        "spans": [[int(s), int(e)] for (s,e) in spans],
        "mode": mode,
    }
    print(json.dumps(out, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

