#!/usr/bin/env python3
import argparse
import os
import sys

DEFAULT_MODEL = "sadjava/multilingual-hate-speech-xlm-roberta"

def pick_label_score(scores, prefer=None):
    if not scores:
        return 0.0
    if prefer:
        for e in scores:
            if str(e.get("label", "")).lower() == prefer.lower():
                return float(e.get("score", 0.0))
    best = max(scores, key=lambda x: float(x.get("score", 0.0)))
    return float(best.get("score", 0.0))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--prefer-label", default=None) 
    ap.add_argument("--max-length", type=int, default=256)
    args = ap.parse_args()

    try:
        text = open(args.infile, "r", encoding="utf-8", errors="ignore").read().strip()
    except Exception as e:
        print(f"[py] read failed: {e}", file=sys.stderr)
        print("0.0")
        return 0

    if not text:
        print("0.0")
        return 0

    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

    try:
        from transformers import pipeline
        from transformers.utils import logging as hf_logging
        hf_logging.set_verbosity_error()
    except Exception as e:
        print(f"[py] transformers import failed: {e}", file=sys.stderr)
        print("0.0")
        return 0

    try:
        clf = pipeline(
            "text-classification",
            model=args.model,
            tokenizer=args.model,
            top_k=None,
            truncation=True,
            max_length=args.max_length,
            device=-1,
        )

        out = clf(text)
        if isinstance(out, list) and out and isinstance(out[0], list):
            scores = out[0]
        elif isinstance(out, list):
            scores = out
        else:
            scores = []

        score = pick_label_score(scores, prefer=args.prefer_label)
        print(f"{float(score):.6f}")
        return 0

    except Exception as e:
        print(f"[py] inference failed: {e}", file=sys.stderr)
        print("0.0")
        return 0

if __name__ == "__main__":
    raise SystemExit(main())

