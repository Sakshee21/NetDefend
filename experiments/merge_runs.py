#!/usr/bin/env python3
"""Merge several runs.csv files (and their transcripts) from different machines.

runs.csv: drops duplicate (scenario_id, run_idx, condition) rows (first wins) and
FAILS LOUDLY if model_name differs between files -- results produced with a
different model must not be pooled.

transcripts.jsonl: concatenated and deduped by (scenario_id, run_idx); FAILS
LOUDLY if the same (scenario_id, run_idx) appears with conflicting records.
Transcript files are taken from --transcripts, or (if omitted) derived from each
runs input by swapping 'runs'->'transcripts' and '.csv'->'.jsonl'.

    python experiments/merge_runs.py experiments/results/runs_*.csv -o experiments/results/runs.csv
    python experiments/merge_runs.py a/runs.csv b/runs.csv -o out/runs.csv \
        --transcripts a/transcripts.jsonl b/transcripts.jsonl \
        --out-transcripts out/transcripts.jsonl
"""
import argparse
import csv
import json
import sys
from pathlib import Path


def _merge_runs(inputs, out):
    fieldnames = None
    models = {}
    seen = set()
    merged = []
    for path in inputs:
        p = Path(path)
        if not p.exists():
            sys.exit(f"input not found: {p}")
        with open(p, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if fieldnames is None:
                fieldnames = reader.fieldnames
            for r in reader:
                models.setdefault(r.get("model_name", ""), set()).add(str(p))
                key = (r["scenario_id"], r["run_idx"], r["condition"])
                if key in seen:
                    continue
                seen.add(key)
                merged.append(r)

    distinct = {m for m in models if m}
    if len(distinct) > 1:
        detail = "\n".join(f"  {m}: {sorted(models[m])}" for m in distinct)
        sys.exit("REFUSING TO MERGE: model_name differs between files.\n" + detail)

    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(merged)
    print(f"runs: merged {len(inputs)} file(s) -> {out}  "
          f"({len(merged)} unique rows; model_name="
          f"{distinct.pop() if distinct else '(none)'})")


def _derive_transcripts(inputs):
    found = []
    for path in inputs:
        cand = Path(str(path).replace("runs", "transcripts"))
        cand = cand.with_suffix(".jsonl")
        if cand.exists():
            found.append(str(cand))
    return found


def _merge_transcripts(files, out):
    if not files:
        print("transcripts: no transcript files found/given; skipping.")
        return
    records = {}
    for path in files:
        p = Path(path)
        if not p.exists():
            sys.exit(f"transcript not found: {p}")
        with open(p, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError as exc:
                    sys.exit(f"bad JSON in {p}:{lineno}: {exc}")
                key = (rec.get("scenario_id"), rec.get("run_idx"))
                canon = json.dumps(rec, sort_keys=True, default=str)
                if key in records:
                    if records[key][0] != canon:
                        sys.exit(
                            f"CONFLICTING TRANSCRIPTS for {key}:\n"
                            f"  first from {records[key][1]}\n  differs in {p}\n"
                            f"Refusing to merge conflicting records.")
                    continue
                records[key] = (canon, str(p))

    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for canon, _src in records.values():
            f.write(canon + "\n")
    print(f"transcripts: merged {len(files)} file(s) -> {out}  "
          f"({len(records)} unique (scenario, run) records)")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", help="runs.csv files to merge")
    ap.add_argument("-o", "--out", required=True, help="output runs.csv path")
    ap.add_argument("--transcripts", nargs="*", default=None,
                    help="transcript jsonl files (default: derived from runs inputs)")
    ap.add_argument("--out-transcripts", default=None,
                    help="output transcripts path (default: derived from --out)")
    args = ap.parse_args()

    _merge_runs(args.inputs, args.out)

    tfiles = args.transcripts if args.transcripts is not None else _derive_transcripts(args.inputs)
    out_t = args.out_transcripts or str(Path(str(args.out).replace("runs", "transcripts")).with_suffix(".jsonl"))
    _merge_transcripts(tfiles, out_t)


if __name__ == "__main__":
    main()
