"""Evaluation harness for the Threat Hunting Agent (answers RQ2).

This is a DIFFERENT kind of test from test_threat_agent.py:
  - test_threat_agent.py checks the agent behaves correctly on a handful
    of hand-picked cases (unit-level correctness).
  - This script checks how ACCURATE the agent's TTP mapping is across a
    labeled dataset (aggregate performance — the actual RQ2 number).

Usage:
    python eval_threat_agent.py                  # uses the bundled synthetic set
    python eval_threat_agent.py --data my.jsonl   # uses your own labeled data

Expected JSONL format, one example per line:
    {
      "packet_features": {...},
      "ml_prediction": {"attack_probability": 0.87, "predicted_class": "Infiltration"},
      "true_ttp_id": "T1021.002"
    }

IMPORTANT: the synthetic dataset below is for smoke-testing the harness
itself, not a substitute for real evaluation data. Swap it out for
labeled samples from CICIDS2017 / UNSW-NB15 / CICIoT2023 / NetDefend-Bench
before reporting any number in the paper — see the note at the bottom of
this file for how to build that labeled set.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
)

from agents.threat_agent import run_threat_agent


# ---------------------------------------------------------------------------
# Bundled synthetic dataset — smoke-tests the harness, not a real benchmark.
# Field names match the REAL Packet Analysis / Intrusion Detection Agent
# contracts: single-flow features, CICIDS2017 label strings for
# predicted_class.
# ---------------------------------------------------------------------------

SYNTHETIC_DATASET = [
    {
        "packet_features": {
            "packet_count": 180, "byte_count": 21000, "duration_s": 4.2,
            "packets_per_sec": 42.8, "bytes_per_sec": 5000.0,
            "mean_inter_arrival": 0.02, "std_inter_arrival": 0.01,
            "syn_count": 40, "synack_count": 3, "rst_count": 2,
            "ssh_auth_attempts": 0, "protocol": "6", "top_dst_port": 445,
        },
        "ml_prediction": {"attack_probability": 0.87, "predicted_class": "Infiltration",
                           "anomaly_score": -0.12},
        "true_ttp_id": "T1021.002",
    },
    {
        "packet_features": {
            "packet_count": 300, "byte_count": 15000, "duration_s": 3.0,
            "packets_per_sec": 100.0, "bytes_per_sec": 5000.0,
            "mean_inter_arrival": 0.01, "std_inter_arrival": 0.005,
            "syn_count": 60, "synack_count": 2, "rst_count": 40,
            "ssh_auth_attempts": 0, "protocol": "6", "top_dst_port": 80,
        },
        "ml_prediction": {"attack_probability": 0.92, "predicted_class": "PortScan",
                           "anomaly_score": -0.2},
        "true_ttp_id": "T1046",
    },
    {
        "packet_features": {
            "packet_count": 50000, "byte_count": 9_000_000, "duration_s": 5.0,
            "packets_per_sec": 10000.0, "bytes_per_sec": 1_800_000.0,
            "mean_inter_arrival": 0.0001, "std_inter_arrival": 0.00005,
            "syn_count": 500, "synack_count": 0, "rst_count": 0,
            "ssh_auth_attempts": 0, "protocol": "17", "top_dst_port": 80,
        },
        "ml_prediction": {"attack_probability": 0.95, "predicted_class": "DDoS",
                           "anomaly_score": -0.3},
        "true_ttp_id": "T1498",
    },
    {
        "packet_features": {
            "packet_count": 60, "byte_count": 9000, "duration_s": 12.0,
            "packets_per_sec": 5.0, "bytes_per_sec": 750.0,
            "mean_inter_arrival": 0.2, "std_inter_arrival": 0.05,
            "syn_count": 8, "synack_count": 6, "rst_count": 1,
            "ssh_auth_attempts": 12, "protocol": "6", "top_dst_port": 22,
        },
        "ml_prediction": {"attack_probability": 0.81, "predicted_class": "SSH-Patator",
                           "anomaly_score": -0.1},
        "true_ttp_id": "T1110",
    },
    {
        "packet_features": {
            "packet_count": 25, "byte_count": 4000, "duration_s": 2.0,
            "packets_per_sec": 12.5, "bytes_per_sec": 2000.0,
            "mean_inter_arrival": 0.08, "std_inter_arrival": 0.02,
            "syn_count": 3, "synack_count": 3, "rst_count": 0,
            "ssh_auth_attempts": 0, "protocol": "6", "top_dst_port": 80,
        },
        "ml_prediction": {"attack_probability": 0.7, "predicted_class": "Web Attack - Brute Force",
                           "anomaly_score": -0.08},
        "true_ttp_id": "T1190",
    },
    {
        # Deliberately ambiguous case with no class hit and weak features —
        # expected to fall through to the LLM (or fallback_default without
        # an LLM configured), likely producing a wrong/low-confidence answer.
        # Included so the harness reports realistic accuracy, not 100%.
        "packet_features": {
            "packet_count": 5, "byte_count": 400, "duration_s": 1.0,
            "packets_per_sec": 5.0, "bytes_per_sec": 400.0,
            "mean_inter_arrival": 0.2, "std_inter_arrival": 0.05,
            "syn_count": 1, "synack_count": 1, "rst_count": 0,
            "ssh_auth_attempts": 0, "protocol": "6", "top_dst_port": 8080,
        },
        "ml_prediction": {"attack_probability": 0.51, "predicted_class": "Unknown",
                           "anomaly_score": None},
        "true_ttp_id": "T1071.001",
    },
]


def load_dataset(path: str | None) -> list[dict]:
    if path is None:
        return SYNTHETIC_DATASET
    examples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                examples.append(json.loads(line))
    return examples


def run_eval(dataset: list[dict]) -> None:
    y_true, y_pred, methods, confidences = [], [], [], []

    for example in dataset:
        state = {
            "packet_features": example.get("packet_features", {}),
            "ml_prediction": example.get("ml_prediction", {}),
        }
        result = run_threat_agent(state)

        y_true.append(example["true_ttp_id"])
        y_pred.append(result["ttp_id"])
        confidences.append(result["ttp_confidence"])
        # mapping_method isn't in the state contract (only ttp_id/ttp_confidence
        # are), so we re-derive it here for reporting purposes only.
        from knowledge.mitre.lookup import lookup_ttp
        match = lookup_ttp(example.get("ml_prediction", {}), example.get("packet_features", {}))
        methods.append(match["mapping_method"] if match else "llm_or_fallback")

    print(f"\n{'='*60}\nThreat Hunting Agent — TTP Mapping Evaluation\n{'='*60}")
    print(f"Examples: {len(dataset)}\n")

    # --- Overall metrics ---------------------------------------------------
    acc = accuracy_score(y_true, y_pred)
    labels = sorted(set(y_true) | set(y_pred))
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="macro", zero_division=0
    )

    print(f"Accuracy:            {acc:.3f}")
    print(f"Macro precision:     {precision:.3f}")
    print(f"Macro recall:        {recall:.3f}")
    print(f"Macro F1:            {f1:.3f}")
    print(f"Mean ttp_confidence: {sum(confidences)/len(confidences):.3f}\n")

    # --- Per-mapping-method breakdown --------------------------------------
    # This tells you how much the (expensive, less-tested) LLM fallback
    # path is actually being relied on vs. the deterministic table.
    by_method = defaultdict(lambda: {"correct": 0, "total": 0})
    for t, p, m in zip(y_true, y_pred, methods):
        by_method[m]["total"] += 1
        if t == p:
            by_method[m]["correct"] += 1

    print("By mapping method:")
    for method, stats in sorted(by_method.items()):
        acc_m = stats["correct"] / stats["total"] if stats["total"] else 0.0
        print(f"  {method:20s} n={stats['total']:3d}  accuracy={acc_m:.3f}")

    # --- Confusion matrix ----------------------------------------------------
    print(f"\nConfusion matrix (labels={labels}):")
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    header = "        " + " ".join(f"{l:>12s}" for l in labels)
    print(header)
    for label, row in zip(labels, cm):
        print(f"{label:>8s} " + " ".join(f"{v:12d}" for v in row))

    # --- Misclassified examples, for error analysis -------------------------
    print("\nMisclassified examples:")
    any_wrong = False
    for example, pred, method in zip(dataset, y_pred, methods):
        if example["true_ttp_id"] != pred:
            any_wrong = True
            print(f"  true={example['true_ttp_id']}  pred={pred}  method={method}  "
                  f"input={example.get('ml_prediction')}")
    if not any_wrong:
        print("  (none)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=str, default=None,
                         help="Path to a JSONL labeled dataset. Uses bundled synthetic data if omitted.")
    args = parser.parse_args()

    dataset = load_dataset(args.data)
    run_eval(dataset)


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# Note on building a REAL labeled set for this harness
# ---------------------------------------------------------------------------
# CICIDS2017 / UNSW-NB15 / CICIoT2023 ship attack-type labels (e.g.
# "PortScan", "Infiltration", "DDoS") but NOT MITRE ATT&CK TTP labels —
# you have to add those yourself. Practical approach:
#   1. Sample N rows per attack class from your dataset(s).
#   2. Extract/compute packet_features for each (from your Packet Analysis
#      Agent) and run each through your trained ML model for ml_prediction.
#   3. Hand-assign true_ttp_id per class using MITRE's own dataset-to-ATT&CK
#      mapping guidance (or your team's literature review) — this becomes
#      your ground truth, done once per class, not per row.
#   4. Export as JSONL in the schema above and point --data at it.
# This is manual/semi-manual work; nothing here can substitute for the
# human judgment call of "which TTP does this label really represent."