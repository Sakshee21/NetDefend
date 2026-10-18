# NetDefend-Bench evaluation summary

Scenarios (valid): 19 (ATTACK=10, MISCONFIGURATION=9).

## Verdict distribution per condition (sanity)
- C1 (n=19): {'MISCONFIGURATION': 19}
- C2 (n=19): {'ATTACK': 19}
- C3 (n=19): {'ATTACK': 12, 'MISCONFIGURATION': 7}
- C4 (n=19): {'ATTACK': 8, 'MISCONFIGURATION': 11}

## Headline (run-level)
- C1: disambiguation=0.474, FPR=0.000, escalation=0.000, recall=0.000, precision=nan, F1=nan
- C2: disambiguation=0.526, FPR=1.000, escalation=0.000, recall=1.000, precision=0.526, F1=0.690
- C3: disambiguation=0.789, FPR=0.333, escalation=0.000, recall=0.900, precision=0.750, F1=0.818
- C4: disambiguation=0.684, FPR=0.222, escalation=0.000, recall=0.600, precision=0.750, F1=0.667

## C1 threshold-free supplement
C1 scenario-level ROC-AUC of attack_probability (ATTACK vs MISCONFIG) = 0.900 [95% CI 0.667, 1.000]. THRESHOLD-FREE separability, NOT a decision rule; the headline C1 row uses threshold 0.5.

## ATT&CK mapping
table_ttp.csv over the MAPPED subset only: 7/10 attack scenarios have a technique (7 mapped runs); technique accuracy (runs) = 0.571. Null-technique attacks excluded, not counted wrong.

## WARNINGS
- Condition C1 predicted a SINGLE verdict (MISCONFIGURATION) for the whole benchmark.
- Condition C2 predicted a SINGLE verdict (ATTACK) for the whole benchmark.

## Method notes
- Positive class = ATTACK; MISCONFIGURATION and UNCERTAIN both count as not-attack. A run with llm_failed=True is excluded for all conditions (paired).
- CIs: 95% percentile, scenario-cluster bootstrap, 10000 draws, seed 1234. Paired C4-vs-Cx diffs use the same draws.
- Significance: exact McNemar on SCENARIO-level correctness (majority verdict, tie->UNCERTAIN), Holm across the 3 comparisons.
- PAPER DIVERGENCE: paper/netdefend.tex §Evaluation specifies per-RUN McNemar and 2000 bootstrap resamples, and leaves the C3 fusion rule as a TODO. This harness uses scenario-level McNemar, 10,000 draws, and the fusion rule 'higher prior confidence wins, tie->ATTACK'. Update the paper text to match.

## Figures
(none)

## Supplementary condition: C3+gate (fusion after the bundle-based null gate)

C3+gate applies the same fusion rule as C3 (higher prior confidence wins, tie -> ATTACK) but first applies the bundle-based null gate: if the misconfiguration side is null (the evidence bundle holds no configuration artifact) the verdict is ATTACK. Computed from cached upstream outputs only, no LLM calls.

- scenarios null-gated (-> ATTACK): 10 of 19
- disambiguation accuracy = 0.842 [95% CI 0.684, 1.000]
- false-positive rate = 0.333 [95% CI 0.000, 0.667]
- escalation rate = 0.000

Primary Holm family is UNCHANGED (C4 vs C1/C2/C3, 3 tests). The C4-vs-C3+gate test below is a separate, pre-declared extra test.

- EXTRA TEST C4 vs C3+gate: delta disambiguation acc = -0.158 [95% CI -0.421, 0.105], McNemar b=2 c=5 p=0.4531, Holm-over-4 adjusted p=1.0000

Holm-adjusted p-values, primary(3) vs all-four, clearly labelled:
  - C4 vs C1: Holm/primary-3 = 0.8672; Holm/all-4 = 1.0000
  - C4 vs C2: Holm/primary-3 = 1.0000; Holm/all-4 = 1.0000
  - C4 vs C3: Holm/primary-3 = 1.0000; Holm/all-4 = 1.0000
  - C4 vs C3+gate: Holm/all-4 = 1.0000 (not in the primary family)
