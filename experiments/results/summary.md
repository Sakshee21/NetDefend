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
fig1_metrics, fig2_confusion, fig3_by_scenario_type, fig4_debate_vs_fusion, fig5_latency_calls, fig6_confidence
