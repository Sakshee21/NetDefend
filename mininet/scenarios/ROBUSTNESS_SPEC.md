# Robustness scenario generator — SPEC (not yet implemented, do not run)

Purpose: stress-test the v2 bundle-based null rule. The rule keeps the
misconfiguration hypothesis alive whenever the evidence bundle contains **any**
configuration artifact. These scenarios put a real but **unrelated, benign**
firewall rule on the victim host while an attack is in progress, so the bundle
*does* contain an artifact even though the attack has nothing to do with it.

The system must still conclude **ATTACK** (or UNCERTAIN), never flip to
MISCONFIGURATION on the strength of an irrelevant rule. The ground-truth label
for all four is **ATTACK**.

These scenarios are deliberately **kept separate from the 23-scenario
benchmark** so they never enter the main precision/recall/disambiguation
numbers; they are an adversarial robustness probe only.

## Proposed script

`mininet/scenarios/generate_robustness_scenarios.py`, reusing the shared
`_benchlib.py` helpers (`PAIR_POOL`, `run_tool`, `capture_rule_sections`,
`capture_log_trail`, `build_evidence`, `sys.executable` for workers,
`/usr/sbin/iptables` full paths, popen+SIGINT tcpdump) exactly as the existing
attack/misconfig generators do — so topology, capture method, evidence format
and label-neutrality controls are identical.

## Scenarios (4, all labelled ATTACK)

| id | attack worker | host pair | unrelated benign rule on the victim |
|---|---|---|---|
| `tcp_port_scan_robust_a`     | TCP SYN scan across many ports | A (h1→h2) | `-A INPUT -s 10.0.0.9/32 -p tcp --dport 22 -j ACCEPT`  (allow SSH from an admin host that is not the scanner) |
| `udp_port_scan_robust_a`     | UDP scan across many ports     | B (h3→h4) | `-A INPUT -p tcp --dport 23 -j DROP`  (block legacy telnet; unrelated protocol/port) |
| `icmp_host_sweep_robust_a`   | ICMP echo sweep across hosts   | C (h5→h6) | `-A INPUT -s 10.0.0.9/32 -p tcp --dport 443 -j ACCEPT`  (allow HTTPS from a monitoring host) |
| `ssh_bruteforce_sim_robust_a`| repeated SSH connects to :22   | A (h1→h2) | `-A INPUT -p tcp --dport 8080 -j ACCEPT`  (allow an internal web app; not the SSH target) |

Rules chosen so that **none matches the attack traffic**: a different source
(10.0.0.9, never the attacker), a different port (23/443/8080, never the scanned
ports or the SSH target in the brute-force case), or a different protocol. The
artifact is genuinely present in the capture but is a false lead for the
misconfiguration side.

### Per-scenario behaviour
1. Start the pair; install the unrelated benign rule on the victim with
   `/usr/sbin/iptables -A INPUT ...` (full path, as in the other generators).
2. Begin the popen+SIGINT `tcpdump` capture on the victim's interface.
3. Run the attack worker (`sys.executable ... --worker <kind> --dst <ip>
   --params ...`) — the same workers the existing attack generator spawns.
4. Stop the capture; capture the rule sections and the kernel log-trail with
   `capture_rule_sections` / `capture_log_trail` (so the benign rule and its
   counters appear in the evidence, just as a real rule would).
5. Emit a label-neutral `<id>_evidence.txt` via `build_evidence` with the same
   uniform section headers as every other scenario — no verdict words, no
   scenario/family names, no source references (passes the run_scenarios leak
   guardrail).

### Metadata
`<id>_metadata.json` with:
- `ground_truth`: `"ATTACK"`
- `family`: `"robustness_<attack_family>"` (e.g. `robustness_tcp_port_scan`) —
  a **distinct family namespace** so `experiments/regen_ml.benchmark_scenarios`
  and the harness's scenario discovery do not fold these into the 23. The main
  benchmark selects the existing families only; these must be requested
  explicitly with `--only <ids>`.
- `mitre_ttp`: the attack's technique (T1046 for scans, T1595/none for sweep,
  T1110 for the brute-force simulation) — ground truth for mapping, consistent
  with the existing attack scenarios.

### Separation from the benchmark
- Output pcaps / evidence / metadata to `dataset/raw/` with the `_robust_`
  infix in the id, OR to a sibling `dataset/robustness/` dir; either way the
  distinct `robustness_*` family keeps them out of the 23-scenario runs.
- Document in `datasets/README.md` that the robustness set is separate and is
  never included in the headline metrics.

### Expected use (after generation, a separate v2/v2 run)
Run only these four with `--only tcp_port_scan_robust_a,udp_port_scan_robust_a,
icmp_host_sweep_robust_a,ssh_bruteforce_sim_robust_a --feature-version v2
--reasoning-version v2`. Success = the system keeps classifying them ATTACK
(or UNCERTAIN) despite `bundle_has_config_artifact` returning True, i.e. the
grounding validator + evidence-support adjudication do not let an unrelated
benign rule carry a misconfiguration verdict. A MISCONFIGURATION verdict on any
of the four is a robustness failure to investigate.

## Not implemented here
This file is a specification only. No generator code is added and nothing is
run. Implement `generate_robustness_scenarios.py` (and a `run_all`-style driver
entry) in a later step, after sign-off.
