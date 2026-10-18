#!/usr/bin/env python3
"""
NetDefend-Bench ROBUSTNESS scenario generator (Mininet + Scapy).

Four ATTACK scenarios in which the victim host also carries an UNRELATED,
benign firewall rule (different source / port / protocol than the attack), so
the evidence bundle contains a real configuration artifact that has nothing to
do with the attack. They probe the v2 bundle-based null gate: the system must
still classify these as ATTACK (or UNCERTAIN), never flip to MISCONFIGURATION
on the strength of an irrelevant rule.

These are DELIBERATELY kept out of the 23-scenario benchmark: their family is
``robustness_<attack>`` (a distinct namespace the harness / regen do not fold
into the 23), and the summary of a robustness run is written to its own file.

Run as root, like the other generators:
    sudo python3 generate_robustness_scenarios.py --outdir dataset/raw
    sudo python3 generate_robustness_scenarios.py --list
    sudo python3 generate_robustness_scenarios.py --only tcp_port_scan_robust_a

See ROBUSTNESS_SPEC.md for the design. The attack workers, pcap verification
and evidence format are reused verbatim from generate_attack_scenarios.py, so
these scenarios are identical to the attack set except for the added benign
rule on the victim.
"""
import argparse
import datetime
import json
import os
import shlex
import signal
import subprocess
import sys
import time

from _benchlib import (  # noqa: F401
    N_HOSTS, PAIR_POOL, PAIR_A, PAIR_B, PAIR_C, ip_of,
    capture_rule_sections, capture_log_trail, build_evidence,
)
# Reuse the attack machinery verbatim (same workers, verifier, params).
import generate_attack_scenarios as atk

# iptables lives in /usr/sbin; full path, as in the misconfiguration generators,
# so it resolves inside the Mininet host namespace regardless of PATH.
IPTABLES = "/usr/sbin/iptables"

# kind/listener/params reuse the attack generator's worker contract. benign_rule
# is an iptables -A INPUT spec that does NOT match the attack traffic (unrelated
# source, port or protocol). benign_desc documents why it is unrelated.
SCENARIOS = [
    dict(base="tcp_port_scan", family="robustness_tcp_port_scan", variant="robust_a", kind="tcp_scan",
         pair=PAIR_A, technique="T1046", listener=None,
         params=dict(port_lo=20, port_hi=40, delay=0.01),
         benign_rule="-A INPUT -s 10.0.0.9/32 -p tcp --dport 22 -j ACCEPT",
         benign_desc="allow SSH from an admin host (10.0.0.9), not the scanner; "
                     "does not touch the scanned ports 20-40"),
    dict(base="udp_port_scan", family="robustness_udp_port_scan", variant="robust_a", kind="udp_scan",
         pair=PAIR_B, technique="T1046", listener=None,
         params=dict(port_lo=1, port_hi=30, delay=0.01),
         benign_rule="-A INPUT -p tcp --dport 23 -j DROP",
         benign_desc="block legacy telnet (TCP/23); unrelated protocol and port "
                     "to the UDP scan of ports 1-30"),
    dict(base="icmp_host_sweep", family="robustness_icmp_host_sweep", variant="robust_a", kind="icmp_sweep",
         pair=PAIR_C, technique="T1018", listener=None,
         params=dict(delay=0.05),
         benign_rule="-A INPUT -s 10.0.0.9/32 -p tcp --dport 443 -j ACCEPT",
         benign_desc="allow HTTPS from a monitoring host (10.0.0.9); unrelated to "
                     "the ICMP echo sweep"),
    dict(base="ssh_bruteforce_sim", family="robustness_ssh_bruteforce_sim", variant="robust_a", kind="conn_series",
         pair=PAIR_A, technique="T1110", listener="banner",
         params=dict(count=30, dport=22, delay=0.1, payload="SSH-2.0-sim_client\r\n"),
         benign_rule="-A INPUT -p tcp --dport 8080 -j ACCEPT",
         benign_desc="allow an internal web app (TCP/8080); not the SSH target "
                     "port 22 the brute-force simulation hits"),
]


def sid_of(sc):
    # id is <base>_<variant> (e.g. tcp_port_scan_robust_a); the
    # robustness_* family namespace keeps these out of the 23 benchmark.
    return "%s_%s" % (sc["base"], sc["variant"])


def run_scenario(net, sc, outdir, script, allow_unverified, scapy_version):
    sid = sid_of(sc)
    a, b = sc["pair"]
    src, dst = net.get("h%d" % a), net.get("h%d" % b)
    params = atk.build_params(sc)

    # Install exactly ONE unrelated benign rule on the victim. Flush INPUT
    # first so a rule left by a previous scenario on the same host cannot leak
    # in. The rule is applied with the full iptables path inside the victim's
    # namespace and is NEVER written to any file by hand -- it is captured back
    # out of the live ruleset below, exactly like a real rule.
    dst.cmd("%s -F INPUT" % IPTABLES)
    rule_rc = dst.cmd("%s %s; echo RC=$?" % (IPTABLES, sc["benign_rule"]))
    benign_installed = "RC=0" in rule_rc

    pcap_name = "%s.pcap" % sid
    pcap_path = os.path.join(outdir, pcap_name)
    tcpdump = src.popen(["tcpdump", "-i", "%s-eth0" % src.name, "-U", "-w", pcap_path],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    listener = None
    try:
        time.sleep(1.0)
        if sc["listener"]:
            kind = "banner_server" if sc["listener"] == "banner" else "http_server"
            listener = atk.start_bg(dst, kind, dst.IP(), params["dport"], atk.__file__)
            time.sleep(1.0)
        wp = json.dumps(params)
        t0 = time.time()
        src.cmd("%s %s --worker %s --src %s --dst %s --params %s" % (
            shlex.quote(sys.executable), shlex.quote(atk.__file__),
            sc["kind"], src.IP(), dst.IP(), shlex.quote(wp)))
        duration = time.time() - t0
        time.sleep(1.0)
    finally:
        if listener:
            listener.terminate()
        tcpdump.send_signal(signal.SIGINT)
        try:
            tcpdump.wait(timeout=5)
        except Exception:
            tcpdump.kill()

    # Same evidence format as every other scenario. The benign rule and its
    # counters now appear in the firewall section, as a real rule would.
    rule_text, rules_ok, restrictive = capture_rule_sections([src, dst])
    log_trail = capture_log_trail(dst, src.IP())
    evidence_name = "%s_evidence.txt" % sid
    evidence_text = build_evidence([
        ("Host firewall rules and INPUT counters", rule_text),
        ("Kernel netfilter log-trail check", log_trail),
    ])
    evidence_path = os.path.join(outdir, evidence_name)
    with open(evidence_path, "w") as f:
        f.write(evidence_text)
    if not rules_ok and not allow_unverified:
        print("  SKIP %s: firewall rules could not be captured (install "
              "iptables/nftables or pass --allow-unverified)" % sid)
        os.remove(evidence_path)
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
        return None

    ok, expected, verified, verify_notes = atk.verify_pcap(sc, pcap_path, params)

    scenario_note = (
        "Robustness probe: controlled-lab %s (variant %s), attacker h%d -> "
        "victim h%d, with an UNRELATED benign firewall rule on the victim "
        "(%s). Ground truth ATTACK is recorded only in this metadata; the "
        "benign rule is a false lead for the misconfiguration side. Kept out "
        "of the 23-scenario benchmark (family %s)."
        % (sc["family"], sc["variant"], a, b, sc["benign_desc"], sc["family"]))
    if sc["technique"] is None:
        scenario_note += " No ATT&CK technique is claimed for this family."

    meta = {
        "scenario_id": sid,
        "family": sc["family"],
        "ground_truth": "ATTACK",
        "scenario_type": "ROBUSTNESS_ATTACK_WITH_UNRELATED_BENIGN_RULE",
        "benchmark_member": False,
        "source_ip": src.IP(),
        "destination_ip": dst.IP() if sc["kind"] != "icmp_sweep" else None,
        "generator": "python3 + scapy %s (robustness script); standalone OVS bridge"
                     % scapy_version,
        "tool": "Python 3 with Scapy" + (" and sockets" if sc["kind"] == "conn_series" else ""),
        "attack_technique": sc["technique"],
        "label_basis": "simulated by script; intent-labelled",
        "benign_rule_installed": sc["benign_rule"],
        "benign_rule_rationale": sc["benign_desc"],
        "benign_rule_apply_ok": benign_installed,
        "pcap_file": pcap_name,
        "evidence_file": evidence_name,
        "notes": scenario_note,
        "destination_ips": params.get("targets"),
        "parameters": {k: v for k, v in params.items() if k != "targets"},
        "listener_on_victim": sc["listener"],
        "expected_packets": expected,
        "verified_packets": verified,
        "pcap_verified": ok,
        "verification_notes": verify_notes,
        "rules_verified": rules_ok,
        "restrictive_rules_found": restrictive,
        "duration_s": round(duration, 2),
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
    }
    with open(os.path.join(outdir, "%s_metadata.json" % sid), "w") as f:
        json.dump(meta, f, indent=2)
    print("  %-34s pcap_verified=%s rules_verified=%s benign_rule_ok=%s %s"
          % (sid, ok, rules_ok, benign_installed, "; ".join(verify_notes)))
    return meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="dataset/raw")
    ap.add_argument("--only", help="comma-separated scenario ids")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--allow-unverified", action="store_true")
    args = ap.parse_args()

    if args.list:
        for sc in SCENARIOS:
            print("%-34s %-12s h%d -> h%d  technique=%s  benign_rule=[%s]"
                  % (sid_of(sc), sc["kind"], sc["pair"][0], sc["pair"][1],
                     sc["technique"], sc["benign_rule"]))
        return

    if os.geteuid() != 0:
        sys.exit("run as root (sudo)")
    from mininet.net import Mininet
    from mininet.node import OVSBridge
    from mininet.topo import SingleSwitchTopo
    from mininet.log import setLogLevel
    import scapy
    setLogLevel("warning")

    os.makedirs(args.outdir, exist_ok=True)
    script = os.path.abspath(__file__)
    chosen = SCENARIOS
    if args.only:
        wanted = set(args.only.split(","))
        chosen = [s for s in SCENARIOS if sid_of(s) in wanted]

    net = Mininet(topo=SingleSwitchTopo(N_HOSTS), switch=OVSBridge, controller=None)
    net.start()
    time.sleep(2.0)
    results = []
    try:
        for sc in chosen:
            print("running %s" % sid_of(sc))
            m = run_scenario(net, sc, args.outdir, script, args.allow_unverified,
                             scapy.__version__)
            if m:
                results.append(m)
            time.sleep(1.0)
    finally:
        net.stop()

    # Own result file -- kept separate from the 23-scenario benchmark outputs.
    summary_path = os.path.join(args.outdir, "robustness_results.json")
    with open(summary_path, "w") as f:
        json.dump({"generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
                   "benchmark_member": False,
                   "scenarios": results}, f, indent=2)
    bad = [m["scenario_id"] for m in results if not m["pcap_verified"]]
    print("\ndone: %d robustness scenarios written to %s" % (len(results), args.outdir))
    print("summary: %s" % summary_path)
    if bad:
        print("PCAP MISMATCH (do not use until fixed): %s" % ", ".join(bad))


if __name__ == "__main__":
    main()
