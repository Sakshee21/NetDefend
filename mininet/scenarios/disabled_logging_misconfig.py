#!/usr/bin/env python3
"""Disabled logging misconfiguration scenario — reproducible Mininet script.

Builds a two-host topology (same OVS standalone switch as
mininet/topologies/basic_topology.py) using a host pair drawn from the
shared NetDefend-Bench pool (_benchlib.PAIR_POOL). A DROP rule is applied
with NO accompanying LOG rule, so traffic is blocked with no audit trail.

The evidence file is built from _benchlib's shared helpers, in the SAME
format every NetDefend-Bench scenario uses (raw firewall rules + INPUT
counters + a kernel log-trail check). It contains only operator-visible
facts — the presence of a DROP rule, its packet counters, and the absence
of any matching kernel log entry — never a verdict word, the scenario name,
or a source-file reference. Ground truth lives only in the *_metadata.json,
which no agent reads.

Run on any pair (A, B, C). The output id includes the pair
(disabled_logging_misconfig_A/_B/_C) so runs never overwrite.

Must be run as root (Mininet requirement):

    sudo python3 mininet/scenarios/disabled_logging_misconfig.py --pair A
"""
import argparse
import json
import signal
import subprocess
import time
from datetime import datetime
from pathlib import Path

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.log import setLogLevel

from _benchlib import (
    PAIR_POOL, ip_of,
    capture_rule_sections, capture_log_trail, build_evidence, parse_input_counter,
)

FAMILY = "disabled_logging_misconfig"
HTTP_PORT = 8000
NUM_CURL_ATTEMPTS = 10
CURL_CONNECT_TIMEOUT = 2
CURL_SLEEP_BETWEEN = 1

REPO_ROOT = Path(__file__).resolve().parents[2]


def build_network(h1_name, h1_ip, h2_name, h2_ip):
    """Build the two-host topology, matching basic_topology.py (no
    controller, OVSSwitch in standalone fail mode)."""
    print("*** Creating network")

    net = Mininet(controller=None, switch=OVSSwitch)

    print("*** Adding hosts")
    h1 = net.addHost(h1_name, ip=f"{h1_ip}/24")
    h2 = net.addHost(h2_name, ip=f"{h2_ip}/24")

    print("*** Adding switch")
    s1 = net.addSwitch("s1", failMode="standalone")

    print("*** Creating links")
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    print("*** Starting network")
    net.start()

    print("*** Network started successfully")
    print("source IP:", h1.IP())
    print("victim IP:", h2.IP())
    return net, h1, h2


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", choices=list(PAIR_POOL), default="A",
                    help="host pair from the shared pool (default A)")
    ap.add_argument("--outdir", default=str(REPO_ROOT / "dataset" / "raw"),
                    help="output directory (default <repo>/dataset/raw)")
    args = ap.parse_args()

    a_idx, b_idx = PAIR_POOL[args.pair]
    h1_name, h2_name = f"h{a_idx}", f"h{b_idx}"
    h1_ip, h2_ip = ip_of(a_idx), ip_of(b_idx)
    scenario_id = f"{FAMILY}_{args.pair}"

    out_dir = Path(args.outdir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = out_dir / f"{scenario_id}.pcap"
    evidence_path = out_dir / f"{scenario_id}_evidence.txt"
    metadata_path = out_dir / f"{scenario_id}_metadata.json"

    setLogLevel("info")

    net, h1, h2 = build_network(h1_name, h1_ip, h2_name, h2_ip)
    http_pid = None
    tcpdump = None
    drop_count = 0
    rules_ok = False

    try:
        # --- start HTTP server on the victim ---
        print("*** Starting HTTP server on victim")
        http_pid = h2.cmd(
            f"python3 -m http.server {HTTP_PORT} "
            f"> /tmp/{scenario_id}_http.log 2>&1 & echo $!"
        ).strip()
        time.sleep(1)

        # --- apply DROP rule with NO accompanying LOG rule ---
        print(f"*** Inserting DROP rule on {h2_name} -- deliberately no LOG rule")
        h2.cmd(f'iptables -I INPUT -p tcp --dport {HTTP_PORT} -s {h1_ip} -j DROP')

        # --- start tcpdump on the source host ---
        # popen + SIGINT (not a backgrounded Host.cmd) so stopping it leaves no
        # job-control message to desync the later evidence-capture commands.
        h1_intf = h1.defaultIntf().name
        print(f"*** Starting tcpdump on {h1_name} ({h1_intf})")
        tcpdump = h1.popen(["tcpdump", "-i", h1_intf, "-U", "-w", str(pcap_path)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

        # --- generate blocked traffic from the source host ---
        print(f"*** Sending {NUM_CURL_ATTEMPTS} curl requests from {h1_name} "
              f"(expected to time out)")
        for i in range(1, NUM_CURL_ATTEMPTS + 1):
            result = h1.cmd(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"--connect-timeout {CURL_CONNECT_TIMEOUT} "
                f"http://{h2_ip}:{HTTP_PORT}"
            ).strip()
            print(f"    attempt {i}/{NUM_CURL_ATTEMPTS}: http_code='{result}' "
                  f"(empty/000 = timed out, as expected)")
            time.sleep(CURL_SLEEP_BETWEEN)

        # --- stop tcpdump ---
        print("*** Stopping tcpdump")
        tcpdump.send_signal(signal.SIGINT)
        try:
            tcpdump.wait(timeout=5)
        except Exception:
            tcpdump.kill()
        tcpdump = None
        time.sleep(1)

        # --- capture evidence AFTER traffic, same format for every scenario ---
        # The log-trail section is what makes the missing LOG rule observable:
        # the DROP rule's counters show traffic was blocked, while the kernel
        # log-trail check shows no matching entry. Both are raw tool output;
        # the file states no conclusion.
        print("*** Capturing evidence (firewall rules + counters + log trail)")
        rule_text, rules_ok, _restrictive = capture_rule_sections([h1, h2])
        log_trail = capture_log_trail(h2, h1_ip)
        evidence_text = build_evidence([
            ("Host firewall rules and INPUT counters", rule_text),
            ("Kernel netfilter log-trail check", log_trail),
        ])
        evidence_path.write_text(evidence_text, encoding="utf-8")

        drop_count = parse_input_counter(rule_text, "DROP", HTTP_PORT)

        # --- write ground-truth metadata (normalized NetDefend-Bench schema) ---
        print("*** Writing metadata.json")
        pcap_verified = drop_count > 0
        verification_notes = []
        if not pcap_verified:
            verification_notes.append(
                "DROP counter is zero; traffic may not have reached the rule")
        metadata = {
            "scenario_id": scenario_id,
            "family": FAMILY,
            "ground_truth": "MISCONFIGURATION",
            "scenario_type": "CONTROLLED_LAB_TRAFFIC",
            "source_ip": h1_ip,
            "destination_ip": h2_ip,
            "generator": "python3 + iptables/tcpdump (this script); "
                         "standalone OVS switch, no controller",
            "tool": "iptables + curl + tcpdump",
            "attack_technique": None,
            "label_basis": "operator misconfiguration reproduced by script; intent-labelled",
            "pcap_file": pcap_path.name,
            "evidence_file": evidence_path.name,
            "notes": (
                "A firewall rule blocks traffic but has no accompanying logging "
                "rule, so blocked traffic leaves no audit trail. Ground truth is "
                "recorded only in this *_metadata.json; the evidence file carries "
                "no label."),
            "protocol": "TCP",
            "destination_port": HTTP_PORT,
            "action": "DROP_NO_LOG",
            "pcap_verified": pcap_verified,
            "verified_packets": {"drop_counter_packets": drop_count,
                                 "curl_attempts": NUM_CURL_ATTEMPTS},
            "verification_notes": verification_notes,
            "rules_verified": rules_ok,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        }
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    finally:
        print("*** Cleaning up")
        if http_pid:
            h2.cmd(f"kill {http_pid}")
        if tcpdump is not None:
            tcpdump.kill()
        print("*** Stopping network")
        net.stop()

    print("\n*** Output file summary")
    for path in (pcap_path, evidence_path, metadata_path):
        if path.exists():
            print(f"    {path}: {path.stat().st_size} bytes")
        else:
            print(f"    {path}: MISSING")
    print(f"*** {scenario_id}: pcap_verified={drop_count > 0} rules_verified={rules_ok}")


if __name__ == "__main__":
    main()
