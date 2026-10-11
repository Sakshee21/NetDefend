#!/usr/bin/env python3
"""DNS resolver misconfiguration scenario — reproducible Mininet script.

Builds a two-host topology (same OVS standalone switch as
mininet/topologies/basic_topology.py) using a host pair drawn from the
shared NetDefend-Bench pool (_benchlib.PAIR_POOL). The victim runs a
stdlib UDP DNS responder that answers correctly but never caches; the
source repeatedly queries the same domain, producing a sustained
query-volume spike.

The evidence file is built from _benchlib's shared helpers, in the SAME
format every NetDefend-Bench scenario uses (raw firewall rules + INPUT
counters + a kernel log-trail check), plus one extra section carrying the
resolver's own before/after state (query counters and cache settings) as
raw tool output. It contains only operator-visible facts — never a verdict
word, the scenario/family name, or a source-file reference. Ground truth
lives only in the *_metadata.json, which no agent reads.

dnsmasq is not installed here, so the resolver is a small stdlib-only UDP
responder (no third-party DNS library, so it runs the same regardless of
what's importable under `sudo`).

Run on any pair (A, B, C). The output id includes the pair
(dns_misconfig_A/_B/_C) so runs never overwrite.

Must be run as root (Mininet requirement):

    sudo python3 mininet/scenarios/dns_misconfig.py --pair C
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
    capture_rule_sections, capture_log_trail, build_evidence,
)

FAMILY = "dns_misconfig"
DNS_PORT = 53
QUERY_DOMAIN = "example.com"
NUM_QUERIES = 18
QUERY_SLEEP_BETWEEN = 1
DIG_TIMEOUT = 2

REPO_ROOT = Path(__file__).resolve().parents[2]


def build_server_source(state_path: str) -> str:
    """Source for the victim's resolver: answers every query correctly (real
    NOERROR + A record) but keeps no cache -- every query, including repeats,
    is a fresh lookup. It writes a running query count to a state file so the
    orchestrator can snapshot resolver state before/after traffic."""
    return f'''
import socket
import struct
from datetime import datetime

ANSWER_IP = "203.0.113.10"  # RFC 5737 TEST-NET-3 -- documentation-only address
TTL = 5
STATE_PATH = {state_path!r}

CACHE_ENABLED = False
FORWARD_MODE = "always_external"


def parse_qname(data, offset=12):
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), offset


def build_response(query, qname_end_offset):
    txn_id = query[0:2]
    flags = struct.pack("!H", 0x8180)
    header = txn_id + flags + struct.pack("!HHHH", 1, 1, 0, 0)
    question = query[12:qname_end_offset + 4]
    answer = (
        b"\\xc0\\x0c"
        + struct.pack("!H", 1)
        + struct.pack("!H", 1)
        + struct.pack("!I", TTL)
        + struct.pack("!H", 4)
        + socket.inet_aton(ANSWER_IP)
    )
    return header + question + answer


def write_state(total_queries_served, last_query_domain, last_query_time):
    with open(STATE_PATH, "w") as f:
        f.write(f"cache_enabled={{str(CACHE_ENABLED).lower()}}\\n")
        f.write(f"forward_mode={{FORWARD_MODE}}\\n")
        f.write("listen_port=53\\n")
        f.write("cache_entries=0\\n")
        f.write(f"total_queries_served={{total_queries_served}}\\n")
        f.write(f"last_query_domain={{last_query_domain}}\\n")
        f.write(f"last_query_time={{last_query_time}}\\n")


def main():
    total_queries_served = 0
    write_state(total_queries_served, "none", "n/a")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    print("[resolver] listening on UDP/53, cache_enabled=False", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(512)
            qname, end = parse_qname(data)
            resp = build_response(data, end)
            sock.sendto(resp, addr)
            total_queries_served += 1
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            write_state(total_queries_served, qname, now)
        except Exception as exc:  # noqa: BLE001 -- keep serving
            print(f"[resolver] error: {{exc}}", flush=True)


if __name__ == "__main__":
    main()
'''


def build_network(h1_name, h1_ip, h2_name, h2_ip):
    """Build the two-host topology (no controller, OVSSwitch standalone)."""
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


def parse_state(raw_state: str) -> dict:
    """Parse the resolver's key=value state file into a dict."""
    state = {}
    for line in raw_state.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            state[key.strip()] = value.strip()
    return state


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

    server_script_path = f"/tmp/{scenario_id}_server.py"
    state_path = f"/tmp/{scenario_id}_state.txt"
    server_log_path = f"/tmp/{scenario_id}_server.log"

    setLogLevel("info")

    net, h1, h2 = build_network(h1_name, h1_ip, h2_name, h2_ip)
    dns_pid = None
    tcpdump = None
    delta = 0
    rules_ok = False

    try:
        # --- write and start the resolver on the victim ---
        print("*** Starting DNS resolver on victim (no cache, port 53)")
        Path(server_script_path).write_text(build_server_source(state_path), encoding="utf-8")
        dns_pid = h2.cmd(
            f"python3 {server_script_path} > {server_log_path} 2>&1 & echo $!"
        ).strip()
        time.sleep(1)

        # --- resolver state right after startup (raw cat) ---
        before_raw = h2.cmd(f"cat {state_path}").strip()
        before_state = parse_state(before_raw)

        # --- start tcpdump on the source host ---
        # popen + SIGINT (not a backgrounded Host.cmd) so stopping it leaves no
        # job-control message to desync the later evidence-capture commands.
        h1_intf = h1.defaultIntf().name
        print(f"*** Starting tcpdump on {h1_name} ({h1_intf})")
        tcpdump = h1.popen(["tcpdump", "-i", h1_intf, "-U", "-w", str(pcap_path)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

        # --- repeated DNS queries from the source host ---
        print(f"*** Sending {NUM_QUERIES} dig queries from {h1_name} for {QUERY_DOMAIN}")
        for i in range(1, NUM_QUERIES + 1):
            result = h1.cmd(
                f"dig @{h2_ip} -p {DNS_PORT} {QUERY_DOMAIN} "
                f"+time={DIG_TIMEOUT} +tries=1 +short"
            ).strip()
            print(f"    query {i}/{NUM_QUERIES}: resolved='{result or 'NO RESPONSE'}'")
            time.sleep(QUERY_SLEEP_BETWEEN)

        # --- stop tcpdump ---
        print("*** Stopping tcpdump")
        tcpdump.send_signal(signal.SIGINT)
        try:
            tcpdump.wait(timeout=5)
        except Exception:
            tcpdump.kill()
        tcpdump = None
        time.sleep(1)

        # --- resolver state after traffic (raw cat) ---
        after_raw = h2.cmd(f"cat {state_path}").strip()
        after_state = parse_state(after_raw)
        delta = (int(after_state.get("total_queries_served", 0))
                 - int(before_state.get("total_queries_served", 0)))

        # --- capture evidence AFTER traffic, same format for every scenario ---
        print("*** Capturing evidence (firewall rules + counters + log trail + resolver state)")
        rule_text, rules_ok, _restrictive = capture_rule_sections([h1, h2])
        log_trail = capture_log_trail(h2, h1_ip)
        # No /tmp path here: it embeds the scenario id and would leak the label.
        resolver_state = ("resolver state (before traffic):\n%s\n\n"
                          "resolver state (after traffic):\n%s" % (before_raw, after_raw))
        evidence_text = build_evidence([
            ("Host firewall rules and INPUT counters", rule_text),
            ("Kernel netfilter log-trail check", log_trail),
            ("Local DNS resolver state (before and after traffic)", resolver_state),
        ])
        evidence_path.write_text(evidence_text, encoding="utf-8")

        # --- write ground-truth metadata (normalized NetDefend-Bench schema) ---
        print("*** Writing metadata.json")
        pcap_verified = delta == NUM_QUERIES
        verification_notes = []
        if not pcap_verified:
            verification_notes.append(
                f"resolver served {delta} queries, expected {NUM_QUERIES} "
                "(some dig queries may have timed out)")
        metadata = {
            "scenario_id": scenario_id,
            "family": FAMILY,
            "ground_truth": "MISCONFIGURATION",
            "scenario_type": "CONTROLLED_LAB_TRAFFIC",
            "source_ip": h1_ip,
            "destination_ip": h2_ip,
            "generator": "python3 stdlib DNS responder + tcpdump (this script); "
                         "standalone OVS switch, no controller",
            "tool": "stdlib DNS responder + dig + tcpdump",
            "attack_technique": None,
            "label_basis": "operator misconfiguration reproduced by script; intent-labelled",
            "pcap_file": pcap_path.name,
            "evidence_file": evidence_path.name,
            "notes": (
                "A resolver that never caches re-resolves every repeated query, "
                "producing a sustained query-volume spike. Ground truth is "
                "recorded only in this *_metadata.json; the evidence file carries "
                "no label."),
            "protocol": "DNS",
            "destination_port": DNS_PORT,
            "action": "REPEATED_QUERY_NO_CACHE",
            "pcap_verified": pcap_verified,
            "verified_packets": {"queries_served_delta": delta,
                                 "queries_sent": NUM_QUERIES},
            "verification_notes": verification_notes,
            "rules_verified": rules_ok,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        }
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    finally:
        print("*** Cleaning up")
        if dns_pid:
            h2.cmd(f"kill {dns_pid}")
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
    print(f"*** {scenario_id}: pcap_verified={delta == NUM_QUERIES} rules_verified={rules_ok}")


if __name__ == "__main__":
    main()
