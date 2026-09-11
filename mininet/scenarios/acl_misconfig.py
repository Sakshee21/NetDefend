#!/usr/bin/env python3
"""ACL misconfiguration scenario — reproducible Mininet script.

Builds the same h1/h2 topology as mininet/topologies/basic_topology.py,
then automates the manual scenario previously run by hand at the Mininet
CLI: an HTTP server on h2 gets blocked by a misordered pair of firewall
rules (DROP inserted before LOG, so LOG ends up checked first and falls
through to DROP), and the resulting traffic capture, rule state, counter
deltas, and ground-truth metadata are written to dataset/raw/.

This script uses Mininet's Python API directly (Mininet, Node/Host,
OVSSwitch) — no interactive CLI(net) session, no scripted CLI commands.
Per-host commands run through Host.cmd(), which is the sanctioned way to
execute commands inside a host's network namespace from the Python API.

Must be run as root (Mininet requirement):

    sudo python3 mininet/scenarios/acl_misconfig.py
"""
import json
import time
from datetime import datetime
from pathlib import Path

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.log import setLogLevel

H1_IP = "10.0.0.1"
H2_IP = "10.0.0.2"
HTTP_PORT = 8000
NUM_CURL_ATTEMPTS = 10
CURL_CONNECT_TIMEOUT = 2
CURL_SLEEP_BETWEEN = 1

REPO_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = REPO_ROOT / "dataset" / "raw"

PCAP_PATH = RAW_DIR / "acl_misconfig.pcap"
IPTABLES_SAVE_PATH = RAW_DIR / "acl_misconfig_iptables.txt"
FIREWALL_LOG_PATH = RAW_DIR / "acl_misconfig_firewall.log"
METADATA_PATH = RAW_DIR / "acl_misconfig_metadata.json"


def build_network():
    """Build the h1/h2/s1 topology, matching basic_topology.py exactly
    (same IPs, no controller, OVSSwitch in standalone fail mode)."""
    print("*** Creating network")

    net = Mininet(
        controller=None,
        switch=OVSSwitch
    )

    print("*** Adding hosts")

    h1 = net.addHost("h1", ip=f"{H1_IP}/24")
    h2 = net.addHost("h2", ip=f"{H2_IP}/24")

    print("*** Adding switch")

    s1 = net.addSwitch("s1", failMode="standalone")

    print("*** Creating links")

    net.addLink(h1, s1)
    net.addLink(h2, s1)

    print("*** Starting network")

    net.start()

    print("*** Network started successfully")
    print("h1 IP:", h1.IP())
    print("h2 IP:", h2.IP())

    return net, h1, h2


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _normalize_bytes(value: str) -> int:
    """iptables -v abbreviates large byte counts (e.g. '1.2K'); convert
    back to a plain integer so deltas can be computed. Traffic volumes in
    this scenario are tiny, so this almost always sees a bare integer."""
    value = value.strip()
    multipliers = {"K": 1_000, "M": 1_000_000, "G": 1_000_000_000}
    if value and value[-1] in multipliers:
        return int(float(value[:-1]) * multipliers[value[-1]])
    return int(value)


def parse_counters(raw_output: str) -> dict:
    """Parse `iptables -L INPUT -n -v --line-numbers` output and return
    {'LOG': (pkts, bytes), 'DROP': (pkts, bytes)} for the dport-8000
    rules this scenario inserted."""
    counters = {}
    for line in raw_output.splitlines():
        parts = line.split(maxsplit=9)
        if len(parts) < 9 or not parts[0].isdigit():
            continue
        pkts, byte_field, target = parts[1], parts[2], parts[3]
        rest = parts[9] if len(parts) > 9 else ""
        if target in ("LOG", "DROP") and "8000" in rest:
            counters[target] = (int(pkts), _normalize_bytes(byte_field))
    return counters


def capture_counters(h2) -> tuple[str, dict, str]:
    """Run `iptables -L INPUT -n -v --line-numbers` on h2 and return the
    raw text, the parsed LOG/DROP counters, and a timestamp string."""
    raw = h2.cmd("iptables -L INPUT -n -v --line-numbers")
    return raw, parse_counters(raw), timestamp()


def format_firewall_log(
    before_raw: str, before_counters: dict, before_ts: str,
    after_raw: str, after_counters: dict, after_ts: str,
    num_attempts: int, traffic_start: str, traffic_end: str,
) -> str:
    """Build the firewall.log text in the exact format already proven to
    work, since kernel LOG output (dmesg/syslog) is unavailable here."""
    before_log = before_counters.get("LOG", (0, 0))
    before_drop = before_counters.get("DROP", (0, 0))
    after_log = after_counters.get("LOG", (0, 0))
    after_drop = after_counters.get("DROP", (0, 0))
    delta_pkts = after_drop[0] - before_drop[0]

    lines = [
        "ACL Misconfiguration Scenario — Firewall Rule Counter Log",
        "Method: iptables -L INPUT -n -v counters sampled before/after "
        "traffic generation. Kernel LOG target output (dmesg/syslog) "
        "unavailable in this WSL environment.",
        "",
        "--- Checkpoint 1: Before any traffic ---",
        f"[{before_ts}]",
        f"LOG rule:  pkts={before_log[0]}   bytes={before_log[1]}",
        f"DROP rule: pkts={before_drop[0]}   bytes={before_drop[1]}",
        "",
        f"--- Traffic generated: {num_attempts} curl attempts from h1 to "
        f"h2:{HTTP_PORT} ({traffic_start} to {traffic_end}) ---",
        "",
        "--- Checkpoint 2: After traffic ---",
        f"[{after_ts}]",
        f"LOG rule:  pkts={after_log[0]}   bytes={after_log[1]}",
        f"DROP rule: pkts={after_drop[0]}   bytes={after_drop[1]}",
        f"Delta: +{delta_pkts} packets",
        "",
    ]
    return "\n".join(lines)


def main():
    setLogLevel("info")
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    net, h1, h2 = build_network()
    http_pid = None
    tcpdump_pid = None

    try:
        # --- Step 2: start HTTP server on h2 ---
        print("*** Starting HTTP server on h2")
        http_pid = h2.cmd(
            f"python3 -m http.server {HTTP_PORT} "
            f"> /tmp/acl_h2_http.log 2>&1 & echo $!"
        ).strip()
        time.sleep(1)
        print(f"*** HTTP server started on h2 (pid {http_pid})")

        # --- Step 3: insert firewall rules, DROP first then LOG ---
        # -I always inserts at position 1, so inserting DROP first and
        # LOG second leaves LOG on top -> LOG (logs, falls through) then
        # DROP (drops) is the effective order.
        print("*** Inserting firewall rules on h2 (DROP first, then LOG)")
        h2.cmd(
            f'iptables -I INPUT -p tcp --dport {HTTP_PORT} '
            f'-s {H1_IP} -j DROP'
        )
        h2.cmd(
            f'iptables -I INPUT -p tcp --dport {HTTP_PORT} '
            f'-s {H1_IP} -j LOG --log-prefix "ACL_BLOCK: "'
        )

        # --- Step 4: save rule state ---
        print("*** Saving iptables rule state")
        iptables_save_output = h2.cmd("iptables-save")
        IPTABLES_SAVE_PATH.write_text(iptables_save_output, encoding="utf-8")

        # --- Step 5: BEFORE counters ---
        print("*** Capturing BEFORE counters")
        before_raw, before_counters, before_ts = capture_counters(h2)
        print(before_raw)

        # --- Step 6: start tcpdump on h1 ---
        h1_intf = h1.defaultIntf().name
        print(f"*** Starting tcpdump on h1 ({h1_intf})")
        tcpdump_pid = h1.cmd(
            f"tcpdump -i {h1_intf} -w {PCAP_PATH} -U "
            f"> /tmp/acl_tcpdump.log 2>&1 & echo $!"
        ).strip()
        time.sleep(2)
        print(f"*** tcpdump started on h1 (pid {tcpdump_pid})")

        # --- Step 7: generate blocked traffic from h1 ---
        print(f"*** Sending {NUM_CURL_ATTEMPTS} curl requests from h1 "
              f"(expected to time out)")
        traffic_start = timestamp()
        for i in range(1, NUM_CURL_ATTEMPTS + 1):
            result = h1.cmd(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"--connect-timeout {CURL_CONNECT_TIMEOUT} "
                f"http://{H2_IP}:{HTTP_PORT}"
            ).strip()
            print(f"    attempt {i}/{NUM_CURL_ATTEMPTS}: "
                  f"http_code='{result}' (empty/000 = timed out, as expected)")
            time.sleep(CURL_SLEEP_BETWEEN)
        traffic_end = timestamp()

        # --- Step 8: stop tcpdump ---
        print("*** Stopping tcpdump")
        h1.cmd(f"kill {tcpdump_pid}")
        time.sleep(2)
        h1.cmd(f"kill -0 {tcpdump_pid} 2>/dev/null && kill -9 {tcpdump_pid}")
        tcpdump_pid = None

        # --- Step 9: AFTER counters ---
        print("*** Capturing AFTER counters")
        after_raw, after_counters, after_ts = capture_counters(h2)
        print(after_raw)

        # --- Step 10: write firewall.log (dmesg/syslog unavailable) ---
        print("*** Writing firewall.log")
        firewall_log_text = format_firewall_log(
            before_raw, before_counters, before_ts,
            after_raw, after_counters, after_ts,
            NUM_CURL_ATTEMPTS, traffic_start, traffic_end,
        )
        FIREWALL_LOG_PATH.write_text(firewall_log_text, encoding="utf-8")

        # --- Step 11: write ground-truth metadata ---
        print("*** Writing metadata.json")
        metadata = {
            "scenario": "ACL_MISCONFIGURATION",
            "ground_truth": "MISCONFIGURATION",
            "source": H1_IP,
            "destination": H2_IP,
            "protocol": "TCP",
            "destination_port": HTTP_PORT,
            "action": "DROP",
            "description": (
                "Legitimate HTTP traffic from h1 to h2 is blocked by an "
                "incorrectly configured firewall rule."
            ),
        }
        METADATA_PATH.write_text(
            json.dumps(metadata, indent=4), encoding="utf-8"
        )

    finally:
        # --- Step 12: clean up background processes and tear down net ---
        print("*** Cleaning up")
        if http_pid:
            h2.cmd(f"kill {http_pid}")
        if tcpdump_pid:
            h1.cmd(f"kill {tcpdump_pid}")
        print("*** Stopping network")
        net.stop()

    # --- Final self-check: confirm output files exist with real content ---
    print("\n*** Output file summary")
    for path in (PCAP_PATH, IPTABLES_SAVE_PATH, FIREWALL_LOG_PATH, METADATA_PATH):
        if path.exists():
            print(f"    {path}: {path.stat().st_size} bytes")
        else:
            print(f"    {path}: MISSING")


if __name__ == "__main__":
    main()
