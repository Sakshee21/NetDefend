#!/usr/bin/env python3
"""Disabled logging misconfiguration scenario — reproducible Mininet script.

Builds the same h1/h2 topology as mininet/topologies/basic_topology.py,
then automates a common real-world misconfiguration: an admin applies a
DROP rule but never adds (or removes) the accompanying LOG rule, so
security-relevant traffic is blocked with no audit trail at all. Unlike
mininet/scenarios/acl_misconfig.py -- where the misconfiguration is rule
*order* (LOG present but shadowed) -- here the misconfiguration is that
no LOG rule exists in the first place. Traffic really is blocked; there
is simply nothing anywhere recording that it happened.

This script uses Mininet's Python API directly (Mininet, Node/Host,
OVSSwitch) -- no interactive CLI(net) session, no scripted CLI commands.
Per-host commands run through Host.cmd().

Must be run as root (Mininet requirement):

    sudo python3 mininet/scenarios/disabled_logging_misconfig.py
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

# Patterns a netfilter LOG rule would have produced in dmesg/journalctl
# if one existed. Used only to prove they are ABSENT -- there is no LOG
# rule in this scenario, so these greps are expected to find nothing.
LOG_TRAIL_GREP_PATTERNS = f"SRC={H1_IP}|DPT={HTTP_PORT}|ACL_BLOCK"

REPO_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = REPO_ROOT / "dataset" / "raw"

PCAP_PATH = RAW_DIR / "disabled_logging_misconfig.pcap"
IPTABLES_SAVE_PATH = RAW_DIR / "disabled_logging_misconfig_iptables.txt"
EVIDENCE_LOG_PATH = RAW_DIR / "disabled_logging_misconfig_evidence.log"
METADATA_PATH = RAW_DIR / "disabled_logging_misconfig_metadata.json"


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


def parse_drop_counter(raw_output: str) -> tuple:
    """Parse `iptables -L INPUT -n -v --line-numbers` output and return
    (pkts, bytes) for the dport-8000 DROP rule this scenario inserted.
    Unlike acl_misconfig.py there is no LOG row to find -- its absence
    here is the point."""
    for line in raw_output.splitlines():
        parts = line.split(maxsplit=9)
        if len(parts) < 9 or not parts[0].isdigit():
            continue
        pkts, byte_field, target = parts[1], parts[2], parts[3]
        rest = parts[9] if len(parts) > 9 else ""
        if target == "DROP" and str(HTTP_PORT) in rest:
            return (int(pkts), _normalize_bytes(byte_field))
    return (0, 0)


def capture_counters(h2) -> tuple:
    """Run `iptables -L INPUT -n -v --line-numbers` on h2 and return the
    raw text, the parsed DROP counters, and a timestamp string."""
    raw = h2.cmd("iptables -L INPUT -n -v --line-numbers")
    return raw, parse_drop_counter(raw), timestamp()


def check_log_trail(h2) -> str:
    """Actively check dmesg and journalctl for any netfilter LOG entries
    matching this flow -- the same style of check used (and found
    unavailable/empty) in acl_misconfig.py, but run for real here since
    proving the log trail's absence IS the evidence for this scenario."""
    dmesg_grep = h2.cmd(
        f"dmesg 2>&1 | grep -iE '{LOG_TRAIL_GREP_PATTERNS}'"
    ).strip()
    journal_grep = h2.cmd(
        f"journalctl -k --no-pager -n 200 2>&1 | grep -iE '{LOG_TRAIL_GREP_PATTERNS}'"
    ).strip()
    journal_raw = h2.cmd("journalctl -k --no-pager -n 5 2>&1").strip()

    lines = [
        f"dmesg | grep -iE '{LOG_TRAIL_GREP_PATTERNS}':",
        f"    {dmesg_grep if dmesg_grep else '(no matching lines -- confirms no netfilter LOG entries for this flow)'}",
        f"journalctl -k --no-pager -n 200 | grep -iE '{LOG_TRAIL_GREP_PATTERNS}':",
        f"    {journal_grep if journal_grep else '(no matching lines)'}",
        "journalctl -k raw sample (context on journal availability in this environment):",
        f"    {journal_raw or '(empty)'}",
    ]
    return "\n".join(lines)


def format_iptables_snapshot(raw_save: str, ts: str, label: str) -> str:
    return f"--- {label} ({ts}) ---\n{raw_save.strip()}\n"


def format_evidence_log(
    before_ts: str, before_pkts: int, before_bytes: int,
    after_ts: str, after_pkts: int, after_bytes: int,
    num_attempts: int, traffic_start: str, traffic_end: str,
    log_trail_check: str,
) -> str:
    delta_pkts = after_pkts - before_pkts

    lines = [
        "Disabled Logging Misconfiguration Scenario — "
        "Firewall Counter + Log-Trail Absence Check",
        "Method: iptables -L INPUT -n -v counters sampled before/after "
        "traffic generation, plus dmesg/journalctl checked directly for "
        "any netfilter LOG entries matching this flow. There is no LOG "
        "rule in this scenario by design -- that absence is the "
        "misconfiguration itself.",
        "",
        "--- Checkpoint 1: Before any traffic ---",
        f"[{before_ts}]",
        f"DROP rule: pkts={before_pkts}   bytes={before_bytes}",
        "",
        f"--- Traffic generated: {num_attempts} curl attempts from h1 to "
        f"h2:{HTTP_PORT} ({traffic_start} to {traffic_end}) ---",
        "",
        "--- Checkpoint 2: After traffic ---",
        f"[{after_ts}]",
        f"DROP rule: pkts={after_pkts}   bytes={after_bytes}",
        f"Delta: +{delta_pkts} packets (traffic WAS blocked)",
        "",
        "--- Log trail check (confirming NO audit trail exists for this "
        "blocked traffic) ---",
        log_trail_check,
        "",
        f"Conclusion: {delta_pkts} packets were confirmed dropped above, "
        "yet zero matching log entries exist in dmesg or the kernel "
        "journal -- this is the disabled-logging misconfiguration.",
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
        # --- Step 2 (setup): start HTTP server on h2 ---
        print("*** Starting HTTP server on h2")
        http_pid = h2.cmd(
            f"python3 -m http.server {HTTP_PORT} "
            f"> /tmp/disabled_logging_h2_http.log 2>&1 & echo $!"
        ).strip()
        time.sleep(1)
        print(f"*** HTTP server started on h2 (pid {http_pid})")

        # --- Step 2: apply DROP rule with NO accompanying LOG rule ---
        print("*** Inserting DROP rule on h2 -- deliberately no LOG rule")
        h2.cmd(
            f'iptables -I INPUT -p tcp --dport {HTTP_PORT} '
            f'-s {H1_IP} -j DROP'
        )

        # --- Step 5 (before): save iptables state ---
        print("*** Saving BEFORE iptables state (iptables-save)")
        before_save = h2.cmd("iptables-save")
        before_save_ts = timestamp()

        # --- BEFORE counters ---
        print("*** Capturing BEFORE counters")
        before_counters_raw, (before_pkts, before_bytes), before_ts = capture_counters(h2)
        print(before_counters_raw)

        # --- Step 4: start tcpdump on h1 ---
        h1_intf = h1.defaultIntf().name
        print(f"*** Starting tcpdump on h1 ({h1_intf})")
        tcpdump_pid = h1.cmd(
            f"tcpdump -i {h1_intf} -w {PCAP_PATH} -U "
            f"> /tmp/disabled_logging_tcpdump.log 2>&1 & echo $!"
        ).strip()
        time.sleep(2)
        print(f"*** tcpdump started on h1 (pid {tcpdump_pid})")

        # --- Step 3: generate blocked traffic from h1 ---
        print(f"*** Sending {NUM_CURL_ATTEMPTS} curl requests from h1 "
              f"(expected to time out, blocked with no log trail)")
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

        # --- stop tcpdump ---
        print("*** Stopping tcpdump")
        h1.cmd(f"kill {tcpdump_pid}")
        time.sleep(2)
        h1.cmd(f"kill -0 {tcpdump_pid} 2>/dev/null && kill -9 {tcpdump_pid}")
        tcpdump_pid = None

        # --- Step 5 (after): save iptables state again ---
        print("*** Saving AFTER iptables state (iptables-save)")
        after_save = h2.cmd("iptables-save")
        after_save_ts = timestamp()

        # --- AFTER counters ---
        print("*** Capturing AFTER counters")
        after_counters_raw, (after_pkts, after_bytes), after_ts = capture_counters(h2)
        print(after_counters_raw)

        # --- Step 6: check for a log trail (expected: none) ---
        print("*** Checking dmesg/journalctl for any log trail (expecting none)")
        log_trail_check = check_log_trail(h2)
        print(log_trail_check)

        # --- Step 5: write iptables.txt (before + after, no LOG rule) ---
        print("*** Writing disabled_logging_misconfig_iptables.txt")
        iptables_text = (
            "Disabled Logging Misconfiguration Scenario — iptables State Snapshot\n"
            "Only a DROP rule is present below -- there is no LOG rule in either "
            "snapshot. That absence is the misconfiguration this scenario "
            "demonstrates: real traffic is blocked (see "
            "disabled_logging_misconfig_evidence.log for the counter deltas) "
            "with no rule anywhere to record it.\n\n"
            + format_iptables_snapshot(before_save, before_save_ts, "BEFORE traffic")
            + "\n"
            + format_iptables_snapshot(after_save, after_save_ts, "AFTER traffic")
        )
        IPTABLES_SAVE_PATH.write_text(iptables_text, encoding="utf-8")

        # --- Step 6: write evidence.log ---
        print("*** Writing disabled_logging_misconfig_evidence.log")
        evidence_text = format_evidence_log(
            before_ts, before_pkts, before_bytes,
            after_ts, after_pkts, after_bytes,
            NUM_CURL_ATTEMPTS, traffic_start, traffic_end,
            log_trail_check,
        )
        EVIDENCE_LOG_PATH.write_text(evidence_text, encoding="utf-8")

        # --- Step 7: write ground-truth metadata ---
        print("*** Writing metadata.json")
        metadata = {
            "scenario": "DISABLED_LOGGING_MISCONFIGURATION",
            "ground_truth": "MISCONFIGURATION",
            "source": H1_IP,
            "destination": H2_IP,
            "protocol": "TCP",
            "destination_port": HTTP_PORT,
            "action": "DROP_NO_LOG",
            "description": (
                "A firewall rule blocks traffic but has no accompanying "
                "logging rule, meaning legitimate security events leave no "
                "audit trail — an operational misconfiguration distinct "
                "from the traffic pattern itself."
            ),
        }
        METADATA_PATH.write_text(
            json.dumps(metadata, indent=4), encoding="utf-8"
        )

    finally:
        # --- Step 8: clean up background processes and tear down net ---
        print("*** Cleaning up")
        if http_pid:
            h2.cmd(f"kill {http_pid}")
        if tcpdump_pid:
            h1.cmd(f"kill {tcpdump_pid}")
        print("*** Stopping network")
        net.stop()

    # --- Final self-check: confirm output files exist with real content ---
    print("\n*** Output file summary")
    for path in (PCAP_PATH, IPTABLES_SAVE_PATH, EVIDENCE_LOG_PATH, METADATA_PATH):
        if path.exists():
            print(f"    {path}: {path.stat().st_size} bytes")
        else:
            print(f"    {path}: MISSING")


if __name__ == "__main__":
    main()
