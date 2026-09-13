#!/usr/bin/env python3
"""DNS resolver misconfiguration scenario — reproducible Mininet script.

Builds the same h1/h2 topology as mininet/topologies/basic_topology.py,
then automates a resolver misconfiguration: h2 runs a DNS responder that
never caches anything and answers every query as if it were forwarding
externally from scratch. h1 repeatedly queries the same domain, producing
a sustained query-volume spike that superficially resembles DNS
tunneling exfiltration, but is actually a benign caching bug.

dnsmasq is not installed in this environment, so h2's resolver is a
small stdlib-only UDP DNS responder (no third-party DNS library, so it
runs the same regardless of what's importable under `sudo`). It answers
real dig queries correctly -- this isn't a stub that drops traffic, it's
a resolver that works but never remembers what it already answered.
h1 and h2 have no route to genuine external DNS infrastructure from this
isolated topology, so "always forwards externally" is modeled as
"always resolves fresh, never from a cache" -- the same observable
behavior (no cache hits despite repeated identical queries) without
requiring real internet egress from a Mininet host namespace.

Uses Mininet's Python API directly (Mininet, Node/Host, OVSSwitch) -- no
interactive CLI(net) session, no scripted CLI commands. Per-host commands
run through Host.cmd().

Must be run as root (Mininet requirement):

    sudo python3 mininet/scenarios/dns_misconfig.py
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
DNS_PORT = 53
QUERY_DOMAIN = "example.com"
NUM_QUERIES = 18
QUERY_SLEEP_BETWEEN = 1
DIG_TIMEOUT = 2

REPO_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = REPO_ROOT / "dataset" / "raw"

PCAP_PATH = RAW_DIR / "dns_misconfig.pcap"
CONFIG_PATH = RAW_DIR / "dns_misconfig_config.txt"
EVIDENCE_LOG_PATH = RAW_DIR / "dns_misconfig_evidence.log"
METADATA_PATH = RAW_DIR / "dns_misconfig_metadata.json"

# Written into h2's filesystem (shared with the host -- mininet network
# namespaces don't isolate the filesystem) so the resolver process and
# this orchestrating script can exchange state.
SERVER_SCRIPT_PATH = "/tmp/dns_misconfig_server.py"
STATE_PATH = "/tmp/dns_misconfig_state.txt"
SERVER_LOG_PATH = "/tmp/dns_misconfig_server.log"

# The resolver's own source, written to disk and launched on h2. Answers
# every query correctly (real NOERROR + A record) but keeps no cache of
# any kind -- every single query, including repeats of the same name,
# is treated as a fresh miss. That's the misconfiguration: a resolver
# that works, but never remembers what it already resolved.
DNS_SERVER_SOURCE = f'''
"""Minimal stdlib DNS responder for the DNS misconfiguration scenario.

Deliberately has NO cache: every query, even a repeat of the exact same
name, is answered as a fresh lookup. Tracks a running query count and
writes it to a state file after every request so the orchestrating
script can snapshot "resolver state" before/after traffic, the same way
the ACL scenario snapshots iptables counters.
"""
import socket
import struct
from datetime import datetime

ANSWER_IP = "203.0.113.10"  # RFC 5737 TEST-NET-3 -- documentation-only address
TTL = 5
STATE_PATH = {STATE_PATH!r}

CACHE_ENABLED = False  # the misconfiguration: this is never consulted
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
    flags = struct.pack("!H", 0x8180)  # standard response, recursion available, no error
    header = txn_id + flags + struct.pack("!HHHH", 1, 1, 0, 0)
    question = query[12:qname_end_offset + 4]  # qname + qtype(2) + qclass(2)
    answer = (
        b"\\xc0\\x0c"
        + struct.pack("!H", 1)      # TYPE A
        + struct.pack("!H", 1)      # CLASS IN
        + struct.pack("!I", TTL)
        + struct.pack("!H", 4)      # RDLENGTH
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
    print("[dns_misconfig_server] listening on UDP/53, cache_enabled=False", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(512)
            qname, end = parse_qname(data)
            resp = build_response(data, end)
            sock.sendto(resp, addr)
            total_queries_served += 1
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            write_state(total_queries_served, qname, now)
            print(f"[dns_misconfig_server] answered query #{{total_queries_served}} "
                  f"for {{qname}} from {{addr}} (no cache consulted)", flush=True)
        except Exception as exc:  # noqa: BLE001 -- keep serving, don't die on one bad packet
            print(f"[dns_misconfig_server] error handling packet: {{exc}}", flush=True)


if __name__ == "__main__":
    main()
'''


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


def parse_state(raw_state: str) -> dict:
    """Parse the resolver's `key=value` state file into a dict."""
    state = {}
    for line in raw_state.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            state[key.strip()] = value.strip()
    return state


def capture_state(h2) -> tuple[str, dict, str]:
    """Cat the resolver's state file on h2 and return the raw text, the
    parsed dict, and a timestamp string."""
    raw = h2.cmd(f"cat {STATE_PATH}")
    return raw, parse_state(raw), timestamp()


def format_config_snapshot(raw_state: str, ts: str, label: str) -> str:
    return (
        f"--- {label} ({ts}) ---\n"
        f"{raw_state.strip()}\n"
    )


def format_evidence_log(
    before_raw: str, before_state: dict, before_ts: str,
    after_raw: str, after_state: dict, after_ts: str,
    num_queries: int, domain: str, traffic_start: str, traffic_end: str,
) -> str:
    """Build the evidence.log text, following the same before/traffic/
    after format as acl_misconfig_firewall.log, but for DNS query counts
    instead of iptables packet counters."""
    before_served = int(before_state.get("total_queries_served", 0))
    after_served = int(after_state.get("total_queries_served", 0))
    before_cache = before_state.get("cache_entries", "0")
    after_cache = after_state.get("cache_entries", "0")
    delta = after_served - before_served

    lines = [
        "DNS Misconfiguration Scenario — Resolver Query Volume Log",
        "Method: resolver query-counter state file sampled before/after "
        "traffic generation (see dns_misconfig_config.txt for the full "
        "resolver configuration snapshot).",
        "",
        "--- Checkpoint 1: Before any traffic ---",
        f"[{before_ts}]",
        f"Queries served: {before_served}",
        f"Cache entries: {before_cache}",
        "",
        f"--- Traffic generated: {num_queries} dig queries from h1 to h2:{DNS_PORT} "
        f"for {domain} ({traffic_start} to {traffic_end}) ---",
        "",
        "--- Checkpoint 2: After traffic ---",
        f"[{after_ts}]",
        f"Queries served: {after_served}",
        f"Cache entries: {after_cache}",
        f"Delta: +{delta} queries "
        f"(0 served from cache — resolver never caches, confirming the misconfiguration)",
        "",
    ]
    return "\n".join(lines)


def main():
    setLogLevel("info")
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    net, h1, h2 = build_network()
    dns_pid = None
    tcpdump_pid = None

    try:
        # --- Step 2: write and start the DNS resolver on h2 ---
        print("*** Writing DNS resolver script to h2's filesystem")
        Path(SERVER_SCRIPT_PATH).write_text(DNS_SERVER_SOURCE, encoding="utf-8")

        print("*** Starting DNS resolver on h2 (no cache, port 53)")
        dns_pid = h2.cmd(
            f"python3 {SERVER_SCRIPT_PATH} "
            f"> {SERVER_LOG_PATH} 2>&1 & echo $!"
        ).strip()
        time.sleep(1)
        print(f"*** DNS resolver started on h2 (pid {dns_pid})")

        # --- Step 5 (before): capture resolver state right after startup ---
        print("*** Capturing BEFORE resolver state")
        before_raw, before_state, before_ts = capture_state(h2)
        print(before_raw)

        # --- Step 4: start tcpdump on h1 ---
        h1_intf = h1.defaultIntf().name
        print(f"*** Starting tcpdump on h1 ({h1_intf})")
        tcpdump_pid = h1.cmd(
            f"tcpdump -i {h1_intf} -w {PCAP_PATH} -U "
            f"> /tmp/dns_tcpdump.log 2>&1 & echo $!"
        ).strip()
        time.sleep(2)
        print(f"*** tcpdump started on h1 (pid {tcpdump_pid})")

        # --- Step 3: generate repeated DNS queries from h1 ---
        print(f"*** Sending {NUM_QUERIES} dig queries from h1 for "
              f"{QUERY_DOMAIN} (expected to all resolve, none cached)")
        traffic_start = timestamp()
        for i in range(1, NUM_QUERIES + 1):
            result = h1.cmd(
                f"dig @{H2_IP} -p {DNS_PORT} {QUERY_DOMAIN} "
                f"+time={DIG_TIMEOUT} +tries=1 +short"
            ).strip()
            print(f"    query {i}/{NUM_QUERIES}: resolved='{result or 'NO RESPONSE'}'")
            time.sleep(QUERY_SLEEP_BETWEEN)
        traffic_end = timestamp()

        # --- stop tcpdump ---
        print("*** Stopping tcpdump")
        h1.cmd(f"kill {tcpdump_pid}")
        time.sleep(2)
        h1.cmd(f"kill -0 {tcpdump_pid} 2>/dev/null && kill -9 {tcpdump_pid}")
        tcpdump_pid = None

        # --- Step 5 (after): capture resolver state again ---
        print("*** Capturing AFTER resolver state")
        after_raw, after_state, after_ts = capture_state(h2)
        print(after_raw)

        # --- Step 5: write config snapshot (before + after) ---
        print("*** Writing dns_misconfig_config.txt")
        config_text = (
            "DNS Misconfiguration Scenario — Resolver Configuration Snapshot\n"
            "dnsmasq was not available in this environment; h2 runs a minimal "
            "stdlib DNS responder configured to never cache and always resolve "
            "fresh (see mininet/scenarios/dns_misconfig.py for its source).\n\n"
            + format_config_snapshot(before_raw, before_ts, "BEFORE traffic (server startup)")
            + "\n"
            + format_config_snapshot(after_raw, after_ts, "AFTER traffic")
        )
        CONFIG_PATH.write_text(config_text, encoding="utf-8")

        # --- Step 6: write evidence.log ---
        print("*** Writing dns_misconfig_evidence.log")
        evidence_text = format_evidence_log(
            before_raw, before_state, before_ts,
            after_raw, after_state, after_ts,
            NUM_QUERIES, QUERY_DOMAIN, traffic_start, traffic_end,
        )
        EVIDENCE_LOG_PATH.write_text(evidence_text, encoding="utf-8")

        # --- Step 7: write ground-truth metadata ---
        print("*** Writing metadata.json")
        metadata = {
            "scenario": "DNS_MISCONFIGURATION",
            "ground_truth": "MISCONFIGURATION",
            "source": H1_IP,
            "destination": H2_IP,
            "protocol": "DNS",
            "destination_port": DNS_PORT,
            "action": "REPEATED_QUERY_NO_CACHE",
            "description": (
                "A misconfigured DNS resolver on h2 fails to cache responses, "
                "causing repeated external queries for the same domain that "
                "superficially resemble a DNS tunneling exfiltration pattern."
            ),
        }
        METADATA_PATH.write_text(
            json.dumps(metadata, indent=4), encoding="utf-8"
        )

    finally:
        # --- Step 8: clean up background processes and tear down net ---
        print("*** Cleaning up")
        if dns_pid:
            h2.cmd(f"kill {dns_pid}")
        if tcpdump_pid:
            h1.cmd(f"kill {tcpdump_pid}")
        print("*** Stopping network")
        net.stop()

    # --- Final self-check: confirm output files exist with real content ---
    print("\n*** Output file summary")
    for path in (PCAP_PATH, CONFIG_PATH, EVIDENCE_LOG_PATH, METADATA_PATH):
        if path.exists():
            print(f"    {path}: {path.stat().st_size} bytes")
        else:
            print(f"    {path}: MISSING")


if __name__ == "__main__":
    main()
