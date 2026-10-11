#!/usr/bin/env python3
"""
NetDefend-Bench attack scenario generator (Mininet + Scapy).

Run as root inside the environment that already runs your Mininet scenarios:
    sudo python3 generate_attack_scenarios.py --outdir dataset/raw
    sudo python3 generate_attack_scenarios.py --list
    sudo python3 generate_attack_scenarios.py --only tcp_port_scan_a

For every scenario it writes, into --outdir:
    <id>.pcap                  capture taken on the attacker's interface (both directions)
    <id>_firewall_rules.txt    raw `iptables -S` / `nft list ruleset` output from each host
                               (real tool output only; NEVER hand-written)
    <id>_metadata.json         ground truth + parameters + verification result

Rules:
  * The generator adds NO DROP/REJECT/ACL rules. Hosts are joined by a standalone
    Open vSwitch bridge (no controller, no flow rules).
  * If neither iptables nor nft works on a host, rules are marked UNVERIFIED and the
    scenario is skipped unless --allow-unverified is given. Install them first:
        sudo apt install iptables nftables
  * After capture, the pcap is checked against the scenario's expected packets.
    A scenario that does not match is reported and marked verified=false.
  * ground truth is stored ONLY in the metadata JSON, never in a file an agent reads.

Honest labelling: these are controlled lab simulations. SYN burst / slow SYN / floods
carry attack_technique=null on purpose (a few packets do not prove a DoS).
"""
import argparse
import datetime
import json
import os
import shlex
import signal
import socket
import statistics
import subprocess
import sys
import time

# Host-pair pool and shared, label-neutral evidence capture (see _benchlib).
# Run as a script, this module's directory is on sys.path, so the bare import
# resolves _benchlib.py beside this file. Every scenario -- attack or
# misconfiguration -- builds its evidence from the SAME helpers in the SAME
# format, so neither the wording nor the shape of the evidence leaks the label.
from _benchlib import (  # noqa: F401
    N_HOSTS, PAIR_POOL, PAIR_A, PAIR_B, PAIR_C, ip_of,
    capture_rule_sections, capture_log_trail, build_evidence,
)

# kind: which worker/verifier to use. listener: None | "banner" | "http" on the victim.
SCENARIOS = [
    # --- TCP SYN port scans (T1046) -------------------------------------------------
    dict(family="tcp_port_scan", variant="a", kind="tcp_scan", pair=PAIR_A, technique="T1046",
         listener=None, params=dict(port_lo=20, port_hi=40, delay=0.01)),
    dict(family="tcp_port_scan", variant="b", kind="tcp_scan", pair=PAIR_B, technique="T1046",
         listener=None, params=dict(port_lo=1, port_hi=100, delay=0.005)),
    # --- UDP port scans (T1046) -----------------------------------------------------
    dict(family="udp_port_scan", variant="a", kind="udp_scan", pair=PAIR_A, technique="T1046",
         listener=None, params=dict(port_lo=1, port_hi=30, delay=0.01)),
    dict(family="udp_port_scan", variant="b", kind="udp_scan", pair=PAIR_C, technique="T1046",
         listener=None, params=dict(port_lo=50, port_hi=90, delay=0.02)),
    # --- slow, low-rate TCP scan (T1046) --------------------------------------------
    dict(family="tcp_slow_scan", variant="a", kind="tcp_scan", pair=PAIR_B, technique="T1046",
         listener=None, params=dict(port_lo=20, port_hi=34, delay=0.5)),
    # --- SYN burst, no technique claimed --------------------------------------------
    dict(family="tcp_syn_burst", variant="a", kind="syn_series", pair=PAIR_A, technique=None,
         listener=None, params=dict(count=40, dport=8000, delay=0.001)),
    dict(family="tcp_syn_burst", variant="b", kind="syn_series", pair=PAIR_C, technique=None,
         listener="http", params=dict(count=60, dport=80, delay=0.001)),
    # --- slow SYN probes, no technique claimed --------------------------------------
    dict(family="tcp_slow_syn", variant="a", kind="syn_series", pair=PAIR_A, technique=None,
         listener=None, params=dict(count=10, dport=8000, delay=0.5)),
    dict(family="tcp_slow_syn", variant="b", kind="syn_series", pair=PAIR_B, technique=None,
         listener=None, params=dict(count=12, dport=9000, delay=0.4)),
    # --- ICMP host sweep (T1018) ----------------------------------------------------
    dict(family="icmp_host_sweep", variant="a", kind="icmp_sweep", pair=PAIR_A, technique="T1018",
         listener=None, params=dict(delay=0.05)),
    dict(family="icmp_host_sweep", variant="b", kind="icmp_sweep", pair=PAIR_B, technique="T1018",
         listener=None, params=dict(delay=0.2)),
    # --- repeated connection attempts against an SSH-like banner service (T1110) ----
    # Simulation: connection pattern only; no real credentials are tried.
    dict(family="ssh_bruteforce_sim", variant="a", kind="conn_series", pair=PAIR_A,
         technique="T1110", listener="banner",
         params=dict(count=30, dport=22, delay=0.1, payload="SSH-2.0-sim_client\r\n")),
    dict(family="ssh_bruteforce_sim", variant="b", kind="conn_series", pair=PAIR_C,
         technique="T1110", listener="banner",
         params=dict(count=20, dport=22, delay=0.25, payload="SSH-2.0-sim_client\r\n")),
    # --- HTTP request flood, no technique claimed -----------------------------------
    dict(family="http_request_flood", variant="a", kind="conn_series", pair=PAIR_B,
         technique=None, listener="http",
         params=dict(count=80, dport=80, delay=0.01, payload="GET / HTTP/1.0\r\n\r\n")),
]


def sid_of(sc):
    return "%s_%s" % (sc["family"], sc["variant"])


# ----------------------------------------------------------------------------------
# Worker mode: runs INSIDE a Mininet host namespace
# ----------------------------------------------------------------------------------
def worker_main(args):
    p = json.loads(args.params)
    kind = args.worker

    if kind == "banner_server":
        import socketserver

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.sendall(b"SSH-2.0-OpenSSH_sim\r\n")
                    self.request.settimeout(1.0)
                    self.request.recv(256)
                except Exception:
                    pass

        socketserver.ThreadingTCPServer.allow_reuse_address = True
        socketserver.ThreadingTCPServer((args.dst, int(p["port"])), H).serve_forever()
        return

    if kind == "http_server":
        os.chdir("/tmp")
        os.execvp(sys.executable, [sys.executable, "-m", "http.server", str(p["port"]), "--bind", args.dst])
        return

    from scapy.all import IP, TCP, UDP, ICMP, Raw, RandShort, send, conf
    conf.verb = 0

    if kind == "tcp_scan":
        for port in range(p["port_lo"], p["port_hi"] + 1):
            send(IP(src=args.src, dst=args.dst) / TCP(sport=RandShort(), dport=port, flags="S"))
            time.sleep(p["delay"])
    elif kind == "udp_scan":
        for port in range(p["port_lo"], p["port_hi"] + 1):
            send(IP(src=args.src, dst=args.dst) / UDP(sport=RandShort(), dport=port) / Raw(b"probe"))
            time.sleep(p["delay"])
    elif kind == "syn_series":
        for _ in range(p["count"]):
            send(IP(src=args.src, dst=args.dst) / TCP(sport=RandShort(), dport=p["dport"], flags="S"))
            time.sleep(p["delay"])
    elif kind == "icmp_sweep":
        for target in p["targets"]:
            send(IP(src=args.src, dst=target) / ICMP())
            time.sleep(p["delay"])
    elif kind == "conn_series":
        for _ in range(p["count"]):
            try:
                s = socket.create_connection((args.dst, p["dport"]), timeout=1.0)
                try:
                    s.settimeout(0.3)
                    try:
                        s.recv(128)
                    except Exception:
                        pass
                    s.sendall(p["payload"].encode())
                finally:
                    s.close()
            except Exception:
                pass
            time.sleep(p["delay"])
    else:
        raise SystemExit("unknown worker kind: %s" % kind)
    time.sleep(1.0)  # let replies land in the capture


# ----------------------------------------------------------------------------------
# Expected parameters and pcap verification (needs scapy only)
# ----------------------------------------------------------------------------------
def sweep_targets(src_idx):
    return [ip_of(i) for i in range(1, N_HOSTS + 1) if i != src_idx]


def build_params(sc):
    p = dict(sc["params"])
    if sc["kind"] == "icmp_sweep":
        p["targets"] = sweep_targets(sc["pair"][0])
    return p


def verify_pcap(sc, pcap_path, params):
    """Return (ok, expected, verified, notes)."""
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    src = ip_of(sc["pair"][0])
    dst = ip_of(sc["pair"][1])
    kind = sc["kind"]
    pkts = [p for p in rdpcap(pcap_path) if IP in p]
    notes = []

    def syns(to_port=None):
        out = []
        for p in pkts:
            if TCP in p and p[IP].src == src and p[IP].dst == dst and int(p[TCP].flags) == 0x02:
                if to_port is None or p[TCP].dport == to_port:
                    out.append(p)
        return out

    if kind == "tcp_scan":
        want = list(range(params["port_lo"], params["port_hi"] + 1))
        got = sorted(p[TCP].dport for p in syns())
        ok = got == want
        expected = dict(syn_packets=len(want), ports="%d-%d" % (want[0], want[-1]))
        verified = dict(syn_packets=len(got), ports=(("%d-%d" % (got[0], got[-1])) if got else "none"))
        if params["delay"] >= 0.3 and len(got) > 2:
            ts = [float(p.time) for p in syns()]
            gaps = [b - a for a, b in zip(ts, ts[1:])]
            med = statistics.median(gaps)
            verified["median_gap_s"] = round(med, 3)
            if abs(med - params["delay"]) > 0.25 * params["delay"] + 0.1:
                ok = False
                notes.append("median gap %.3f s differs from %.3f s" % (med, params["delay"]))
    elif kind == "udp_scan":
        want = list(range(params["port_lo"], params["port_hi"] + 1))
        got = sorted(p[UDP].dport for p in pkts
                     if UDP in p and p[IP].src == src and p[IP].dst == dst)
        ok = got == want
        expected = dict(udp_packets=len(want), ports="%d-%d" % (want[0], want[-1]))
        verified = dict(udp_packets=len(got), ports=(("%d-%d" % (got[0], got[-1])) if got else "none"))
    elif kind == "syn_series":
        s = syns(params["dport"])
        ok = len(s) == params["count"]
        expected = dict(syn_packets=params["count"], dport=params["dport"])
        verified = dict(syn_packets=len(s), dport=params["dport"])
        if len(s) > 2:
            ts = [float(p.time) for p in s]
            gaps = [b - a for a, b in zip(ts, ts[1:])]
            med = statistics.median(gaps)
            verified["median_gap_s"] = round(med, 4)
            if params["delay"] >= 0.1 and abs(med - params["delay"]) > 0.25 * params["delay"] + 0.1:
                ok = False
                notes.append("median gap %.3f s differs from %.3f s" % (med, params["delay"]))
    elif kind == "icmp_sweep":
        want = set(params["targets"])
        got = [p[IP].dst for p in pkts
               if ICMP in p and p[ICMP].type == 8 and p[IP].src == src]
        ok = set(got) == want and len(got) == len(want)
        expected = dict(echo_requests=len(want), distinct_hosts=len(want))
        verified = dict(echo_requests=len(got), distinct_hosts=len(set(got)))
    elif kind == "conn_series":
        s = syns(params["dport"])
        ok = len(s) == params["count"]  # fresh SYNs only; retransmissions would raise this
        expected = dict(connection_attempts=params["count"], dport=params["dport"])
        verified = dict(connection_attempts=len(s), dport=params["dport"])
        if len(s) != params["count"]:
            notes.append("SYN count differs (retransmissions or refused connects?)")
    else:
        ok, expected, verified = False, {}, {}
        notes.append("no verifier for kind %s" % kind)
    return ok, expected, verified, notes


# ----------------------------------------------------------------------------------
# Orchestration (needs Mininet, root)
# ----------------------------------------------------------------------------------
def start_bg(host, kind, ip, port, script):
    # sys.executable, not literal "python3": the worker imports scapy, so it
    # must run on the SAME interpreter that launched this orchestrator (the
    # repo venv has mininet+scapy; system python3 may not have scapy).
    cmd = [sys.executable, script, "--worker", kind, "--dst", ip, "--params", json.dumps({"port": port})]
    return host.popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_scenario(net, sc, outdir, script, allow_unverified, scapy_version):
    sid = sid_of(sc)
    a, b = sc["pair"]
    src, dst = net.get("h%d" % a), net.get("h%d" % b)
    params = build_params(sc)

    pcap_name = "%s.pcap" % sid
    pcap_path = os.path.join(outdir, pcap_name)
    tcpdump = src.popen(["tcpdump", "-i", "%s-eth0" % src.name, "-U", "-w", pcap_path],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    listener = None
    try:
        time.sleep(1.0)
        if sc["listener"]:
            kind = "banner_server" if sc["listener"] == "banner" else "http_server"
            listener = start_bg(dst, kind, dst.IP(), params["dport"], script)
            time.sleep(1.0)
        wp = json.dumps(params)
        t0 = time.time()
        src.cmd("%s %s --worker %s --src %s --dst %s --params %s" % (
            shlex.quote(sys.executable), shlex.quote(script),
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

    # Evidence is captured AFTER the traffic (so INPUT counters are populated)
    # and in the SAME format as the misconfiguration generators: raw firewall
    # rules + counters on both hosts, plus a kernel log-trail check on the
    # victim. Raw tool output only -- no label, no scenario name.
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
        print("  SKIP %s: firewall rules could not be captured on every host "
              "(install iptables/nftables, or pass --allow-unverified)" % sid)
        os.remove(evidence_path)
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
        return None
    if restrictive:
        print("  WARNING %s: DROP/REJECT rules found; review the label before using it" % sid)

    ok, expected, verified, verify_notes = verify_pcap(sc, pcap_path, params)

    # Human-readable note for the metadata only. Ground truth lives here and
    # nowhere else; the honest-labelling caveat is spelled out for the families
    # that deliberately claim no ATT&CK technique.
    scenario_note = ("Controlled-lab %s (variant %s), attacker h%d -> victim h%d. "
                     "Ground truth is recorded only in this *_metadata.json; no "
                     "file an agent reads carries the label." % (sc["family"], sc["variant"], a, b))
    if sc["technique"] is None:
        scenario_note += (" No ATT&CK technique is claimed: a short burst/series of "
                          "packets does not on its own prove a DoS, so this is labelled "
                          "attack traffic by intent only.")

    meta = {
        # --- normalized NetDefend-Bench schema ---
        "scenario_id": sid,
        "family": sc["family"],
        "ground_truth": "ATTACK",
        "scenario_type": "CONTROLLED_LAB_TRAFFIC",
        "source_ip": src.IP(),
        "destination_ip": dst.IP() if sc["kind"] != "icmp_sweep" else None,
        "generator": "python3 + scapy %s (this script); standalone Open vSwitch bridge" % scapy_version,
        "tool": "Python 3 with Scapy" + (" and sockets" if sc["kind"] == "conn_series" else ""),
        "attack_technique": sc["technique"],
        "label_basis": "simulated by script; intent-labelled",
        "pcap_file": pcap_name,
        "evidence_file": evidence_name,
        "notes": scenario_note,
        # --- extra context (no ground truth) ---
        "destination_ips": params.get("targets"),
        "parameters": {k: v for k, v in params.items() if k != "targets"},
        "listener_on_victim": sc["listener"],
        # --- verification fields (kept) ---
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
    print("  %-26s pcap_verified=%s rules_verified=%s %s" % (sid, ok, rules_ok, "; ".join(verify_notes)))
    return meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="dataset/raw")
    ap.add_argument("--only", help="comma-separated scenario ids")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="keep scenarios even if iptables/nft output could not be captured")
    ap.add_argument("--worker")
    ap.add_argument("--src")
    ap.add_argument("--dst")
    ap.add_argument("--params", default="{}")
    args = ap.parse_args()

    if args.worker:
        worker_main(args)
        return

    if args.list:
        for sc in SCENARIOS:
            print("%-26s %-14s h%d -> h%d  technique=%s" % (
                sid_of(sc), sc["kind"], sc["pair"][0], sc["pair"][1], sc["technique"]))
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
            m = run_scenario(net, sc, args.outdir, script, args.allow_unverified, scapy.__version__)
            if m:
                results.append(m)
            time.sleep(1.0)
    finally:
        net.stop()

    bad = [m["scenario_id"] for m in results if not m["pcap_verified"]]
    unv = [m["scenario_id"] for m in results if not m["rules_verified"]]
    print("\ndone: %d scenarios written" % len(results))
    if bad:
        print("PCAP MISMATCH (do not use as labelled data until fixed): %s" % ", ".join(bad))
    if unv:
        print("RULES UNVERIFIED: %s" % ", ".join(unv))


if __name__ == "__main__":
    main()
