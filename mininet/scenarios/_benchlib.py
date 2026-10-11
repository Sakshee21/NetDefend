"""Shared constants and evidence capture for the NetDefend-Bench generators.

Imported by generate_attack_scenarios.py and the three *_misconfig.py
generators. Each is run as `python <path>/<script>.py`, so this module's own
directory is sys.path[0] and a bare `import _benchlib` resolves it.

Two shared pieces:

1. PAIR_POOL — the attack AND misconfig generators draw host pairs from the
   SAME set, so the source/destination IP pair never predicts the label.

2. Evidence capture — EVERY scenario (attack or misconfiguration) writes its
   fed evidence file from the same helpers here, in the same section format,
   using RAW tool output only. This keeps the evidence label-neutral (no
   verdict words, no scenario/family names, no source-file references) and
   structurally uniform, so neither the wording nor the shape of the evidence
   leaks the ground-truth label into an agent prompt. The ground truth lives
   only in *_metadata.json, which no agent ever reads.
"""
import re

N_HOSTS = 10

# name -> (attacker/source host index, victim/destination host index)
PAIR_POOL = {"A": (1, 2), "B": (3, 4), "C": (5, 6)}

# Convenience aliases for the attack generator's scenario table.
PAIR_A = PAIR_POOL["A"]
PAIR_B = PAIR_POOL["B"]
PAIR_C = PAIR_POOL["C"]


def ip_of(n):
    """Host index -> its 10.0.0.0/24 address."""
    return "10.0.0.%d" % n


# ----------------------------------------------------------------------------------
# Raw tool runner (absolute path first, bare name as fallback)
# ----------------------------------------------------------------------------------
# Mininet's Host.cmd does not always run with /usr/sbin on PATH (a capture
# shared with us came back "iptables: command not found"), so every tool is
# tried at its absolute path first and only falls back to the bare name.
_RULE_TOOLS = [
    ("iptables -S", ("/usr/sbin/iptables -S", "iptables -S")),
    ("iptables -L INPUT -v -n -x", ("/usr/sbin/iptables -L INPUT -v -n -x",
                                     "iptables -L INPUT -v -n -x")),
    ("nft list ruleset", ("/usr/sbin/nft list ruleset", "nft list ruleset")),
]


def run_tool(host, variants):
    """Run the first working command variant on a Mininet host.

    Returns (used_cmd, exit_code, body) for the first variant that exits 0,
    else the last variant tried. Body is the raw tool output (stderr merged).

    code == -1 means the trailing `__EXIT:<n>` marker could not be parsed --
    which happens when Host.cmd desyncs (e.g. a stray job-control message from
    a just-killed background process lands in the buffer). That clears after
    one command, so each variant is retried once on a -1 before giving up.
    """
    used, code, body = variants[-1], -1, ""
    for cmd in variants:
        for _attempt in range(2):
            out = host.cmd("%s 2>&1; echo __EXIT:$?" % cmd)
            m = re.search(r"__EXIT:(-?\d+)\s*$", out.strip())
            code = int(m.group(1)) if m else -1
            body = (out[:m.start()] if m else out).strip()
            used = cmd
            if code != -1:
                break
        if code == 0:
            break
    return used, code, body


def capture_rule_sections(hosts):
    """Raw firewall/nft tool output from each host, label-neutral.

    Runs `iptables -S`, `iptables -L INPUT -v -n -x` (exact counters) and
    `nft list ruleset` on every host and concatenates the raw output. Returns
    (text, all_verified, restrictive_found):
      * all_verified   -- every host produced usable output for every tool
      * restrictive    -- a DROP/REJECT rule was seen on some host
    """
    blocks = []
    all_ok = True
    restrictive = False
    for h in hosts:
        host_ok = True
        for _label, variants in _RULE_TOOLS:
            used, code, body = run_tool(h, variants)
            blocks.append("[%s %s] $ %s  (exit %d)\n%s"
                          % (h.name, h.IP(), used, code, body if body else "(empty)"))
            if code != 0:
                host_ok = False
            elif re.search(r"\b(DROP|REJECT)\b", body):
                restrictive = True
        if not host_ok:
            all_ok = False
    return "\n\n".join(blocks), all_ok, restrictive


def capture_log_trail(victim, src_ip):
    """Raw dmesg/journalctl output for traffic from src_ip on the victim host.

    This is the same check for every scenario: it shows whether the kernel
    emitted any netfilter LOG entries for this source. Presence or absence is
    a fact the agent may reason from; the helper itself writes no conclusion.
    """
    pat = "SRC=%s" % src_ip
    dmesg = victim.cmd("dmesg 2>&1 | grep -iE '%s' || true" % pat).strip()
    journal = victim.cmd("journalctl -k --no-pager -n 200 2>&1 | grep -iE '%s' || true"
                         % pat).strip()
    return ("$ dmesg | grep -iE '%s'\n%s\n\n"
            "$ journalctl -k --no-pager -n 200 | grep -iE '%s'\n%s"
            % (pat, dmesg or "(no matching lines)", pat, journal or "(no matching lines)"))


def parse_input_counter(rule_text, target, dport):
    """Pull the packet count for an INPUT rule out of raw
    `iptables -L INPUT -v -n -x` output (first column), matching rows whose
    target and `dpt:<dport>` both appear. Returns an int (0 if not found).

    Used only to set the metadata pcap_verified boolean; never written into
    any evidence file.
    """
    want_dpt = "dpt:%s" % dport
    for line in rule_text.splitlines():
        parts = line.split()
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        if parts[2] == target and want_dpt in line:
            return int(parts[0])
    return 0


def build_evidence(sections):
    """Format a list of (header, body) into a neutral evidence file.

    Headers are plain operator-log section titles; bodies are raw tool output.
    No verdict words, no scenario names.
    """
    out = []
    for header, body in sections:
        out.append("=== %s ===" % header)
        out.append(body.rstrip() if (body and body.strip()) else "(none)")
        out.append("")
    return "\n".join(out).rstrip() + "\n"
