"""Evidence grounding utilities for v2 reasoning.

A hypothesis's cited evidence is "grounded" when the concrete values it quotes
(IP addresses, ports, counts, scores) actually appear in the incident evidence
bundle the hypothesis was built from. Ungrounded items -- ones that quote a
value absent from the bundle -- are the fabrication the grounding validator
exists to catch; they are dropped and counted.

This module is pure and deterministic (no LLM, no I/O), so it is unit-testable
with synthetic evidence. It is only consulted when reasoning v2 is active (see
agents/config.get_reasoning_version); v1 never calls it.
"""
import json
import re

# A distinctive value is an IPv4 address, or a number with >=2 digits or a
# decimal point. Single-digit integers (0, 1, 2) are too common to verify
# meaningfully, so an item quoting only those is treated as a general
# statement rather than a checkable value.
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_NUMBER = re.compile(r"\b\d+\.\d+\b|\b\d{2,}\b")

# Tokens that mark a line as a concrete configuration artifact: a firewall /
# ACL rule, a packet-filter log line, or a resolver / DNS setting.
_CONFIG_TOKENS = (
    "iptables", "nft", "chain", "policy", "-a ", "-j ", "drop", "reject",
    "accept", "dport", "--dport", "-p tcp", "-p udp", "pkts", "bytes",
    "nameserver", "resolver", "resolv", "forwarder", "forward", "server=",
    "ttl", "cache", "nxdomain", "servfail", "dns", "zone", "named",
    "route", "gateway", "nat", "masquerade", "denied", "blocked", "dropped",
)


def bundle_text(evidence_bundle) -> str:
    """Flatten the whole evidence bundle to one searchable string."""
    try:
        return json.dumps(evidence_bundle, default=str)
    except (TypeError, ValueError):
        return str(evidence_bundle)


def extract_quoted_values(item: str) -> list:
    """Distinctive values an evidence string quotes: IPv4 addresses and
    numbers with >=2 digits or a decimal point."""
    text = str(item)
    values = list(_IPV4.findall(text))
    # Remove IPs before scanning for bare numbers so an octet isn't double-counted.
    stripped = _IPV4.sub(" ", text)
    values.extend(_NUMBER.findall(stripped))
    # De-duplicate, preserve order.
    seen, out = set(), []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def item_is_grounded(item: str, bundle_str: str) -> bool:
    """An item is grounded unless it quotes a distinctive value (IP / multi-
    digit / decimal number) that does not appear anywhere in the bundle. An
    item that quotes no such value is not checkable and is kept."""
    for value in extract_quoted_values(item):
        if value not in bundle_str:
            return False
    return True


def validate_items(items, evidence_bundle):
    """Partition evidence items into grounded / dropped against the bundle.

    Returns (kept_items, dropped_count, dropped_items). An item is dropped
    only when it quotes a concrete value absent from the bundle.
    """
    bundle_str = bundle_text(evidence_bundle)
    kept, dropped = [], []
    for item in (items or []):
        if item_is_grounded(item, bundle_str):
            kept.append(item)
        else:
            dropped.append(item)
    return kept, len(dropped), dropped


def extract_config_artifacts(evidence_bundle) -> list:
    """Concrete configuration artifacts present in the bundle: non-trivial
    lines from log_evidence that read like a firewall rule, a packet-filter
    log line or a resolver/DNS setting, plus any configuration_evidence values.
    """
    artifacts = []

    cfg = (evidence_bundle or {}).get("configuration_evidence") or {}
    if isinstance(cfg, dict):
        for value in cfg.values():
            if value and str(value).strip():
                artifacts.append(str(value).strip())
    elif cfg:
        artifacts.append(str(cfg).strip())

    log = (evidence_bundle or {}).get("log_evidence") or {}
    raw = ""
    if isinstance(log, dict):
        raw = log.get("raw_log_excerpt") or ""
    elif log:
        raw = str(log)
    for line in str(raw).splitlines():
        s = line.strip()
        if not s:
            continue
        low = s.lower()
        if any(tok in low for tok in _CONFIG_TOKENS):
            artifacts.append(s)
    return artifacts


def cites_config_artifact(items, evidence_bundle) -> bool:
    """True when at least one cited evidence item references a concrete
    configuration artifact that is present in the bundle.

    An item references an artifact when it shares a distinctive value (IP /
    port / counter) with an artifact line, or itself reads like a firewall /
    resolver / DNS statement whose keywords appear in the bundle's artifacts.
    """
    artifacts = extract_config_artifacts(evidence_bundle)
    if not artifacts:
        return False
    artifact_blob = " \n ".join(artifacts).lower()

    for item in (items or []):
        text = str(item)
        low = text.lower()
        # (a) shares a distinctive value with an artifact line
        for value in extract_quoted_values(text):
            if value in artifact_blob:
                return True
        # (b) the item itself names a config/log/DNS artifact that the
        #     bundle's artifacts also contain
        for tok in _CONFIG_TOKENS:
            if tok in low and tok in artifact_blob:
                return True
    return False


def _log_raw(evidence_bundle) -> str:
    log = (evidence_bundle or {}).get("log_evidence") or {}
    if isinstance(log, dict):
        return log.get("raw_log_excerpt") or ""
    return str(log or "")


# Lines in a captured ruleset / log that are boilerplate, NOT configuration
# artifacts: default-ACCEPT policies, chain/column headers, command echoes,
# section headers and empty/no-match markers.
def _is_boilerplate(low: str) -> bool:
    if not low:
        return True
    if low.startswith("==="):
        return True
    if "] $ " in low or low.startswith("$ "):  # command echoes (incl. the
        return True                            # log-trail grep, whose pattern
        #                                        itself contains "SRC=...")
    if low in ("(empty)", "(no matching lines)"):
        return True
    if low.startswith(("-p input accept", "-p forward accept", "-p output accept")):
        return True
    if low.startswith("chain ") and "policy accept" in low:
        return True
    if low.startswith("pkts") and "target" in low:   # -L column header
        return True
    if low.startswith("table ") or low in ("{", "}") or low.endswith("{"):
        return True
    if low.startswith("type filter hook"):            # nft chain declaration
        return True
    if "resolver state" in low and "(" in low:        # the section label line
        return True
    return False


# Non-default resolver / DNS settings (the DNS misconfiguration signature).
_DNS_ARTIFACT_TOKENS = (
    "cache_enabled=false", "forward_mode=always_external", "nameserver",
    "forwarder", "server=", "named", "zone ",
    "total_queries_served=", "last_query_domain=",
)


def bundle_has_config_artifact(evidence_bundle) -> bool:
    """True when the evidence bundle itself contains a concrete configuration
    artifact: a custom firewall rule, a log / LOG-target line, a matched
    netfilter log entry, or a resolver/DNS setting beyond defaults.

    Deliberately scans the captured log/ruleset text, NOT the agent's cited
    evidence and NOT the synthetic "default ACCEPT only" statement -- a default
    ruleset with no custom rules and no resolver block returns False, so the
    misconfiguration hypothesis is nulled on a bundle that holds nothing for it
    to rest on.
    """
    for line in _log_raw(evidence_bundle).splitlines():
        s = line.strip()
        low = s.lower()
        if _is_boilerplate(low):
            continue

        # Custom firewall rule (iptables -S add line).
        if low.startswith("-a "):
            return True
        # iptables -L rule row carrying a target on a protocol.
        if any(t in low for t in (" drop ", " reject ", " log ", " log  ")) \
                and any(p in low for p in ("tcp", "udp", "icmp")):
            return True
        # nft rule line inside a chain (drop / reject / log / an actual match).
        if "meta l4proto" in low or "log prefix" in low \
                or ((low.endswith(" drop") or low.endswith(" reject"))
                    and ("saddr" in low or "dport" in low or "counter" in low)):
            return True
        # Explicit LOG target.
        if "-j log" in low or "log prefix" in low:
            return True
        # Matched netfilter log entry (not the "(no matching lines)" marker).
        if "src=" in low:
            return True
        # Non-default resolver / DNS setting.
        if any(tok in low for tok in _DNS_ARTIFACT_TOKENS):
            return True
    return False


def ruleset_has_no_custom_rules(evidence_bundle) -> bool:
    """True when the captured firewall ruleset in log_evidence shows only
    default-ACCEPT policies and no custom rules.

    Recognises iptables ("-S"/"-L") and nft output: every chain policy is
    ACCEPT and there is no rule-adding line ("-A ..."/"add rule"/a DROP/REJECT
    line). Conservative: returns False whenever a custom rule is seen or the
    log is empty/unrecognised, so the neutral statement is only emitted when
    the capture genuinely shows a default ruleset.
    """
    log = (evidence_bundle or {}).get("log_evidence") or {}
    raw = log.get("raw_log_excerpt") if isinstance(log, dict) else str(log or "")
    if not raw or not str(raw).strip():
        return False
    saw_policy = False
    for line in str(raw).splitlines():
        s = line.strip()
        low = s.lower()
        if not s:
            continue
        # A custom rule in any supported syntax -> not a default-only ruleset.
        if low.startswith("-a ") or low.startswith("add rule") or " -j drop" in low \
                or " -j reject" in low or low.startswith("iptables -a"):
            return False
        if ("drop" in low or "reject" in low) and ("chain" not in low):
            return False
        # Policy lines.
        if "policy accept" in low or low.startswith("-p accept") \
                or (low.startswith("chain ") and "accept" in low):
            saw_policy = True
        if "policy drop" in low or "policy reject" in low:
            return False
    return saw_policy
