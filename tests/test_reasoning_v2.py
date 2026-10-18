"""v2 reasoning tests -- grounding validator, null misconfiguration rule,
UDP port-scan ATT&CK lookup and neutral default-ruleset detection.

All inputs are synthetic; no Groq / LLM calls and no scenario data are used.

Run: ./venv/bin/python tests/test_reasoning_v2.py
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from agents import grounding                              # noqa: E402
from agents.troubleshooting_agent import (                # noqa: E402
    _apply_v2_reasoning, NO_MISCONFIG_EVIDENCE)
from knowledge.mitre.lookup import lookup_ttp, _match_cross_flow  # noqa: E402


# A synthetic incident evidence bundle: one firewall DROP rule in the log,
# a destination 10.0.0.2:8000, and 30 distinct scanned ports cross-flow.
BUNDLE = {
    "network_observation": {
        "representative_flow": {"syn_count": 2, "destination_port": 8000},
        "capture_wide": {"flow_count": 31},
    },
    "cross_flow_evidence": {"distinct_dst_ports": 30, "distinct_dst_hosts": 1},
    "ml_evidence": {"random_forest": {"attack_probability": 0.21}},
    "configuration_evidence": {},
    "log_evidence": {
        "raw_log_excerpt": (
            "Chain INPUT (policy ACCEPT)\n"
            "-A INPUT -s 10.0.0.1/32 -p tcp --dport 8000 -j DROP\n"
            "pkts 20 bytes 1200\n"
        )
    },
    "context": {"destination_port": 8000},
}


# ----------------------------------------------------------------- validator
def test_validator_keeps_grounded_items():
    items = [
        "Firewall DROP rule targets destination port 8000",   # 8000 in bundle
        "Source 10.0.0.1 is denied by the rule",              # 10.0.0.1 in bundle
    ]
    kept, dropped_n, dropped = grounding.validate_items(items, BUNDLE)
    assert dropped_n == 0, dropped
    assert kept == items


def test_validator_drops_ungrounded_items():
    items = [
        "Firewall DROP rule on port 8000",                    # grounded
        "Observed 4096 SYN packets to port 9999",             # 4096, 9999 absent
        "Attacker 203.0.113.55 scanned the host",             # IP absent
    ]
    kept, dropped_n, dropped = grounding.validate_items(items, BUNDLE)
    assert dropped_n == 2, dropped
    assert "Firewall DROP rule on port 8000" in kept
    assert all("4096" not in k and "203.0.113.55" not in k for k in kept)


def test_validator_keeps_unquoted_general_statements():
    # No distinctive value quoted -> not checkable -> kept.
    items = ["The resolver stopped answering queries"]
    kept, dropped_n, _ = grounding.validate_items(items, BUNDLE)
    assert dropped_n == 0 and kept == items


# --------------------------------------------------------- null-hypothesis rule
def _misconfig_result(evidence):
    return {
        "is_misconfiguration": 0.7,
        "misconfig_reasoning": "synthetic",
        "misconfig_hypothesis": {
            "summary": "ACL drop blocks the service",
            "taxonomy_category": "ACL_FIREWALL",
            "evidence": list(evidence),
        },
    }


def test_null_rule_keeps_hypothesis_citing_config_artifact():
    # Cites the DROP rule / port 8000 present in the bundle -> stays MISCONFIGURATION.
    res = _misconfig_result([
        "The firewall DROP rule on port 8000 explains the blocked traffic",
    ])
    out = _apply_v2_reasoning(res, "MISCONFIGURATION", BUNDLE)
    mh = out["misconfig_hypothesis"]
    assert mh["taxonomy_category"] == "ACL_FIREWALL"
    assert not mh.get("null_hypothesis")
    assert out["misconfig_grounding"]["null_hypothesis"] is False
    assert out["is_misconfiguration"] == 0.7


# A bundle whose captured ruleset is default-ACCEPT only (no custom rule, no
# resolver block) -- the attack-scenario shape.
EMPTY_BUNDLE = {
    "configuration_evidence": {"firewall_ruleset": "default ACCEPT only, no custom rules"},
    "log_evidence": {"raw_log_excerpt": (
        "=== Host firewall rules and INPUT counters ===\n"
        "[h3 10.0.0.3] $ /usr/sbin/iptables -S  (exit 0)\n"
        "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
        "[h3 10.0.0.3] $ /usr/sbin/nft list ruleset  (exit 0)\n(empty)\n"
        "=== Kernel netfilter log-trail check ===\n"
        "$ dmesg | grep -iE 'SRC=10.0.0.3'\n(no matching lines)\n")},
}

# A bundle whose captured state carries a non-default resolver setting but a
# default-ACCEPT firewall -- the dns_misconfig shape.
DNS_BUNDLE = {
    "configuration_evidence": {"firewall_ruleset": "default ACCEPT only, no custom rules"},
    "log_evidence": {"raw_log_excerpt": (
        "=== Host firewall rules and INPUT counters ===\n"
        "[h1 10.0.0.1] $ /usr/sbin/iptables -S  (exit 0)\n"
        "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"
        "=== Local DNS resolver state (before and after traffic) ===\n"
        "resolver state (before traffic):\n"
        "cache_enabled=false\nforward_mode=always_external\n"
        "total_queries_served=0\n"
        "resolver state (after traffic):\n"
        "cache_enabled=false\nforward_mode=always_external\n"
        "total_queries_served=18\nlast_query_domain=example.com\n")},
}


def test_bundle_artifact_detection():
    assert grounding.bundle_has_config_artifact(BUNDLE) is True        # DROP rule
    assert grounding.bundle_has_config_artifact(DNS_BUNDLE) is True    # resolver
    assert grounding.bundle_has_config_artifact(EMPTY_BUNDLE) is False # default only


def test_empty_ruleset_bundle_nulls_even_misconfiguration_claim():
    # Agent claims MISCONFIGURATION but the bundle has no artifact -> null.
    res = _misconfig_result([
        "The service appears blocked by a configuration issue",
    ])
    out = _apply_v2_reasoning(res, "MISCONFIGURATION", EMPTY_BUNDLE)
    mh = out["misconfig_hypothesis"]
    assert mh["null_hypothesis"] is True
    assert mh["taxonomy_category"] == NO_MISCONFIG_EVIDENCE
    assert out["is_misconfiguration"] == 0.0
    assert out["misconfig_grounding"]["null_hypothesis"] is True


def test_dns_shaped_bundle_no_clear_is_not_nulled():
    # dns_misconfig shape: resolver artifact present, agent returns
    # NO_CLEAR_MISCONFIGURATION -> NOT null; the debate runs as in v1.
    res = {
        "is_misconfiguration": 0.4,
        "misconfig_reasoning": "synthetic",
        "misconfig_hypothesis": {
            "summary": "No clear misconfiguration",
            "taxonomy_category": "NONE",
            "evidence": ["Resolver cache_enabled=false, forward_mode=always_external"],
        },
    }
    out = _apply_v2_reasoning(res, "NO_CLEAR_MISCONFIGURATION", DNS_BUNDLE)
    mh = out["misconfig_hypothesis"]
    assert mh.get("null_hypothesis") is not True
    assert out["misconfig_grounding"]["null_hypothesis"] is False


def test_artifact_bundle_uncertain_is_not_nulled():
    # Bundle has a custom rule (BUNDLE), agent returns UNCERTAIN -> NOT null.
    res = {
        "is_misconfiguration": 0.5,
        "misconfig_reasoning": "synthetic",
        "misconfig_hypothesis": {
            "summary": "Did not clearly resolve",
            "taxonomy_category": "NONE",
            "evidence": [],
        },
    }
    out = _apply_v2_reasoning(res, "UNCERTAIN", BUNDLE)
    assert out["misconfig_grounding"]["null_hypothesis"] is False


def test_null_rule_counts_dropped_evidence_and_flags():
    # One grounded config citation + one fabricated citation -> dropped=1, flagged.
    res = _misconfig_result([
        "DROP rule on port 8000 blocks it",                # grounded config artifact
        "9999 blocked SYNs were logged",                   # 9999 absent -> dropped
    ])
    out = _apply_v2_reasoning(res, "MISCONFIGURATION", BUNDLE)
    g = out["misconfig_grounding"]
    assert g["evidence_dropped"] == 1
    assert g["flagged"] is True
    # Still cites a real config artifact -> not null.
    assert out["misconfig_hypothesis"].get("null_hypothesis") is not True


def test_dropped_items_text_is_persisted():
    # The verbatim text of each dropped item is recorded, not just the count.
    res = _misconfig_result([
        "DROP rule on port 8000 blocks it",                # grounded -> kept
        "9999 blocked SYNs were logged",                   # ungrounded -> dropped
        "attacker 203.0.113.55 scanned the host",          # ungrounded -> dropped
    ])
    out = _apply_v2_reasoning(res, "MISCONFIGURATION", BUNDLE)
    g = out["misconfig_grounding"]
    assert g["evidence_dropped"] == 2
    assert g["dropped_items"] == [
        "9999 blocked SYNs were logged",
        "attacker 203.0.113.55 scanned the host",
    ]
    # Counts stay; the kept item is no longer in dropped_items.
    assert "DROP rule on port 8000 blocks it" not in g["dropped_items"]


# --------------------------------------------------------------- UDP scan lookup
def test_udp_scan_cross_flow_maps_to_t1046():
    cf = {"distinct_dst_ports": 30, "distinct_dst_hosts": 1,
          "total_syn_count": 0, "total_synack_count": 0}
    m = _match_cross_flow(cf)
    assert m and m["ttp_id"] == "T1046"
    assert m["mapping_method"] == "cross_flow_heuristic"
    # Via the public entry point (benign ML, empty single flow, scan cross-flow).
    full = lookup_ttp({"predicted_class": "Benign"}, {"protocol": 17}, cross_flow=cf)
    assert full and full["ttp_id"] == "T1046"


def test_cross_flow_not_applied_without_flag_arg():
    # v1 behaviour: no cross_flow passed -> scan pattern not used.
    assert lookup_ttp({"predicted_class": "Benign"}, {"protocol": 17}) is None


def test_cross_flow_ignores_few_ports_or_tcp_flags():
    assert _match_cross_flow({"distinct_dst_ports": 3, "distinct_dst_hosts": 1,
                              "total_syn_count": 0, "total_synack_count": 0}) is None
    assert _match_cross_flow({"distinct_dst_ports": 30, "distinct_dst_hosts": 1,
                              "total_syn_count": 12, "total_synack_count": 0}) is None


# ------------------------------------------------------- default-ruleset detect
def test_default_accept_ruleset_detected():
    b = {"log_evidence": {"raw_log_excerpt":
         "Chain INPUT (policy ACCEPT)\nChain FORWARD (policy ACCEPT)\n"}}
    assert grounding.ruleset_has_no_custom_rules(b) is True


def test_custom_rule_is_not_default():
    assert grounding.ruleset_has_no_custom_rules(BUNDLE) is False
    assert grounding.ruleset_has_no_custom_rules(
        {"log_evidence": {"raw_log_excerpt": ""}}) is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print("PASS", fn.__name__)
            passed += 1
        except AssertionError as e:
            print("FAIL", fn.__name__, "--", e)
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
