"""Runtime configuration flags for the NetDefend pipeline.

Currently holds the feature-version selector. v1 is the legacy behaviour that
produced the committed cache/results; v2 applies the feature-unit corrections
from the Intrusion Detection diagnosis (see feature_extractor.apply_feature_version).

The version is read from the NETDEFEND_FEATURE_VERSION environment variable so
it can be set per-process without touching code (and defaults to v1, so nothing
changes unless v2 is explicitly requested).
"""
import os

FEATURE_VERSIONS = ("v1", "v2")
DEFAULT_FEATURE_VERSION = "v1"

REASONING_VERSIONS = ("v1", "v2")
DEFAULT_REASONING_VERSION = "v1"


def get_feature_version() -> str:
    """Return the active feature version ('v1' or 'v2'); defaults to 'v1'."""
    v = os.environ.get("NETDEFEND_FEATURE_VERSION", DEFAULT_FEATURE_VERSION)
    v = (v or "").strip().lower()
    return "v2" if v == "v2" else "v1"


def get_reasoning_version() -> str:
    """Return the active reasoning version ('v1' or 'v2'); defaults to 'v1'.

    v1 is the committed, reproducible behaviour. v2 turns on the grounding
    validator, the misconfiguration null-hypothesis rule, the evidence-support
    adjudication rubric and the neutral default-ruleset statement. Read from
    NETDEFEND_REASONING_VERSION so it can be set per-process; off by default so
    nothing changes unless v2 reasoning is explicitly requested.
    """
    v = os.environ.get("NETDEFEND_REASONING_VERSION", DEFAULT_REASONING_VERSION)
    v = (v or "").strip().lower()
    return "v2" if v == "v2" else "v1"
