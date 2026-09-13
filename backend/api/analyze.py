"""POST /analyze -- runs the real four-agent pipeline on an uploaded
PCAP + log file and returns their real output.

Scoped to exactly what's implemented right now: Packet Analysis,
Intrusion Detection, Threat Hunting, and Network Troubleshooting. The
Dialectical Arbiter and Incident Response Agent are still stubs (see
agents/arbiter.py, agents/response_agent.py) -- this deliberately never
touches final_report or arbiter_verdict, so their fabricated,
disconnected content can never reach a response from this endpoint.
Runs agents.graph.partial_app (the graph that stops right after the two
hypothesis agents) rather than the full app, for the same reason.
"""
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, HTTPException, UploadFile

from agents.graph import partial_app

router = APIRouter()


# Plain `def`, not `async def`: FastAPI runs sync path operations in a
# worker thread automatically, which matters here because
# partial_app.invoke() below is a blocking call that can run for many
# seconds (real LLM calls to Groq/Ollama) -- an async def would block
# the whole event loop, and every other request, for that entire time.
# UploadFile.file is a plain synchronous file-like object, so no `await`
# is needed to read it in this style.
@router.post("/analyze")
def analyze(
    pcap: UploadFile = File(...),
    router_log: Optional[UploadFile] = File(None),
    firewall_log: Optional[UploadFile] = File(None),
):
    """Save the uploaded files, run the real pipeline, and shape its
    output into the two-independent-hypotheses response the frontend's
    partial view (see frontend/src/components/HypothesesView.jsx)
    expects.
    """
    # NetDefendState carries a single log_path, not one per log type (see
    # agents/state_schema.py) -- only one log file reaches the pipeline
    # for now. Prefer the firewall log when both are uploaded, since
    # every scenario script under mininet/scenarios/ produces a
    # firewall-style log; fall back to the router log, or none.
    log_file = firewall_log or router_log

    # Diagnostic logging: prints exactly what this request actually
    # carried, so a report of "works with hardcoded paths but not
    # through the browser" is instantly checkable against the real
    # server console next time, instead of re-guessing from outside.
    print(f"[POST /analyze] pcap received: filename={pcap.filename!r}")
    print(f"[POST /analyze] router_log received: "
          f"{(router_log.filename if router_log else 'not provided')!r}")
    print(f"[POST /analyze] firewall_log received: "
          f"{(firewall_log.filename if firewall_log else 'not provided')!r}")

    try:
        with tempfile.TemporaryDirectory(prefix="netdefend_analyze_") as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Defensive seek(0): UploadFile.file is a SpooledTemporaryFile:
            # reading it should already start at position 0 for a fresh
            # upload, but seeking explicitly costs nothing and removes any
            # doubt if something upstream ever advances the cursor first.
            pcap.file.seek(0)
            pcap_path = tmp_path / (pcap.filename or "upload.pcap")
            pcap_bytes = pcap.file.read()
            pcap_path.write_bytes(pcap_bytes)
            print(f"[POST /analyze] saved pcap to {pcap_path} ({len(pcap_bytes)} bytes)")

            log_path = ""
            if log_file is not None:
                log_file.file.seek(0)
                log_dest = tmp_path / (log_file.filename or "upload.log")
                log_bytes = log_file.file.read()
                log_dest.write_bytes(log_bytes)
                log_path = str(log_dest)
                print(f"[POST /analyze] saved log to {log_path} ({len(log_bytes)} bytes)")
            else:
                print("[POST /analyze] no log file attached to this request "
                      "-- log_path will be empty, and the Troubleshooting "
                      "Agent will have no log_evidence to reason from")

            # The pipeline reads these files from disk while still inside
            # the TemporaryDirectory context, so invoke() must happen
            # before the directory (and the files in it) get cleaned up.
            result = partial_app.invoke({
                "pcap_path": str(pcap_path),
                "log_path": log_path,
            })
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 -- surface a clear 500, never crash silently
        raise HTTPException(
            status_code=500,
            detail=f"Pipeline failed: {exc}",
        ) from exc

    threat_hypothesis = result.get("threat_hypothesis") or {}
    misconfig_hypothesis = result.get("misconfig_hypothesis") or {}

    return {
        "packet_features": result.get("packet_features"),
        "ml_prediction": result.get("ml_prediction"),
        "threat_hypothesis": {
            "ttp_id": result.get("ttp_id"),
            "confidence": result.get("ttp_confidence"),
            "mapping_method": result.get("ttp_mapping_method"),
            # If Ollama/Groq are unreachable, this flows through as True
            # honestly -- it is NOT hidden or swapped for fake-confident
            # output. See agents/threat_agent.py's _resolve_ttp().
            "llm_call_failed": result.get("llm_call_failed", False),
            "summary": threat_hypothesis.get("summary"),
            "evidence": threat_hypothesis.get("evidence", []),
        },
        "misconfig_hypothesis": {
            "is_misconfiguration": result.get("is_misconfiguration"),
            "reasoning": result.get("misconfig_reasoning"),
            "summary": misconfig_hypothesis.get("summary"),
            "taxonomy_category": misconfig_hypothesis.get("taxonomy_category"),
            "evidence": misconfig_hypothesis.get("evidence", []),
        },
        "note": (
            "Dialectical Arbiter and Incident Response Agent are not yet "
            "implemented — this response shows the two competing "
            "hypotheses independently, not a resolved final verdict."
        ),
    }
