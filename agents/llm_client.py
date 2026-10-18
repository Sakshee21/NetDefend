"""Thin wrapper around the Groq API, shared by every agent.

Kept as a single swappable function so agent modules never import the
groq SDK directly -- this is what makes them testable with a stub LLM
call and keeps a single place to change model/params. Groq (open-weight
Llama models), not a proprietary API -- see CLAUDE.md's "No Gemini or
other proprietary LLM APIs" project decision.

Requires GROQ_API_KEY in the environment (the SDK picks it up
automatically). .env is loaded here, once, at import time.

This module also provides, for the evaluation harness (experiments/):
  * telemetry -- per-call model, token usage and latency, drained by the
    harness around each agent (reset_telemetry / get_telemetry). Recording
    is always on; it is cheap and bounded by one run's call count.
  * repair_json / parse_json_response -- a STRUCTURAL-ONLY JSON repair
    (strip fences, drop trailing junk after a balanced close, close a
    single unterminated object/array -- nothing semantic) plus recovery of
    Groq's ``failed_generation`` body on a 400 json_validate_failed, so a
    response that is valid except for a stray brace is not thrown away.
  * rate-limit handling -- a requests/tokens-per-MINUTE 429 is retried with
    exponential backoff inside call_llm; a tokens-per-DAY 429 sets a flag
    (daily_token_budget_exceeded) and raises DailyTokenBudgetExceeded so the
    harness can stop cleanly and print a resume command.

None of this changes any prompt or the model.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")


DEFAULT_MODEL = os.environ.get("MODEL_NAME_HEAVY", "openai/gpt-oss-120b")

# Optional per-call completion cap (experiments --max-tokens). None => not sent,
# so default behaviour is byte-for-byte unchanged. Never caps the prompt.
_MAX_TOKENS: Optional[int] = None

# Minute-level 429 backoff.
_RPM_MAX_RETRIES = 5
_RPM_BASE_SLEEP_S = 2.0


def set_max_tokens(n: Optional[int]) -> None:
    global _MAX_TOKENS
    _MAX_TOKENS = n


# ----------------------------------------------------------------------------------
# Telemetry (for the evaluation harness)
# ----------------------------------------------------------------------------------
_TELEMETRY = {"calls": [], "parses": []}
_TPD_EXCEEDED = False


class DailyTokenBudgetExceeded(RuntimeError):
    """Raised when Groq reports a tokens-per-DAY 429. The harness stops
    cleanly; agents catch it like any other failure and fall back."""


def reset_telemetry() -> None:
    _TELEMETRY["calls"].clear()
    _TELEMETRY["parses"].clear()


def get_telemetry() -> dict:
    return {"calls": list(_TELEMETRY["calls"]), "parses": list(_TELEMETRY["parses"])}


def reset_tpd_flag() -> None:
    global _TPD_EXCEEDED
    _TPD_EXCEEDED = False


def daily_token_budget_exceeded() -> bool:
    return _TPD_EXCEEDED


def _is_per_day(exc) -> bool:
    msg = str(getattr(exc, "message", "") or exc).lower()
    return "per day" in msg or "tpd" in msg


def _extract_failed_generation(exc) -> Optional[str]:
    """Pull Groq's ``failed_generation`` out of a 400 error body, if present."""
    body = getattr(exc, "body", None)
    for src in (body, getattr(exc, "response", None)):
        if isinstance(src, dict):
            fg = src.get("error", {}).get("failed_generation")
            if fg:
                return fg
    # Some SDK versions expose .response with .json()
    resp = getattr(exc, "response", None)
    if resp is not None:
        try:
            data = resp.json()
            fg = data.get("error", {}).get("failed_generation")
            if fg:
                return fg
        except Exception:  # noqa: BLE001
            pass
    return None


def call_llm(
    prompt: str,
    system: Optional[str] = None,
    model: str = DEFAULT_MODEL,
    timeout: Optional[float] = None,
    json_mode: bool = False,
) -> str:
    """Send a single-turn prompt to Groq and return the raw text response.

    Behaviour for existing callers is unchanged: returns the model's text.
    Additions are transparent -- telemetry recording, minute-level 429
    backoff, and (on a 400 json_validate_failed) returning the recoverable
    ``failed_generation`` text instead of raising, so the caller's JSON parse
    can repair it. A day-level 429 raises DailyTokenBudgetExceeded.
    """
    from groq import Groq, RateLimitError, BadRequestError

    client = Groq(timeout=timeout) if timeout is not None else Groq()

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    kwargs = {"model": model, "messages": messages}
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}
    if _MAX_TOKENS is not None:
        kwargs["max_tokens"] = _MAX_TOKENS

    attempt = 0
    while True:
        t0 = time.time()
        try:
            completion = client.chat.completions.create(**kwargs)
        except RateLimitError as exc:
            global _TPD_EXCEEDED
            if _is_per_day(exc):
                _TPD_EXCEEDED = True
                _TELEMETRY["calls"].append({
                    "model": model, "prompt_tokens": 0, "completion_tokens": 0,
                    "latency_s": round(time.time() - t0, 3), "status": "tpd_429"})
                raise DailyTokenBudgetExceeded(str(getattr(exc, "message", exc))) from exc
            # minute-level: back off and retry
            attempt += 1
            _TELEMETRY["calls"].append({
                "model": model, "prompt_tokens": 0, "completion_tokens": 0,
                "latency_s": round(time.time() - t0, 3), "status": "rpm_429"})
            if attempt > _RPM_MAX_RETRIES:
                raise
            time.sleep(_RPM_BASE_SLEEP_S * (2 ** (attempt - 1)))
            continue
        except BadRequestError as exc:
            fg = _extract_failed_generation(exc)
            # completion tokens were generated even though validation failed;
            # estimate from the recovered text when usage is unavailable.
            est_completion = (len(fg) // 4) if fg else 0
            _TELEMETRY["calls"].append({
                "model": model, "prompt_tokens": None, "completion_tokens": est_completion,
                "latency_s": round(time.time() - t0, 3),
                "status": "json_validate_failed",
                "completion_tokens_estimated": True})
            if fg is not None:
                return fg  # let the caller's parser try a structural repair
            raise

        usage = getattr(completion, "usage", None)
        _TELEMETRY["calls"].append({
            "model": model,
            "prompt_tokens": getattr(usage, "prompt_tokens", None),
            "completion_tokens": getattr(usage, "completion_tokens", None),
            "latency_s": round(time.time() - t0, 3),
            "status": "ok"})
        return completion.choices[0].message.content or ""


# ----------------------------------------------------------------------------------
# JSON parsing with structural-only repair
# ----------------------------------------------------------------------------------
def _structural_repair(s: str) -> Optional[str]:
    """Return a structurally-balanced slice of s starting at its first
    JSON container, or None if there is none. Drops trailing junk after a
    balanced close; closes a single unterminated object/array. Never edits
    or invents keys/values."""
    starts = [i for i in (s.find("{"), s.find("[")) if i != -1]
    if not starts:
        return None
    start = min(starts)
    depth = 0
    instr = False
    esc = False
    stack = []
    closers = {"{": "}", "[": "]"}
    for i in range(start, len(s)):
        ch = s[i]
        if instr:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                instr = False
            continue
        if ch == '"':
            instr = True
        elif ch in "{[":
            stack.append(ch)
            depth += 1
        elif ch in "}]":
            if depth == 0:
                return s[start:i]  # stray close before any open: take prefix
            stack.pop()
            depth -= 1
            if depth == 0:
                return s[start:i + 1]  # balanced; trailing junk dropped
    # unterminated: close what is open (and any open string)
    tail = ('"' if instr else "") + "".join(closers[c] for c in reversed(stack))
    return s[start:] + tail


def repair_json(raw: str):
    """Best-effort structural JSON parse. Returns (obj_or_None, repaired_bool).
    repaired_bool is True when the raw text did not parse but a structural
    repair did."""
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if "\n" in cleaned:
            cleaned = cleaned.split("\n", 1)[1]
    cleaned = cleaned.strip()
    try:
        return json.loads(cleaned), False
    except json.JSONDecodeError:
        pass
    repaired = _structural_repair(cleaned)
    if repaired is not None and repaired != cleaned:
        try:
            return json.loads(repaired), True
        except json.JSONDecodeError:
            pass
    return None, False


def parse_json_response(raw: str) -> dict:
    """Best-effort JSON parse of an LLM response, tolerant of markdown
    fences and malformed-but-recoverable output (see repair_json). Returns
    {} on failure rather than raising. Records whether a repair was needed
    in telemetry so the harness can count it."""
    obj, repaired = repair_json(raw)
    _TELEMETRY["parses"].append({"ok": obj is not None, "repaired": bool(repaired)})
    return obj if obj is not None else {}
