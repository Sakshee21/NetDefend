"""Thin wrapper around the Groq API, shared by every agent.

Kept as a single swappable function so agent modules never import the
groq SDK directly -- this is what makes them testable with a stub LLM
call and keeps a single place to change model/params. Groq (open-weight
Llama models), not a proprietary API -- see CLAUDE.md's "No Gemini or
other proprietary LLM APIs" project decision, which an earlier version
of this file violated by calling Gemini; that's fixed here.

Requires GROQ_API_KEY in the environment (the SDK picks it up
automatically -- Groq() needs no explicit key argument). Get a key at
https://console.groq.com/keys.

DEFAULT_MODEL reads MODEL_NAME_HEAVY from the environment, matching the
name already used in .env/.env.example. Falls back to
openai/gpt-oss-120b (Groq-hosted, open-weight despite the "openai/"
namespace) if that var isn't set -- CLAUDE.md names Llama 3.3, but that
model family is no longer available on Groq's catalog as of this
writing; update this default and .env(.example) together if that
changes.

.env is loaded right here, once, at import time -- nothing else in the
codebase calls load_dotenv(), and every agent that needs an LLM already
imports this module, so this is the one place that guarantees
GROQ_API_KEY (and anything else in .env) actually reaches os.environ
before Groq() reads it. dotenv_path is explicit rather than relying on
load_dotenv()'s cwd-search so this doesn't silently no-op depending on
where the process was launched from.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")


DEFAULT_MODEL = os.environ.get("MODEL_NAME_HEAVY", "openai/gpt-oss-120b")


def call_llm(prompt: str, system: Optional[str] = None, model: str = DEFAULT_MODEL) -> str:
    """Send a single-turn prompt to Groq and return the raw text response.

    Requires GROQ_API_KEY in the environment.
    """
    from groq import Groq

    client = Groq()  # reads GROQ_API_KEY from the environment

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    completion = client.chat.completions.create(model=model, messages=messages)
    return completion.choices[0].message.content or ""


def parse_json_response(raw: str) -> dict:
    """Best-effort JSON parse of an LLM response, tolerant of stray
    markdown code fences. Returns {} on failure rather than raising, so
    a malformed LLM response degrades gracefully instead of crashing
    the pipeline."""
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if "\n" in cleaned:
            cleaned = cleaned.split("\n", 1)[1]
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {}