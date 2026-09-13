"""Thin wrapper around the Gemini API, shared by every agent.

Kept as a single swappable function so agent modules never import the
google-genai SDK directly -- this is what makes them testable with a
stub LLM call and keeps a single place to change model/params.

Requires GEMINI_API_KEY in the environment (the SDK picks it up
automatically -- genai.Client() needs no explicit key argument).
Get a key at https://aistudio.google.com/apikey.
"""

from __future__ import annotations

import json
from typing import Optional


DEFAULT_MODEL = "gemini-3.8-flash"


def call_llm(prompt: str, system: Optional[str] = None, model: str = DEFAULT_MODEL) -> str:
    """Send a single-turn prompt to Gemini and return the raw text response.

    Requires GEMINI_API_KEY in the environment.
    """
    from google import genai

    client = genai.Client()  # reads GEMINI_API_KEY from the environment

    kwargs = {"model": model, "input": prompt}
    if system:
        kwargs["system_instruction"] = system

    interaction = client.interactions.create(**kwargs)
    return interaction.output_text or ""


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