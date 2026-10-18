from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agents.config import get_feature_version, get_reasoning_version
from backend.api.analyze import router as analyze_router

# Versions are read from the environment ONLY (NETDEFEND_FEATURE_VERSION /
# NETDEFEND_REASONING_VERSION); the default stays v1. Print the active versions
# at server start so the demo makes clear which pipeline is running.
print("[NetDefend API] active pipeline versions: "
      f"feature={get_feature_version()} reasoning={get_reasoning_version()}")

app = FastAPI(title="NetDefend API")


@app.on_event("startup")
def _log_versions() -> None:
    print("[NetDefend API] startup -- feature_version="
          f"{get_feature_version()} reasoning_version={get_reasoning_version()}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
