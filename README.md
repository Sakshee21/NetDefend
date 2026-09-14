# NetDefend — Multi-Agent Network Attack vs. Misconfiguration Detection

A multi-agent system that determines, for a given network anomaly, whether it is caused by a genuine attack or an operator misconfiguration — using a Dialectical Arbiter to resolve conflicting evidence between competing hypotheses.

---

## Prerequisites (Install Once, System-Level)

Before setting up the project, install these on your machine:

**Wireshark / tshark** (required for PyShark)
```bash
sudo apt update
sudo apt install wireshark tshark -y
```
> During install, select **Yes** when asked to allow non-superusers to capture packets.

**Mininet**
```bash
sudo apt install mininet -y
```

**Python 3.10 or 3.11**
```bash
python3 --version   # confirm 3.10+
```

**Node.js 18+** (required for the React dashboard)
```bash
sudo apt install nodejs npm -y
node --version      # confirm 18+
```

**Git LFS** (required to actually get the trained models)
```bash
sudo apt install git-lfs -y
git lfs install
```
> The five `.joblib` files under `ml/models/` (Random Forest, Isolation
> Forest, and their encoders/scaler) are tracked with Git LFS. Without this
> installed *before* you clone, you'll get 100-byte pointer files instead of
> the real models, and the Intrusion Detection Agent will fail to load them.
> If you already cloned without it, run `git lfs pull` afterward to fetch
> the real files.

**Ollama** (required for the Network Troubleshooting Agent)
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b
```
> The Troubleshooting Agent calls a local Ollama model, not Groq — see
> **LLM setup** below for why the two agents use different providers.
> Without Ollama running, that agent still returns a real, honestly-labeled
> result (`taxonomy_category: "OLLAMA_UNAVAILABLE"`), it just won't be a
> real analysis.

---

## Setup Instructions

### 1. Clone the repository

```bash
git clone <repo-url>
cd NetDefend
git lfs pull    # fetches the real ml/models/*.joblib files, not just pointers
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up environment variables and LLM access

```bash
cp .env.example .env
```

Then open `.env` and add your Groq API key:

```env
GROQ_API_KEY=your_key_here
```

> Get a free API key at [console.groq.com](https://console.groq.com/keys).
> **LLM setup, split across two agents, on purpose:** the Threat Hunting
> Agent (`agents/llm_client.py`) calls Groq — open-weight models, not a
> proprietary API, per the reproducibility constraint in `CLAUDE.md`. The
> Network Troubleshooting Agent (`agents/troubleshooting_agent.py`) calls a
> **local Ollama** model instead (`qwen2.5:7b`, see Prerequisites above),
> so you need both a Groq key *and* Ollama running for both agents to
> produce real output.
>
> `MODEL_NAME_HEAVY`/`MODEL_NAME_LIGHT` in `.env.example` are Groq model
> IDs. Groq's catalog moves fast — if `openai/gpt-oss-120b` ever 404s,
> run `python3 -c "from groq import Groq; [print(m.id) for m in Groq().models.list().data]"`
> to see what's currently available on your key and update `.env`.

### 5. Verify the setup

```bash
# Confirm PyShark can find Wireshark's tshark
python3 -c "import pyshark; print('pyshark ok')"

# Confirm Mininet works
sudo mn --test pingall

# Confirm Groq is reachable with your key
python3 -c "from agents.llm_client import call_llm; print(call_llm('Reply with exactly: OK'))"

# Confirm Ollama is running and the model is pulled
curl -s http://localhost:11434/api/tags | grep qwen2.5
```

---

## Running the Frontend (React Dashboard)

The dashboard runs standalone. It ships with mocked API responses, so you do not
need the backend running to develop or demo it.

### 1. Install frontend dependencies

```bash
cd frontend
npm install
```

> **On Windows with the repo inside WSL:** run `npm` from inside WSL, not from
> PowerShell or Git Bash. Windows `npm` cannot execute the esbuild postinstall
> script when the working directory is a `\\wsl.localhost\...` UNC path, and the
> install fails with `Cannot find module 'C:\Windows\install.js'`.

### 2. Start the dev server

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). Click **Load sample
evidence** on the upload screen to run the pipeline end to end without supplying
real files.

### 3. Build for production

```bash
npm run build     # bundles into frontend/dist/
npm run preview   # serves the built bundle locally
```

---

## Running the Real Pipeline

There are three ways to actually run this, from quickest to most complete.

### Option A — just the pipeline, no servers

The fastest way to see real agent output without touching the frontend or
backend at all:

```bash
python -m agents.test_pipeline
```

This runs `agents.graph.partial_app` — Packet Analysis, Intrusion Detection,
Threat Hunting, and Network Troubleshooting, in that order, fanning out the
last two in parallel. It deliberately **stops there**: the Dialectical
Arbiter and Incident Response Agent (`agents/arbiter.py`,
`agents/response_agent.py`) are still stubs that return fixed content
disconnected from the real evidence, so this never runs them. You'll see the
full state dict printed, including `cross_flow_pattern` (repeated-attempt
evidence aggregated across every flow, not just the one representative flow
`packet_features` describes) and each agent's real reasoning.

It points at `dataset/raw/acl_misconfig.pcap` by default. See **Sample
data** below for where that file comes from.

### Option B — the backend API directly

```bash
# from the repo root, with venv active
uvicorn backend.main:app --reload --port 8000
```

`POST /analyze` (`backend/api/analyze.py`) accepts a multipart upload —
`pcap` (required), plus `router_log` and/or `firewall_log` (optional; if
both are given, the firewall log wins). It saves them to a temp directory,
runs the same `partial_app` Option A uses, and returns the two hypotheses
independently:

```json
{
  "packet_features": { ... },
  "ml_prediction": { ... },
  "threat_hypothesis": { "ttp_id": ..., "confidence": ..., "summary": ..., "evidence": [...] },
  "misconfig_hypothesis": { "is_misconfiguration": ..., "reasoning": ..., "summary": ..., "evidence": [...] },
  "note": "Dialectical Arbiter and Incident Response Agent are not yet implemented ..."
}
```

This is **not** the `Final Incident Report Shape` documented in `CLAUDE.md`
— that shape needs a real Arbiter verdict, which doesn't exist yet. Try it
with curl:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -F "pcap=@dataset/raw/acl_misconfig.pcap" \
  -F "firewall_log=@dataset/raw/acl_misconfig_firewall.log"
```

### Option C — the full dashboard

All of the above, through the actual UI. `frontend/src/api.js` gates
everything behind one flag:

```js
export const USE_MOCK_API = true   // set to false to call the real backend
```

With it set to `false` and the backend running (Option B), Vite proxies
`/analyze` to `http://127.0.0.1:8000` in development:

```bash
cd frontend
npm run dev
```

Upload a real PCAP and log through the UI and you'll land on a "Competing
hypotheses" view instead of the mock's full debate + verdict — two cards,
same thesis/antithesis styling, no refutation exchange or verdict badge,
with a banner explaining why. That's `HypothesesView.jsx`; the mock flow
still renders the full `DialecticalDebate.jsx` as before. **Don't** click
"Load sample evidence" once `USE_MOCK_API` is `false` — it generates fake
placeholder files client-side (a few zero-bytes each), not real capture
data, so you'll get a real but meaningless response. Upload the files
under `dataset/raw/` instead (see below).

For a deployed build, set the API origin instead of relying on the proxy:

```bash
VITE_API_BASE_URL=https://your-backend-host npm run build
```

`fetchHistory()` and `fetchIncident(id)` in `api.js` are placeholders for
`GET /incidents` and `GET /incidents/{id}`, which the backend does not
expose yet. They follow the same pattern and go live with the same flag.

> Frontend file structure and component-level notes are documented separately in
> [`frontend/README.md`](frontend/README.md).

---

## Sample Data

`dataset/raw/` is gitignored — raw captures and logs never get committed
(see `CLAUDE.md`). To get real evidence to test with, generate it yourself
with the Mininet scenario scripts under `mininet/scenarios/`:

```bash
sudo python3 mininet/scenarios/acl_misconfig.py
sudo python3 mininet/scenarios/dns_misconfig.py
sudo python3 mininet/scenarios/disabled_logging_misconfig.py
```

Each one builds a two-host Mininet topology, generates real traffic against
a deliberately misconfigured firewall or resolver, and writes a `.pcap`, a
counter/evidence log, and a ground-truth `_metadata.json` into
`dataset/raw/`. They need `sudo` (a Mininet requirement) and take under a
minute each. `acl_misconfig.pcap` + `acl_misconfig_firewall.log` are what
Option A defaults to and what the curl example above uses.
