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

---

## Setup Instructions

### 1. Clone the repository

```bash
git clone <repo-url>
cd NetDefend
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

### 4. Set up environment variables

```bash
cp .env.example .env
```

Then open `.env` and add your Groq API key:

```env
GROQ_API_KEY=your_key_here
```

> Get a free API key at [console.groq.com](https://console.groq.com)

### 5. Verify the setup

```bash
# Confirm PyShark can find Wireshark's tshark
python3 -c "import pyshark; print('pyshark ok')"

# Confirm Mininet works
sudo mn --test pingall
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

## Connecting the Frontend to the Backend

The dashboard currently returns mock data. All of it lives in
`frontend/src/api.js`, behind a single flag:

```js
export const USE_MOCK_API = true   // set to false to call FastAPI
```

With the flag set to `false`, `analyzeIncident()` sends `multipart/form-data` to
`POST /analyze` with the fields `pcap`, `router_log` and `firewall_log`, and
expects the incident JSON documented in **Final Incident Report Shape** in
`CLAUDE.md`. In development, Vite proxies `/analyze` to `http://127.0.0.1:8000`,
so the backend needs to listen on that port. Once `backend/main.py` defines the
FastAPI app, that means:

```bash
# from the repo root, with venv active
uvicorn backend.main:app --reload --port 8000
```

> `backend/main.py` is still an empty placeholder, so leave `USE_MOCK_API` set to
> `true` until the `/analyze` endpoint exists.

For a deployed build, set the API origin instead of relying on the proxy:

```bash
VITE_API_BASE_URL=https://your-backend-host npm run build
```

`fetchHistory()` and `fetchIncident(id)` in the same file are placeholders for
`GET /incidents` and `GET /incidents/{id}`, which the backend does not expose
yet. They follow the same pattern and go live with the same flag.

> Frontend file structure and component-level notes are documented separately in
> [`frontend/README.md`](frontend/README.md).
