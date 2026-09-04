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
