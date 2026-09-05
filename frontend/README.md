# NetDefend — Frontend

Dark SOC console for the NetDefend multi-agent pipeline. Vite + React 18, plain
CSS, no UI framework.

## Running

The project lives on a WSL filesystem, so run npm from inside WSL. Windows npm
cannot execute the esbuild postinstall script over a UNC path.

```bash
cd /home/sakshee/NetDefend/frontend
npm install
npm run dev      # http://localhost:5173
npm run build    # production bundle into dist/
```

## File structure

```
frontend/
├── index.html
├── vite.config.js          proxies /analyze to 127.0.0.1:8000 for the live backend
├── public/shield.svg       favicon
└── src/
    ├── main.jsx            React root
    ├── App.jsx             shell, view routing, pipeline run orchestration
    ├── api.js              analyzeIncident() + all mock data  <-- swap point
    ├── components/
    │   ├── FileUpload.jsx / .css        PCAP dropzone, router + firewall log inputs
    │   ├── AgentPipeline.jsx / .css     six agents, parallel branch, agent trace log
    │   ├── DialecticalDebate.jsx / .css thesis vs antithesis, refutation thread, verdict
    │   ├── IncidentReport.jsx / .css    summary card, evidence, recommended action
    │   └── HistoryList.jsx / .css       past analyses sidebar
    ├── lib/
    │   ├── format.js       timestamp, percentage, byte and agent-identity helpers
    │   └── icons.jsx       inline SVG icon set
    └── styles/
        ├── tokens.css      palette, typography, shared primitives, grid texture
        └── app.css         sidebar, top bar, main scroll region
```

## Wiring up the real backend

Everything is mocked today. `src/api.js` already contains the working `fetch()`
implementation of `POST /analyze`, gated behind one constant:

```js
export const USE_MOCK_API = true   // set to false to call FastAPI
```

That request posts `multipart/form-data` with the fields `pcap`, `router_log`
and `firewall_log`, and expects the incident JSON documented as `MOCK_REPORT` in
the same file. In development, Vite proxies `/analyze` to `http://127.0.0.1:8000`;
in production, set `VITE_API_BASE_URL` to the FastAPI origin.

`fetchHistory()` and `fetchIncident(id)` are placeholders for `GET /incidents`
and `GET /incidents/{id}`, which the backend does not expose yet. They follow the
same pattern, so they go live with the same flag.

Once the backend is live, delete the block under the `MOCK DATA` banner in
`src/api.js` and the "Load sample evidence" button in `FileUpload.jsx`.

## Notes on behaviour

- The pipeline animation is presentation only. It runs concurrently with the
  request rather than gating it, so a real backend that takes longer than the
  animation simply keeps the last stage spinning until the response lands.
- A run started while an earlier one is still in flight cancels the earlier one.
  `runRef` in `App.jsx` guards against a stale response overwriting fresh state.
- Classification and risk colours come from the `t-*` classes in `tokens.css`,
  keyed off the raw backend enum values.
