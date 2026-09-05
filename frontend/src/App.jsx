import { useCallback, useEffect, useRef, useState } from 'react'
import { USE_MOCK_API, analyzeIncident, fetchHistory } from './api'
import AgentPipeline, { initialStageState, runPipelineTimeline } from './components/AgentPipeline'
import DialecticalDebate from './components/DialecticalDebate'
import FileUpload from './components/FileUpload'
import HistoryList from './components/HistoryList'
import IncidentReport from './components/IncidentReport'
import { titleCase } from './lib/format'
import {
  IconAlert,
  IconDebate,
  IconFlow,
  IconReport,
  IconShield,
  IconUpload,
} from './lib/icons'
import './styles/app.css'

const VIEWS = [
  { id: 'upload', label: 'New analysis', Icon: IconUpload },
  { id: 'pipeline', label: 'Agent pipeline', Icon: IconFlow },
  { id: 'debate', label: 'Dialectical debate', Icon: IconDebate },
  { id: 'report', label: 'Incident report', Icon: IconReport },
]

const VIEW_COPY = {
  upload: {
    eyebrow: 'Evidence intake',
    title: 'Run a new analysis',
    blurb:
      'Upload a packet capture with the router and firewall logs from the same window. Six agents parse the evidence, argue both readings of it, and return a single adjudicated verdict.',
  },
  pipeline: {
    eyebrow: 'Execution',
    title: 'Agent pipeline',
    blurb:
      'Threat hunting and network troubleshooting run in parallel on the same evidence, then converge on the dialectical arbiter.',
  },
  debate: {
    eyebrow: 'Adjudication',
    title: 'Dialectical debate',
    blurb:
      'The attack thesis and the misconfiguration antithesis, the cross-examination between them, and the arbiter ruling.',
  },
  report: {
    eyebrow: 'Output',
    title: 'Incident report',
    blurb: 'The analyst-facing summary, ready to hand to whoever picks up the ticket.',
  },
}

export default function App() {
  const [view, setView] = useState('upload')
  const [stages, setStages] = useState(initialStageState)
  const [report, setReport] = useState(null)
  const [history, setHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState(null)

  // Guards against a stale run finishing after the user has started another.
  const runRef = useRef(0)

  useEffect(() => {
    let cancelled = false
    fetchHistory()
      .then((items) => {
        if (!cancelled) setHistory(items)
      })
      .catch(() => {
        if (!cancelled) setHistory([])
      })
      .finally(() => {
        if (!cancelled) setHistoryLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const handleAnalyze = useCallback(async (files) => {
    const runId = runRef.current + 1
    runRef.current = runId

    setError(null)
    setReport(null)
    setStages(initialStageState())
    setRunning(true)
    setView('pipeline')

    // The request and the pipeline animation run concurrently: the animation is
    // pure presentation, so pointing api.js at the real FastAPI service does not
    // change anything here.
    const request = analyzeIncident(files).then(
      (value) => ({ ok: true, value }),
      (reason) => ({ ok: false, reason }),
    )

    await runPipelineTimeline(setStages, () => runRef.current === runId)
    const result = await request
    if (runRef.current !== runId) return

    setRunning(false)
    if (!result.ok) {
      setError(result.reason?.message ?? 'The analysis pipeline failed.')
      setStages(initialStageState())
      return
    }

    setReport(result.value)
    setHistory((current) => [result.value, ...current])
    setView('debate')
  }, [])

  const openIncident = useCallback((incident) => {
    runRef.current += 1 // cancel any run still in flight
    setRunning(false)
    setError(null)
    setReport(incident)
    setStages(Object.fromEntries(Object.keys(initialStageState()).map((id) => [id, 'complete'])))
    setView('report')
  }, [])

  const startNew = useCallback(() => {
    runRef.current += 1
    setRunning(false)
    setError(null)
    setReport(null)
    setStages(initialStageState())
    setView('upload')
  }, [])

  const pipelineStarted = Object.values(stages).some((status) => status !== 'pending')
  const copy = VIEW_COPY[view]

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">
            <IconShield width={19} height={19} />
          </span>
          <div>
            <p className="brand-name">NetDefend</p>
            <p className="brand-sub">Multi-agent SOC</p>
          </div>
        </div>

        <nav className="nav">
          <p className="eyebrow nav-label">Workspace</p>
          {VIEWS.map(({ id, label, Icon }) => {
            const disabled =
              (id === 'pipeline' && !pipelineStarted) ||
              ((id === 'debate' || id === 'report') && !report)
            return (
              <button
                key={id}
                type="button"
                className={`nav-item${view === id ? ' is-active' : ''}`}
                onClick={() => (id === 'upload' ? startNew() : setView(id))}
                disabled={disabled}
              >
                <span className="nav-icon">
                  <Icon width={15} height={15} />
                </span>
                {label}
                {id === 'pipeline' && running && <span className="nav-badge mono">live</span>}
              </button>
            )
          })}
        </nav>

        <HistoryList
          items={history}
          activeId={report?.incident_id ?? null}
          loading={historyLoading}
          onSelect={openIncident}
        />

        <div className="sidebar-foot">
          <p className={`api-mode${USE_MOCK_API ? '' : ' is-live'}`}>
            <span className="chip-dot" />
            {USE_MOCK_API ? 'MOCK API' : 'LIVE API'}
          </p>
          <p className="api-mode-note">
            {USE_MOCK_API
              ? 'Responses are sample data. Set USE_MOCK_API to false in src/api.js to call POST /analyze.'
              : 'Calling POST /analyze on the FastAPI backend.'}
          </p>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="crumbs">
            <span>netdefend</span>
            <span className="crumb-sep">/</span>
            <strong>{VIEWS.find((entry) => entry.id === view)?.label}</strong>
            {report && (
              <>
                <span className="crumb-sep">/</span>
                <span>{report.incident_id}</span>
              </>
            )}
          </div>

          <div className="topbar-right">
            {running && (
              <span className="chip status-live">
                <span className="chip-dot" />
                Pipeline running
              </span>
            )}
            {report && !running && (
              <span className={`chip t-${report.classification.toLowerCase()}`}>
                <span className="chip-dot" />
                {titleCase(report.classification)} · {report.risk_level}
              </span>
            )}
            {(report || running) && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={startNew}>
                New analysis
              </button>
            )}
          </div>
        </header>

        <div className="view">
          <div className="view-inner" key={view}>
            <div className="view-head">
              <p className="eyebrow">{copy.eyebrow}</p>
              <h1>{copy.title}</h1>
              <p>{copy.blurb}</p>
            </div>

            {error && (
              <div className="error-banner" role="alert">
                <IconAlert width={16} height={16} />
                <span>{error}</span>
              </div>
            )}

            {view === 'upload' && <FileUpload onAnalyze={handleAnalyze} busy={running} />}

            {view === 'pipeline' && <AgentPipeline stages={stages} error={error} />}

            {view === 'debate' &&
              (report ? (
                <DialecticalDebate report={report} />
              ) : (
                <EmptyState label="Run an analysis to see the agents argue." />
              ))}

            {view === 'report' &&
              (report ? (
                <IncidentReport report={report} />
              ) : (
                <EmptyState label="Run an analysis or pick an incident from the history." />
              ))}
          </div>
        </div>
      </main>
    </div>
  )
}

function EmptyState({ label }) {
  return (
    <div className="empty-state">
      <IconShield width={24} height={24} />
      <h2>{label}</h2>
    </div>
  )
}
