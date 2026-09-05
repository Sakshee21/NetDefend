import { useState } from 'react'
import { formatTimestamp, percent, titleCase, tone } from '../lib/format'
import { IconCopy, IconDownload, IconGavel, IconSiren } from '../lib/icons'
import './IncidentReport.css'

/** The signed-off summary an analyst reads first. */
export default function IncidentReport({ report }) {
  const [copied, setCopied] = useState(false)
  if (!report) return null

  const {
    incident_id: incidentId,
    classification,
    risk_level: risk,
    confidence,
    mitre_ttp: mitre,
    threat_hypothesis: thesis,
    misconfig_hypothesis: antithesis,
    recommended_action: action,
    affected_host: host,
    timestamp,
    source_files: sources,
  } = report

  const uncertain = classification === 'UNCERTAIN'
  const attackLed = classification === 'ATTACK'
  const primary = uncertain || attackLed ? thesis : antithesis
  const secondary = uncertain || attackLed ? antithesis : thesis
  const primaryLabel = uncertain || attackLed ? 'Attack evidence' : 'Misconfiguration evidence'
  const secondaryLabel = uncertain || attackLed ? 'Misconfiguration evidence' : 'Attack evidence'

  const copyJson = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(report, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    } catch {
      setCopied(false)
    }
  }

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${incidentId}.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <article className={`report panel ${tone(classification)}`}>
      <header className="report-head">
        <div className="report-id">
          <p className="eyebrow">Incident report</p>
          <h2 className="mono report-number">{incidentId}</h2>
          <p className="report-time mono">{formatTimestamp(timestamp)}</p>
        </div>

        <div className="report-badges">
          <span className={`verdict-pill ${tone(classification)}`}>
            <IconGavel width={15} height={15} />
            {titleCase(classification)}
          </span>
          <span className={`risk-pill ${tone(risk)}`}>
            <span className="risk-rungs" aria-hidden="true">
              {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((level, index) => (
                <span
                  key={level}
                  className={`rung${index <= riskIndex(risk) ? ' is-on' : ''}`}
                />
              ))}
            </span>
            {risk} RISK
          </span>
        </div>
      </header>

      <section className="facts">
        <Fact label="Classification" value={titleCase(classification)} tone={tone(classification)} />
        <Fact label="Affected host" value={host ?? '—'} mono />
        <Fact
          label="MITRE ATT&CK"
          value={mitre ? mitre.id : 'Not applicable'}
          sub={mitre ? mitre.name : 'No adversary technique mapped'}
          mono
        />
        <div className="fact fact-confidence">
          <span className="eyebrow">Confidence</span>
          <div className="confidence-row">
            <span className="mono confidence-value">{percent(confidence)}</span>
            <div
              className="confidence-track"
              role="meter"
              aria-valuenow={Math.round(Number(confidence ?? 0) * 100)}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Model confidence"
            >
              <span
                className="confidence-fill"
                style={{ width: `${Math.round(Number(confidence ?? 0) * 100)}%` }}
              />
            </div>
          </div>
        </div>
      </section>

      <section className="report-section">
        <span className="eyebrow">Assessment</span>
        <p className="assessment">{primary?.summary}</p>
      </section>

      <section className="report-section">
        <span className="eyebrow">{primaryLabel}</span>
        <ul className="evidence">
          {(primary?.evidence ?? []).map((item) => (
            <li key={item}>
              <span className="evidence-bullet" aria-hidden="true" />
              {item}
            </li>
          ))}
        </ul>

        {(secondary?.evidence ?? []).length > 0 && (
          <details className="counter">
            <summary>
              {secondaryLabel} · {secondary.evidence.length} items considered and{' '}
              {uncertain ? 'unresolved' : 'discounted'}
            </summary>
            <ul className="evidence is-muted">
              {secondary.evidence.map((item) => (
                <li key={item}>
                  <span className="evidence-bullet" aria-hidden="true" />
                  {item}
                </li>
              ))}
            </ul>
          </details>
        )}
      </section>

      <section className={`callout ${tone(classification)}`}>
        <span className="callout-icon">
          <IconSiren width={18} height={18} />
        </span>
        <div>
          <span className="eyebrow">Recommended action</span>
          <p className="callout-text">{action}</p>
        </div>
      </section>

      <footer className="report-foot">
        <div className="sources mono">
          {sources?.pcap ? (
            <>
              <span>{sources.pcap}</span>
              {sources.router_log && <span>{sources.router_log}</span>}
              {sources.firewall_log && <span>{sources.firewall_log}</span>}
            </>
          ) : (
            <span>Archived analysis</span>
          )}
        </div>
        <div className="report-actions">
          <button type="button" className="btn btn-ghost btn-sm" onClick={copyJson}>
            <IconCopy width={14} height={14} />
            {copied ? 'Copied' : 'Copy JSON'}
          </button>
          <button type="button" className="btn btn-sm" onClick={downloadJson}>
            <IconDownload width={14} height={14} />
            Export
          </button>
        </div>
      </footer>
    </article>
  )
}

function Fact({ label, value, sub, mono = false, tone: toneClass }) {
  return (
    <div className="fact">
      <span className="eyebrow">{label}</span>
      <span className={`fact-value${mono ? ' mono' : ''} ${toneClass ?? ''}`}>{value}</span>
      {sub && <span className="fact-sub">{sub}</span>}
    </div>
  )
}

function riskIndex(risk) {
  return ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].indexOf(String(risk ?? '').toUpperCase())
}
