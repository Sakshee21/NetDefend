import { formatRelative, titleCase, tone } from '../lib/format'
import './HistoryList.css'

/** Past analyses. Selecting a row reopens that incident's report. */
export default function HistoryList({ items = [], activeId = null, loading = false, onSelect }) {
  return (
    <div className="history">
      <div className="history-head">
        <span className="eyebrow">Past analyses</span>
        <span className="eyebrow">{loading ? '…' : items.length}</span>
      </div>

      <ul className="history-list">
        {loading && <li className="history-loading">Loading incidents…</li>}

        {!loading && items.length === 0 && (
          <li className="history-loading">No analyses recorded yet.</li>
        )}

        {items.map((incident) => {
          const active = incident.incident_id === activeId
          return (
            <li key={incident.incident_id}>
              <button
                type="button"
                className={`history-row${active ? ' is-active' : ''}`}
                onClick={() => onSelect?.(incident)}
                aria-current={active ? 'true' : undefined}
              >
                <span className={`history-dot ${tone(incident.classification)}`} aria-hidden="true" />
                <span className="history-body">
                  <span className="history-top">
                    <span className="mono history-id">{incident.incident_id}</span>
                    <span className="history-age">{formatRelative(incident.timestamp)}</span>
                  </span>
                  <span className="history-bottom">
                    <span className={`history-class ${tone(incident.classification)}`}>
                      {titleCase(incident.classification)}
                    </span>
                    <span className="history-sep">·</span>
                    <span className={`history-risk mono ${tone(incident.risk_level)}`}>
                      {incident.risk_level}
                    </span>
                  </span>
                  <span className="history-host mono">{incident.affected_host}</span>
                </span>
              </button>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
