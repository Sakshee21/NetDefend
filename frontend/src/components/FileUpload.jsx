import { useCallback, useId, useRef, useState } from 'react'
import { formatBytes } from '../lib/format'
import { IconAlert, IconFile, IconShield, IconUpload, IconX } from '../lib/icons'
import './FileUpload.css'

/**
 * Evidence intake: one PCAP (required) plus optional router and firewall logs.
 * Calls onAnalyze({ pcap, routerLog, firewallLog }).
 */
export default function FileUpload({ onAnalyze, busy = false }) {
  const [pcap, setPcap] = useState(null)
  const [routerLog, setRouterLog] = useState(null)
  const [firewallLog, setFirewallLog] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [warning, setWarning] = useState('')

  const pcapInputRef = useRef(null)
  const dropzoneId = useId()

  const acceptPcap = useCallback((file) => {
    if (!file) return
    const looksRight = /\.(pcap|pcapng|cap)$/i.test(file.name)
    setWarning(looksRight ? '' : `${file.name} is not a .pcap/.pcapng file. Analysing it anyway.`)
    setPcap(file)
  }, [])

  const handleDrop = (event) => {
    event.preventDefault()
    setDragging(false)
    if (busy) return
    acceptPcap(event.dataTransfer.files?.[0])
  }

  const handleDragOver = (event) => {
    event.preventDefault()
    if (!busy) setDragging(true)
  }

  const submit = (event) => {
    event.preventDefault()
    if (!pcap || busy) return
    onAnalyze({ pcap, routerLog, firewallLog })
  }

  /* Demo affordance: stub files so the mocked pipeline can be run in one click.
     Remove alongside the mock API. */
  const loadSample = () => {
    setWarning('')
    setPcap(new File([new Uint8Array(8)], 'lateral-movement-2026-09-05.pcap'))
    setRouterLog(new File([new Uint8Array(4)], 'rtr-core-01.log'))
    setFirewallLog(new File([new Uint8Array(4)], 'fw-edge-02.log'))
  }

  return (
    <form className="upload" onSubmit={submit}>
      <section
        className={`dropzone${dragging ? ' is-dragging' : ''}${pcap ? ' has-file' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        aria-describedby={dropzoneId}
      >
        <input
          ref={pcapInputRef}
          id="pcap-input"
          className="visually-hidden"
          type="file"
          accept=".pcap,.pcapng,.cap"
          disabled={busy}
          onChange={(event) => acceptPcap(event.target.files?.[0])}
        />

        <div className="dropzone-glow" aria-hidden="true" />

        {pcap ? (
          <div className="dropzone-file">
            <span className="file-icon">
              <IconFile width={20} height={20} />
            </span>
            <div className="file-meta">
              <p className="mono file-name">{pcap.name}</p>
              <p className="file-size mono">
                {formatBytes(pcap.size)} · packet capture
              </p>
            </div>
            <button
              type="button"
              className="icon-btn"
              onClick={() => {
                setPcap(null)
                setWarning('')
                if (pcapInputRef.current) pcapInputRef.current.value = ''
              }}
              disabled={busy}
              aria-label="Remove capture file"
            >
              <IconX width={15} height={15} />
            </button>
          </div>
        ) : (
          <>
            <span className="dropzone-icon">
              <IconUpload width={26} height={26} />
            </span>
            <h2 className="dropzone-title">Drop a packet capture here</h2>
            <p id={dropzoneId} className="dropzone-hint">
              .pcap, .pcapng or .cap — the capture is the primary evidence source for
              the pipeline.
            </p>
            <label className="btn btn-sm dropzone-browse" htmlFor="pcap-input">
              Browse files
            </label>
          </>
        )}
      </section>

      {warning && (
        <p className="upload-warning">
          <IconAlert width={14} height={14} />
          {warning}
        </p>
      )}

      <div className="log-grid">
        <LogInput
          id="router-log"
          label="Router log"
          hint="Syslog or config-change export"
          file={routerLog}
          onChange={setRouterLog}
          disabled={busy}
        />
        <LogInput
          id="firewall-log"
          label="Firewall log"
          hint="ACL hits, denies and rule pushes"
          file={firewallLog}
          onChange={setFirewallLog}
          disabled={busy}
        />
      </div>

      <div className="upload-actions">
        <div className="readiness">
          <span className={`chip${pcap ? ' is-ready' : ''}`}>
            <span className="chip-dot" />
            {pcap ? 'Capture loaded' : 'Capture required'}
          </span>
          <span className="chip">
            <span className="chip-dot" />
            {[routerLog, firewallLog].filter(Boolean).length} of 2 logs
          </span>
        </div>

        <div className="upload-buttons">
          <button type="button" className="btn btn-ghost" onClick={loadSample} disabled={busy}>
            Load sample evidence
          </button>
          <button type="submit" className="btn btn-primary" disabled={!pcap || busy}>
            <IconShield width={15} height={15} />
            {busy ? 'Analysing…' : 'Analyze'}
          </button>
        </div>
      </div>
    </form>
  )
}

function LogInput({ id, label, hint, file, onChange, disabled }) {
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef(null)

  return (
    <div
      className={`log-input${dragging ? ' is-dragging' : ''}${file ? ' has-file' : ''}`}
      onDragOver={(event) => {
        event.preventDefault()
        if (!disabled) setDragging(true)
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(event) => {
        event.preventDefault()
        setDragging(false)
        if (!disabled) onChange(event.dataTransfer.files?.[0] ?? null)
      }}
    >
      <div className="log-input-head">
        <span className="log-label">{label}</span>
        <span className="chip">optional</span>
      </div>

      <input
        ref={inputRef}
        id={id}
        className="visually-hidden"
        type="file"
        accept=".log,.txt,.json,.csv"
        disabled={disabled}
        onChange={(event) => onChange(event.target.files?.[0] ?? null)}
      />

      {file ? (
        <div className="log-file">
          <span className="file-icon sm">
            <IconFile width={14} height={14} />
          </span>
          <div className="file-meta">
            <p className="mono file-name">{file.name}</p>
            <p className="file-size mono">{formatBytes(file.size)}</p>
          </div>
          <button
            type="button"
            className="icon-btn"
            onClick={() => {
              onChange(null)
              if (inputRef.current) inputRef.current.value = ''
            }}
            disabled={disabled}
            aria-label={`Remove ${label}`}
          >
            <IconX width={14} height={14} />
          </button>
        </div>
      ) : (
        <label className="log-drop" htmlFor={id}>
          <span className="log-hint">{hint}</span>
          <span className="log-cta">Choose file or drop here</span>
        </label>
      )}
    </div>
  )
}
