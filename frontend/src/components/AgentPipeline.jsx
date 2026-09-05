import { useEffect, useMemo, useRef, useState } from 'react'
import {
  IconBrain,
  IconCheck,
  IconGavel,
  IconPackets,
  IconSiren,
  IconTarget,
  IconWrench,
} from '../lib/icons'
import './AgentPipeline.css'

/* -----------------------------------------------------------------------------
 * The six agents of the NetDefend pipeline. Stages 3 and 4 run in parallel and
 * converge on the arbiter.
 * -------------------------------------------------------------------------- */
export const PIPELINE_STAGES = [
  {
    id: 'packet',
    step: '01',
    name: 'Packet Analysis Agent',
    role: 'Parses the capture and extracts flow features',
    Icon: IconPackets,
  },
  {
    id: 'ids',
    step: '02',
    name: 'Intrusion Detection Agent',
    role: 'Scores flows against the trained anomaly model',
    tag: 'ML',
    Icon: IconBrain,
  },
  {
    id: 'threat',
    step: '03',
    name: 'Threat Hunting Agent',
    role: 'Argues the attack thesis and maps MITRE ATT&CK',
    branch: 'thesis',
    Icon: IconTarget,
  },
  {
    id: 'troubleshoot',
    step: '04',
    name: 'Network Troubleshooting Agent',
    role: 'Argues the misconfiguration antithesis',
    branch: 'antithesis',
    Icon: IconWrench,
  },
  {
    id: 'arbiter',
    step: '05',
    name: 'Dialectical Arbiter',
    role: 'Runs the refutation exchange and rules on a verdict',
    Icon: IconGavel,
  },
  {
    id: 'response',
    step: '06',
    name: 'Incident Response Agent',
    role: 'Drafts the recommended action and incident report',
    Icon: IconSiren,
  },
]

/** Execution order. Nested arrays are stages that run at the same time. */
const TIMELINE = [
  { ids: ['packet'], duration: 1500 },
  { ids: ['ids'], duration: 1700 },
  { ids: ['threat', 'troubleshoot'], duration: 1900 },
  { ids: ['arbiter'], duration: 1600 },
  { ids: ['response'], duration: 1300 },
]

export function initialStageState() {
  return Object.fromEntries(PIPELINE_STAGES.map((stage) => [stage.id, 'pending']))
}

/**
 * Drives the visual pipeline: marks each group running, waits, marks it complete.
 * Runs alongside the real analyzeIncident() request rather than gating it, so
 * swapping the mock API for FastAPI does not change this animation.
 */
export async function runPipelineTimeline(setStages, shouldContinue = () => true) {
  for (const group of TIMELINE) {
    if (!shouldContinue()) return
    setStages((current) => withStatus(current, group.ids, 'running'))
    await new Promise((resolve) => setTimeout(resolve, group.duration))
    if (!shouldContinue()) return
    setStages((current) => withStatus(current, group.ids, 'complete'))
  }
}

function withStatus(current, ids, status) {
  const next = { ...current }
  ids.forEach((id) => {
    next[id] = status
  })
  return next
}

/* -------------------------------------------------------------------------- */

export default function AgentPipeline({ stages, error = null }) {
  const byId = useMemo(
    () => Object.fromEntries(PIPELINE_STAGES.map((stage) => [stage.id, stage])),
    [],
  )
  const done = PIPELINE_STAGES.every((stage) => stages[stage.id] === 'complete')
  const active = PIPELINE_STAGES.some((stage) => stages[stage.id] === 'running')
  const completed = PIPELINE_STAGES.filter((s) => stages[s.id] === 'complete').length

  return (
    <div className="pipeline">
      <div className="panel">
        <header className="panel-head">
          <div>
            <p className="eyebrow">Multi-agent execution</p>
            <h2 className="panel-title" style={{ marginTop: 4 }}>
              Analysis pipeline
            </h2>
          </div>
          <div className="pipeline-head-right">
            <ElapsedClock running={active} reset={completed === 0} />
            <span className={`chip${done ? ' is-done' : ''}`}>
              <span className="chip-dot" />
              {completed} / {PIPELINE_STAGES.length} agents
            </span>
          </div>
        </header>

        <div className="flow">
          <StageCard stage={byId.packet} status={stages.packet} />
          <Connector active={stages.packet === 'complete'} />
          <StageCard stage={byId.ids} status={stages.ids} />

          <FanOut left={stages.threat} right={stages.troubleshoot} />

          <div className="branch">
            <span className="branch-label thesis">Parallel branch · thesis</span>
            <span className="branch-label antithesis">Parallel branch · antithesis</span>
            <StageCard stage={byId.threat} status={stages.threat} />
            <StageCard stage={byId.troubleshoot} status={stages.troubleshoot} />
          </div>

          <FanIn left={stages.threat} right={stages.troubleshoot} />

          <StageCard stage={byId.arbiter} status={stages.arbiter} />
          <Connector active={stages.arbiter === 'complete'} />
          <StageCard stage={byId.response} status={stages.response} />
        </div>
      </div>

      <ConsoleFeed stages={stages} error={error} />
    </div>
  )
}

function StageCard({ stage, status }) {
  const { Icon } = stage
  return (
    <article className={`stage is-${status}${stage.branch ? ` branch-${stage.branch}` : ''}`}>
      <span className="stage-step mono">{stage.step}</span>
      <span className="stage-icon">
        <Icon width={17} height={17} />
      </span>
      <div className="stage-body">
        <h3 className="stage-name">
          {stage.name}
          {stage.tag && <span className="stage-tag mono">{stage.tag}</span>}
        </h3>
        <p className="stage-role">{stage.role}</p>
      </div>
      <StatusBadge status={status} />
      <span className="stage-bar" aria-hidden="true" />
    </article>
  )
}

function StatusBadge({ status }) {
  if (status === 'complete') {
    return (
      <span className="status status-complete">
        <IconCheck width={13} height={13} />
        Complete
      </span>
    )
  }
  if (status === 'running') {
    return (
      <span className="status status-running">
        <span className="spinner" aria-hidden="true" />
        Running
      </span>
    )
  }
  return (
    <span className="status status-pending">
      <span className="dot-hollow" aria-hidden="true" />
      Pending
    </span>
  )
}

function Connector({ active }) {
  return <div className={`connector${active ? ' is-active' : ''}`} aria-hidden="true" />
}

/** Two curves splitting stage 02 into the parallel branch. */
function FanOut({ left, right }) {
  return (
    <svg className="fan" viewBox="0 0 400 46" preserveAspectRatio="none" aria-hidden="true">
      <path d="M200 0 C200 26 100 20 100 46" className={`fan-path ${lineState(left)}`} />
      <path d="M200 0 C200 26 300 20 300 46" className={`fan-path ${lineState(right)}`} />
    </svg>
  )
}

/** The same two curves converging on the arbiter. */
function FanIn({ left, right }) {
  return (
    <svg className="fan" viewBox="0 0 400 46" preserveAspectRatio="none" aria-hidden="true">
      <path d="M100 0 C100 26 200 20 200 46" className={`fan-path ${lineState(left)}`} />
      <path d="M300 0 C300 26 200 20 200 46" className={`fan-path ${lineState(right)}`} />
    </svg>
  )
}

function lineState(status) {
  if (status === 'complete') return 'is-complete'
  if (status === 'running') return 'is-running'
  return ''
}

/** Wall-clock timer for the current run. */
function ElapsedClock({ running, reset }) {
  const [elapsed, setElapsed] = useState(0)
  const startRef = useRef(null)

  useEffect(() => {
    if (reset) {
      startRef.current = null
      setElapsed(0)
    }
  }, [reset])

  useEffect(() => {
    if (!running) return undefined
    if (startRef.current === null) startRef.current = Date.now()
    const id = setInterval(() => setElapsed(Date.now() - startRef.current), 100)
    return () => clearInterval(id)
  }, [running])

  return <span className="elapsed mono">t+{(elapsed / 1000).toFixed(1)}s</span>
}

/** Append-only log of stage transitions, styled like a SOC console. */
function ConsoleFeed({ stages, error }) {
  const [lines, setLines] = useState([])
  const seen = useRef(new Set())
  const endRef = useRef(null)

  useEffect(() => {
    const allPending = PIPELINE_STAGES.every((stage) => stages[stage.id] === 'pending')
    if (allPending) {
      seen.current.clear()
      setLines([])
      return
    }

    const additions = []
    PIPELINE_STAGES.forEach((stage) => {
      const status = stages[stage.id]
      if (status === 'pending') return
      const key = `${stage.id}:${status}`
      if (seen.current.has(key)) return
      seen.current.add(key)
      additions.push({
        key,
        level: status === 'running' ? 'run' : 'ok',
        text:
          status === 'running'
            ? `[${stage.step}] ${stage.name} dispatched`
            : `[${stage.step}] ${stage.name} returned`,
        time: new Date().toLocaleTimeString('en-GB', { hour12: false }),
      })
    })
    if (additions.length) setLines((current) => [...current, ...additions])
  }, [stages])

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'nearest' })
  }, [lines.length])

  return (
    <div className="console panel">
      <header className="panel-head">
        <h2 className="panel-title">Agent trace</h2>
        <span className="eyebrow">stdout</span>
      </header>
      <div className="console-body mono">
        {lines.length === 0 && <p className="console-idle">Awaiting dispatch…</p>}
        {lines.map((line) => (
          <p key={line.key} className={`console-line lvl-${line.level}`}>
            <span className="console-time">{line.time}</span>
            <span className="console-level">{line.level === 'run' ? 'RUN' : 'OK '}</span>
            {line.text}
          </p>
        ))}
        {error && (
          <p className="console-line lvl-err">
            <span className="console-time">--:--:--</span>
            <span className="console-level">ERR</span>
            {error}
          </p>
        )}
        <span ref={endRef} />
      </div>
    </div>
  )
}
