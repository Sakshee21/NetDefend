import { agentInfo, challengerOf, percent, titleCase, tone } from '../lib/format'
import { IconGavel, IconTarget, IconWrench } from '../lib/icons'
import './DialecticalDebate.css'

/**
 * Thesis versus antithesis, the refutation exchange between them, and the
 * arbiter's verdict.
 */
export default function DialecticalDebate({ report }) {
  if (!report) return null

  const {
    threat_hypothesis: thesis,
    misconfig_hypothesis: antithesis,
    refutation_exchange: exchange = [],
    classification,
    confidence,
    mitre_ttp: mitre,
  } = report

  return (
    <div className="debate">
      <section className="argument-grid">
        <ArgumentColumn
          side="thesis"
          Icon={IconTarget}
          agent="Threat Hunting Agent"
          stance="Thesis · Attack hypothesis"
          summary={thesis?.summary}
          tagLabel="MITRE ATT&CK"
          tagValue={mitre ? `${mitre.id} — ${mitre.name}` : 'No technique mapped'}
          evidence={thesis?.evidence ?? []}
          prevailed={classification === 'ATTACK'}
        />

        <div className="argument-divider" aria-hidden="true">
          <span className="divider-line" />
          <span className="divider-badge mono">VS</span>
          <span className="divider-line" />
        </div>

        <ArgumentColumn
          side="antithesis"
          Icon={IconWrench}
          agent="Network Troubleshooting Agent"
          stance="Antithesis · Misconfiguration hypothesis"
          summary={antithesis?.summary}
          tagLabel="Taxonomy"
          tagValue={antithesis?.taxonomy_category ?? 'Uncategorised'}
          evidence={antithesis?.evidence ?? []}
          prevailed={classification === 'MISCONFIGURATION'}
        />
      </section>

      <RefutationExchange exchange={exchange} />

      <Verdict classification={classification} confidence={confidence} exchange={exchange} />
    </div>
  )
}

function ArgumentColumn({
  side,
  Icon,
  agent,
  stance,
  summary,
  tagLabel,
  tagValue,
  evidence,
  prevailed,
}) {
  return (
    <article className={`argument ${side}${prevailed ? ' is-prevailing' : ''}`}>
      <header className="argument-head">
        <span className="argument-icon">
          <Icon width={17} height={17} />
        </span>
        <div>
          <h3 className="argument-agent">{agent}</h3>
          <p className="argument-stance">{stance}</p>
        </div>
        {prevailed && <span className="prevail-flag mono">Upheld</span>}
      </header>

      <blockquote className="argument-summary">{summary}</blockquote>

      <div className="argument-tag">
        <span className="eyebrow">{tagLabel}</span>
        <span className="mono argument-tag-value">{tagValue}</span>
      </div>

      <div className="argument-evidence">
        <span className="eyebrow">Supporting evidence</span>
        <ul>
          {evidence.map((item) => (
            <li key={item}>
              <span className="bullet" aria-hidden="true" />
              {item}
            </li>
          ))}
          {evidence.length === 0 && <li className="muted">No evidence supplied.</li>}
        </ul>
      </div>
    </article>
  )
}

function RefutationExchange({ exchange }) {
  return (
    <section className="panel refutation">
      <header className="panel-head">
        <div>
          <p className="eyebrow">Cross-examination</p>
          <h2 className="panel-title" style={{ marginTop: 4 }}>
            Refutation exchange
          </h2>
        </div>
        <span className="chip">
          {exchange.length} {exchange.length === 1 ? 'round' : 'rounds'}
        </span>
      </header>

      <ol className="thread">
        {exchange.map((round, index) => {
          const defender = agentInfo(round.challenged_agent)
          const challenger = challengerOf(round.challenged_agent)
          return (
            <li className="round" key={`${round.challenged_agent}-${index}`}>
              <div className="round-rail" aria-hidden="true">
                <span className="round-number mono">{String(index + 1).padStart(2, '0')}</span>
                <span className="round-line" />
              </div>

              <div className="round-body">
                <p className="round-caption">
                  <strong className={`side-${challenger.side}`}>{challenger.short}</strong>
                  {' challenges '}
                  <strong className={`side-${defender.side}`}>{defender.name}</strong>
                </p>

                <Bubble
                  kind="challenge"
                  side={challenger.side}
                  initials={challenger.initials}
                  who={challenger.name}
                  label="Challenge"
                  text={round.challenge}
                />
                <Bubble
                  kind="response"
                  side={defender.side}
                  initials={defender.initials}
                  who={defender.name}
                  label="Response"
                  text={round.response}
                />
              </div>
            </li>
          )
        })}
        {exchange.length === 0 && (
          <li className="muted round-empty">The arbiter recorded no refutation rounds.</li>
        )}
      </ol>
    </section>
  )
}

function Bubble({ kind, side, initials, who, label, text }) {
  return (
    <div className={`bubble ${kind} side-${side}`}>
      <span className="avatar mono" aria-hidden="true">
        {initials}
      </span>
      <div className="bubble-body">
        <p className="bubble-head">
          <span className="bubble-who">{who}</span>
          <span className="bubble-label mono">{label}</span>
        </p>
        <p className="bubble-text">{text}</p>
      </div>
    </div>
  )
}

function Verdict({ classification, confidence, exchange }) {
  const value = Math.round(Number(confidence ?? 0) * 100)
  const segments = 24
  const filled = Math.round((value / 100) * segments)
  const toneClass = tone(classification)

  const rationale = {
    ATTACK: 'Attack thesis survived cross-examination; the misconfiguration account did not explain the observed pattern.',
    MISCONFIGURATION:
      'Misconfiguration antithesis survived cross-examination; the attack account lacked corroborating evidence.',
    UNCERTAIN:
      'Neither hypothesis was refuted decisively. Further evidence is required before escalation.',
  }[classification] ?? 'The arbiter did not record a rationale.'

  return (
    <section className={`verdict ${toneClass}`}>
      <div className="verdict-glow" aria-hidden="true" />

      <div className="verdict-left">
        <p className="eyebrow">Arbiter verdict</p>
        <div className="verdict-badge">
          <IconGavel width={22} height={22} />
          <span>{titleCase(classification)}</span>
        </div>
        <p className="verdict-rationale">{rationale}</p>
      </div>

      <div className="verdict-right">
        <div className="verdict-confidence">
          <span className="eyebrow">Confidence</span>
          <span className="verdict-number mono">{percent(confidence)}</span>
        </div>
        <div
          className="meter"
          role="meter"
          aria-valuenow={value}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Arbiter confidence"
        >
          {Array.from({ length: segments }, (_, index) => (
            <span key={index} className={`meter-seg${index < filled ? ' is-on' : ''}`} />
          ))}
        </div>
        <p className="verdict-meta mono">
          {exchange.length} refutation {exchange.length === 1 ? 'round' : 'rounds'} · dialectical
          synthesis
        </p>
      </div>
    </section>
  )
}
