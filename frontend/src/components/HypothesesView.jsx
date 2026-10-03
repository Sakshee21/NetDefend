import { agentInfo, challengerOf, percent, titleCase, tone } from '../lib/format'
import { IconAlert, IconGavel, IconTarget, IconWrench } from '../lib/icons'
import IncidentReport from './IncidentReport'
import './DialecticalDebate.css'
import './HypothesesView.css'

/**
 * The real-pipeline view: the two competing hypotheses, the Dialectical
 * Arbiter's real refutation exchange between them, and its adjudicated
 * verdict. Reuses DialecticalDebate.css for the thesis/antithesis columns,
 * the refutation thread and the verdict panel. Backed by
 * backend/api/analyze.py's response shape (arbiter_verdict +
 * refutation_exchange are now real, not stub text).
 */
export default function HypothesesView({ report }) {
  if (!report) return null

  const {
    threat_hypothesis: threat,
    misconfig_hypothesis: misconfig,
    refutation_exchange: exchange = [],
    arbiter_verdict: verdict,
    final_report: finalReport,
    note,
  } = report

  return (
    <div className="debate hypotheses-view">
      {note && (
        <div className="banner-note">
          <IconAlert width={15} height={15} />
          <span>{note}</span>
        </div>
      )}

      <section className="argument-grid">
        <ArgumentColumn
          side="thesis"
          Icon={IconTarget}
          agent="Threat Hunting Agent"
          stance="Attack hypothesis"
          summary={threat?.summary}
          tagLabel="MITRE ATT&CK"
          tagValue={
            threat?.ttp_id
              ? `${threat.ttp_id} · via ${threat.mapping_method ?? 'unknown'}`
              : 'No technique mapped'
          }
          evidence={threat?.evidence ?? []}
          confidence={threat?.confidence}
          llmCallFailed={threat?.llm_call_failed}
          prevailed={verdict?.classification === 'ATTACK'}
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
          stance="Misconfiguration hypothesis"
          summary={misconfig?.summary}
          tagLabel="Taxonomy"
          tagValue={misconfig?.taxonomy_category ?? 'Uncategorised'}
          evidence={misconfig?.evidence ?? []}
          confidence={misconfig?.is_misconfiguration}
          llmCallFailed={misconfig?.taxonomy_category === 'LLM_UNAVAILABLE'}
          prevailed={verdict?.classification === 'MISCONFIGURATION'}
        />
      </section>

      {exchange.length > 0 && <RefutationExchange exchange={exchange} />}

      {verdict && <ArbiterVerdict verdict={verdict} />}

      {finalReport && (
        <div className="final-report-stage">
          <p className="eyebrow stage-label">Incident response</p>
          <IncidentReport report={finalReport} />
        </div>
      )}
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
  confidence,
  llmCallFailed,
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
        {llmCallFailed && (
          <span
            className="llm-fail-flag mono"
            title="The LLM call behind this hypothesis failed — this is an honest fallback result, not a real answer."
          >
            <IconAlert width={12} height={12} />
            LLM call failed
          </span>
        )}
        {prevailed && !llmCallFailed && <span className="prevail-flag mono">Upheld</span>}
      </header>

      <blockquote className="argument-summary">{summary || 'No summary returned.'}</blockquote>

      <div className="argument-tag-row">
        <div className="argument-tag">
          <span className="eyebrow">{tagLabel}</span>
          <span className="mono argument-tag-value">{tagValue}</span>
        </div>
        {confidence != null && (
          <div className="argument-tag">
            <span className="eyebrow">Confidence</span>
            <span className="mono argument-tag-value">{percent(confidence)}</span>
          </div>
        )}
      </div>

      <div className="argument-evidence">
        <span className="eyebrow">Supporting evidence</span>
        <ul>
          {evidence.map((item, index) => (
            <li key={`${index}-${item}`}>
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

/**
 * The cross-examination: each hypothesis's challenge and its rebuttal.
 * challenged_agent is the defender; the challenger is the other agent.
 */
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

/**
 * The arbiter's adjudicated verdict: badge (ATTACK red / MISCONFIGURATION
 * blue / UNCERTAIN amber), confidence meter, and the real adjudication
 * reasoning. UNCERTAIN gets an explicit human-review escalation; a
 * rule-based fallback (reasoning carries the fixed sentinel) gets a
 * warning badge so it reads as a degraded, not genuine, verdict.
 */
function ArbiterVerdict({ verdict }) {
  const classification = verdict.classification ?? 'UNCERTAIN'
  const value = Math.round(Number(verdict.confidence ?? 0) * 100)
  const segments = 24
  const filled = Math.round((value / 100) * segments)
  const toneClass = tone(classification)

  const isUncertain = classification === 'UNCERTAIN'
  const isFallback = (verdict.reasoning ?? '').includes('fallback rule used')

  return (
    <section className={`verdict ${toneClass}`}>
      <div className="verdict-glow" aria-hidden="true" />

      <div className="verdict-left">
        <p className="eyebrow">Arbiter verdict</p>
        <div className="verdict-badge">
          <IconGavel width={22} height={22} />
          <span>{titleCase(classification)}</span>
        </div>

        <div className="verdict-flags">
          {isFallback && (
            <span className="verdict-flag is-fallback mono">
              <IconAlert width={12} height={12} />
              Fallback rule — not LLM-adjudicated
            </span>
          )}
          {isUncertain && (
            <span className="verdict-flag is-escalated mono">
              <IconAlert width={12} height={12} />
              Escalated for human review
            </span>
          )}
        </div>

        <p className="verdict-rationale">
          {verdict.reasoning || 'The arbiter did not record a rationale.'}
        </p>

        {isUncertain && verdict.escalation && (
          <p className="verdict-escalation">{verdict.escalation}</p>
        )}
      </div>

      <div className="verdict-right">
        <div className="verdict-confidence">
          <span className="eyebrow">Confidence</span>
          <span className="verdict-number mono">{percent(verdict.confidence)}</span>
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
        <p className="verdict-meta mono">dialectical adjudication</p>
      </div>
    </section>
  )
}
