import { percent } from '../lib/format'
import { IconAlert, IconTarget, IconWrench } from '../lib/icons'
import './DialecticalDebate.css'
import './HypothesesView.css'

/**
 * The real-pipeline equivalent of DialecticalDebate, for right now: two
 * independent hypotheses, side by side, in the same thesis/antithesis
 * column styling (reuses DialecticalDebate.css directly) -- but with NO
 * refutation exchange and NO verdict badge, because the Dialectical
 * Arbiter and Incident Response Agent are still stubs (see
 * agents/arbiter.py, agents/response_agent.py). Backed by
 * backend/api/analyze.py's response shape, not the full MOCK_REPORT shape
 * DialecticalDebate expects.
 */
export default function HypothesesView({ report }) {
  if (!report) return null

  const { threat_hypothesis: threat, misconfig_hypothesis: misconfig, note } = report

  return (
    <div className="debate hypotheses-view">
      <div className="banner-note">
        <IconAlert width={15} height={15} />
        <span>
          {note ??
            'Arbiter resolution coming in next milestone — showing both hypotheses independently.'}
        </span>
      </div>

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
          llmCallFailed={misconfig?.taxonomy_category === 'OLLAMA_UNAVAILABLE'}
        />
      </section>
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
}) {
  return (
    <article className={`argument ${side}`}>
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
