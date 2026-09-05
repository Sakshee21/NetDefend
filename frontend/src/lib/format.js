/* Small presentation helpers shared across views. */

/** Maps a classification or risk level to its colour class in tokens.css. */
export function tone(value) {
  return `t-${String(value ?? 'uncertain').toLowerCase()}`
}

/** ATTACK -> Attack, MISCONFIGURATION -> Misconfiguration */
export function titleCase(value) {
  if (!value) return 'Unknown'
  const text = String(value).replace(/_/g, ' ')
  return text.charAt(0).toUpperCase() + text.slice(1).toLowerCase()
}

/** 0.89 -> "89%" */
export function percent(confidence, digits = 0) {
  const value = Number(confidence ?? 0) * 100
  return `${value.toFixed(digits)}%`
}

/** ISO 8601 -> "05 Sep 2026 · 14:23:41 UTC" */
export function formatTimestamp(iso) {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return String(iso ?? '—')
  const parts = new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZone: 'UTC',
  }).formatToParts(date)
  const get = (type) => parts.find((part) => part.type === type)?.value ?? ''
  return `${get('day')} ${get('month')} ${get('year')} · ${get('hour')}:${get('minute')}:${get('second')} UTC`
}

/** ISO 8601 -> "4h ago" */
export function formatRelative(iso) {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return ''
  const seconds = Math.round((Date.now() - date.getTime()) / 1000)
  const future = seconds < 0
  const abs = Math.abs(seconds)
  const units = [
    [60, 's'],
    [3600, 'm'],
    [86400, 'h'],
    [2592000, 'd'],
  ]
  let label = `${Math.floor(abs / 2592000)}mo`
  if (abs < 45) label = 'just now'
  else {
    for (let i = 0; i < units.length; i += 1) {
      const [limit, suffix] = units[i]
      if (abs < limit) {
        const divisor = i === 0 ? 1 : units[i - 1][0]
        label = `${Math.floor(abs / divisor)}${suffix}`
        break
      }
    }
  }
  if (label === 'just now') return label
  return future ? `in ${label}` : `${label} ago`
}

/** 1048576 -> "1.0 MB" */
export function formatBytes(bytes) {
  const size = Number(bytes ?? 0)
  if (!size) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const exponent = Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1)
  const value = size / 1024 ** exponent
  return `${value.toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`
}

/** Identity of the two debating agents, keyed by the backend's agent slug. */
export const AGENTS = {
  threat_hunting: {
    key: 'threat_hunting',
    name: 'Threat Hunting Agent',
    short: 'Threat Hunting',
    initials: 'TH',
    side: 'thesis',
  },
  troubleshooting: {
    key: 'troubleshooting',
    name: 'Network Troubleshooting Agent',
    short: 'Troubleshooting',
    initials: 'NT',
    side: 'antithesis',
  },
}

export function agentInfo(key) {
  return (
    AGENTS[key] ?? {
      key: key ?? 'unknown',
      name: titleCase(key ?? 'Unknown agent'),
      short: titleCase(key ?? 'Unknown'),
      initials: '??',
      side: 'thesis',
    }
  )
}

/** The agent that raised a challenge is whichever one was not challenged. */
export function challengerOf(challengedAgentKey) {
  return challengedAgentKey === 'threat_hunting'
    ? AGENTS.troubleshooting
    : AGENTS.threat_hunting
}
