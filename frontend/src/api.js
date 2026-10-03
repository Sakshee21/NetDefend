/* =============================================================================
 * NetDefend API client
 * =============================================================================
 * The backend contract is FastAPI:
 *
 *   POST /analyze   multipart/form-data
 *     pcap          -> the capture file            (required)
 *     router_log    -> router log file             (optional)
 *     firewall_log  -> firewall log file           (optional)
 *   -> 200 application/json  (see MOCK_REPORT below for the exact shape)
 *
 * Everything under the MOCK DATA banner is throwaway sample data. The only line
 * you change to go live is USE_MOCK_API.
 * ========================================================================== */

// >>> REAL API INTEGRATION: flip this to false and the app talks to FastAPI. <<<
export const USE_MOCK_API = false

// The Vite dev server proxies /analyze to http://127.0.0.1:8000 (vite.config.js).
// In production, set VITE_API_BASE_URL to the FastAPI origin.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? ''

/** Simulated round-trip latency for the mock, in milliseconds. */
const MOCK_LATENCY_MS = 7600

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/* -----------------------------------------------------------------------------
 * analyzeIncident(files)
 *   files:   { pcap: File, routerLog: File|null, firewallLog: File|null }
 *   returns: Promise<IncidentReport>
 * -------------------------------------------------------------------------- */
export async function analyzeIncident(files) {
  if (USE_MOCK_API) return mockAnalyzeIncident(files)

  const body = new FormData()
  body.append('pcap', files.pcap)
  if (files.routerLog) body.append('router_log', files.routerLog)
  if (files.firewallLog) body.append('firewall_log', files.firewallLog)

  const response = await fetch(`${API_BASE_URL}/analyze`, { method: 'POST', body })
  if (!response.ok) {
    const detail = await response.text().catch(() => '')
    throw new Error(`Analysis failed (HTTP ${response.status}). ${detail}`.trim())
  }
  return response.json()
}

/* -----------------------------------------------------------------------------
 * History endpoints. Placeholders for GET /incidents and GET /incidents/{id},
 * which the backend does not expose yet. Same swap point as above.
 * -------------------------------------------------------------------------- */
export async function fetchHistory() {
  if (USE_MOCK_API) {
    await sleep(240)
    return MOCK_HISTORY
  }
  const response = await fetch(`${API_BASE_URL}/incidents`)
  if (!response.ok) throw new Error(`Could not load history (HTTP ${response.status}).`)
  return response.json()
}

export async function fetchIncident(incidentId) {
  if (USE_MOCK_API) {
    await sleep(160)
    return MOCK_HISTORY.find((incident) => incident.incident_id === incidentId) ?? null
  }
  const response = await fetch(`${API_BASE_URL}/incidents/${incidentId}`)
  if (!response.ok) throw new Error(`Could not load ${incidentId} (HTTP ${response.status}).`)
  return response.json()
}

/* =============================================================================
 * MOCK DATA — remove this whole block once the backend is wired up.
 * ========================================================================== */

async function mockAnalyzeIncident(files) {
  if (!files?.pcap) throw new Error('A PCAP file is required to run the pipeline.')
  await sleep(MOCK_LATENCY_MS)
  // Demo toggle: ?mock=uncertain returns the UNCERTAIN/escalation scenario,
  // anything else returns the ACL MISCONFIGURATION scenario.
  let variant = 'misconfig'
  try {
    if (new URLSearchParams(window.location.search).get('mock') === 'uncertain') {
      variant = 'uncertain'
    }
  } catch {
    /* no window (SSR/tests) — fall back to the default variant */
  }
  const base = variant === 'uncertain' ? MOCK_REPORT_UNCERTAIN : MOCK_REPORT
  return {
    ...base,
    // Freshen the ID and timestamp so repeat runs read as distinct incidents.
    incident_id: `INC-${new Date().getFullYear()}-${String(Math.floor(Math.random() * 9000) + 1000)}`,
    timestamp: new Date().toISOString(),
    source_files: {
      pcap: files.pcap?.name ?? null,
      router_log: files.routerLog?.name ?? null,
      firewall_log: files.firewallLog?.name ?? null,
    },
  }
}

/** The canonical backend response shape. Default demo scenario: the ACL
 *  misconfiguration that the real pipeline is built around. */
export const MOCK_REPORT = {
  incident_id: 'INC-2026-0847',
  classification: 'MISCONFIGURATION',
  risk_level: 'MEDIUM',
  confidence: 0.85,
  mitre_ttp: null,
  threat_hypothesis: {
    summary:
      'Repeated SYN probes to 10.0.0.2:8000 with no replies could be a low-rate service scan.',
    evidence: [
      '20 SYN packets across 10 flows to 10.0.0.2:8000, 0 SYN-ACKs',
      'Pattern labelled repeated_blocked_attempts over a 28s window',
    ],
  },
  misconfig_hypothesis: {
    summary:
      'An iptables DROP rule is blocking legitimate TCP traffic to 10.0.0.2:8000.',
    taxonomy_category: 'ACL_FIREWALL',
    evidence: [
      'Firewall log: DROP rule pkts rose from 0 to 20 after traffic was generated',
      'Absence of SYN-ACKs is the signature of a silent drop, not a refusal',
      'Random Forest labels the flow Benign (attack probability 0.11)',
    ],
  },
  refutation_exchange: [
    {
      challenged_agent: 'threat_hunting',
      challenge:
        'The firewall log shows a DROP rule matched exactly 20 packets to 10.0.0.2:8000. How is that a scan rather than blocked legitimate traffic?',
      response:
        'A dropped SYN is still a SYN an attacker chose to send; the 20-packet budget fits a deliberate low-rate probe. But no follow-on activity is present.',
    },
    {
      challenged_agent: 'troubleshooting',
      challenge:
        'If this is just a misconfiguration, why does the ML model see a repeated_blocked_attempts pattern at all?',
      response:
        'That pattern is exactly what a DROP rule produces: repeated unanswered SYNs from a legitimate client whose traffic the firewall silently discards.',
    },
  ],
  recommended_action:
    'Review and correct the iptables DROP rule blocking TCP traffic to 10.0.0.2 on port 8000. Confirm whether the block is intentional; if not, reposition or remove it so the legitimate service path is restored, then retest connectivity.',
  affected_host: '10.0.0.2',
  timestamp: '2026-09-05T14:23:41Z',
}

/** Second demo scenario (?mock=uncertain): the arbiter could not separate
 *  the two hypotheses, so the incident is escalated for human review. */
export const MOCK_REPORT_UNCERTAIN = {
  incident_id: 'INC-2026-0851',
  classification: 'UNCERTAIN',
  risk_level: 'MEDIUM',
  confidence: 0.54,
  mitre_ttp: null,
  threat_hypothesis: {
    summary: 'Repeated SYN-only attempts to 10.0.0.2:8000 could be reconnaissance.',
    evidence: [
      '20 SYN packets, 0 SYN-ACKs, across 10 flows to 10.0.0.2:8000',
      'No LOG entries despite the DROP counter advancing',
    ],
  },
  misconfig_hypothesis: {
    summary: 'A DROP rule with no LOG target is silently blocking the traffic.',
    taxonomy_category: 'ACL_FIREWALL',
    evidence: [
      'DROP counter rose 0 -> 20; no matching LOG line exists',
      'Benign ML scores are consistent with a blocked legitimate client',
    ],
  },
  refutation_exchange: [
    {
      challenged_agent: 'threat_hunting',
      challenge:
        'With no LOG entries and only 20 SYNs, what distinguishes this from a benign client hitting a drop rule?',
      response:
        'Nothing conclusive — the volume is too low to separate a cautious probe from a blocked legitimate client on this evidence alone.',
    },
    {
      challenged_agent: 'troubleshooting',
      challenge:
        'Can you prove the DROP is misconfigured rather than an intended block of hostile traffic?',
      response:
        'Not from this capture — the rule could be deliberate. The log lacks the LOG target that would confirm intent.',
    },
  ],
  recommended_action:
    'Route this incident to a human analyst. Obtain the full iptables ruleset for 10.0.0.2:8000 (including whether the DROP is intentional) and a longer capture to confirm whether the SYN source is a legitimate client before classifying.',
  escalation_note:
    'Verdict is UNCERTAIN — neither hypothesis clearly survived cross-examination on the available evidence. Recommend human analyst review; risk cannot be firmly assessed until the block’s intent is confirmed.',
  affected_host: '10.0.0.2',
  timestamp: '2026-09-05T15:10:22Z',
}

/** Past analyses backing the history sidebar. */
export const MOCK_HISTORY = [
  MOCK_REPORT,
  {
    incident_id: 'INC-2026-0846',
    classification: 'MISCONFIGURATION',
    risk_level: 'MEDIUM',
    confidence: 0.81,
    mitre_ttp: null,
    threat_hypothesis: {
      summary: 'Repeated failed authentication could indicate password spraying',
      evidence: [
        '312 failed RADIUS authentications in 6 minutes',
        'Attempts originate from a single source address',
      ],
    },
    misconfig_hypothesis: {
      summary: 'Stale RADIUS shared secret on the branch switch after a credential rotation',
      taxonomy_category: 'Authentication Misconfiguration',
      evidence: [
        'Failures began 3 minutes after the scheduled secret rotation window',
        'Every failure carries the same reject reason code',
        'Source is a managed switch, not an end-user host',
      ],
    },
    refutation_exchange: [
      {
        challenged_agent: 'threat_hunting',
        challenge: 'If this is password spraying, why is only one account referenced?',
        response:
          'Single-account targeting is unusual for spraying; the volume is better explained by an automated retry loop.',
      },
      {
        challenged_agent: 'troubleshooting',
        challenge: 'If the secret is stale, why did failures continue past the retry backoff?',
        response:
          'The switch firmware ignores backoff for RADIUS rejects, so retries continue at a fixed interval.',
      },
    ],
    recommended_action:
      'Re-push the RADIUS shared secret to switch sw-branch-04 and confirm authentication recovers within one retry interval.',
    affected_host: '10.20.4.11',
    timestamp: '2026-09-04T09:12:07Z',
  },
  {
    incident_id: 'INC-2026-0845',
    classification: 'UNCERTAIN',
    risk_level: 'MEDIUM',
    confidence: 0.54,
    mitre_ttp: {
      id: 'T1071.004',
      name: 'Application Layer Protocol: DNS',
    },
    threat_hypothesis: {
      summary: 'High-entropy DNS TXT queries suggest tunnelling for data exfiltration',
      evidence: [
        'Mean subdomain entropy of 4.1 bits per character',
        'TXT record queries account for 68 percent of resolver traffic',
      ],
    },
    misconfig_hypothesis: {
      summary: 'Endpoint security agent is using DNS as a telemetry fallback channel',
      taxonomy_category: 'DNS Resolver Misconfiguration',
      evidence: [
        'All queries resolve under a single vendor telemetry domain',
        'The host lost its HTTPS egress route in the same interval',
      ],
    },
    refutation_exchange: [
      {
        challenged_agent: 'threat_hunting',
        challenge: 'If this is exfiltration, why is the destination domain vendor-owned?',
        response:
          'Vendor domains are reachable through hijacked infrastructure, though no such compromise is visible in this capture.',
      },
      {
        challenged_agent: 'troubleshooting',
        challenge:
          'If this is telemetry fallback, why did volume not drop when egress recovered?',
        response:
          'The agent caches a fallback channel for a fixed window, and the capture ends before that window closes.',
      },
    ],
    recommended_action:
      'Capture a further 30 minutes of traffic after HTTPS egress is restored, then re-run the pipeline before escalating.',
    affected_host: '192.168.7.22',
    timestamp: '2026-09-03T18:44:52Z',
  },
  {
    incident_id: 'INC-2026-0844',
    classification: 'ATTACK',
    risk_level: 'CRITICAL',
    confidence: 0.94,
    mitre_ttp: {
      id: 'T1046',
      name: 'Network Service Discovery',
    },
    threat_hypothesis: {
      summary: 'Full TCP port sweep of the server VLAN from a compromised workstation',
      evidence: [
        '4,812 SYN packets to 1,024 distinct ports in 90 seconds',
        'No completed handshakes on any closed port',
        'Scan source is a workstation with no scanning role',
      ],
    },
    misconfig_hypothesis: {
      summary: 'Newly deployed vulnerability scanner running outside its maintenance window',
      taxonomy_category: 'Scan Policy Misconfiguration',
      evidence: ['A scanner rollout ticket was open during the same week'],
    },
    refutation_exchange: [
      {
        challenged_agent: 'troubleshooting',
        challenge:
          'If this is the scanner, why does the source address sit outside the scanner pool?',
        response:
          'No inventory record places a scanner at this address, so the misconfiguration hypothesis is unsupported.',
      },
      {
        challenged_agent: 'threat_hunting',
        challenge: 'If this is discovery, why is there no follow-on exploitation traffic?',
        response:
          'The capture window closes 90 seconds after the sweep, before follow-on activity would be expected.',
      },
    ],
    recommended_action:
      'Isolate 192.168.3.87 from the server VLAN and begin host forensics on the scanning process tree.',
    affected_host: '192.168.3.87',
    timestamp: '2026-09-02T22:05:19Z',
  },
  {
    incident_id: 'INC-2026-0843',
    classification: 'MISCONFIGURATION',
    risk_level: 'LOW',
    confidence: 0.88,
    mitre_ttp: null,
    threat_hypothesis: {
      summary: 'Broadcast storm could be a denial of service attempt against the access layer',
      evidence: ['ARP broadcast volume 40 times above the seven-day baseline'],
    },
    misconfig_hypothesis: {
      summary: 'Spanning tree loop introduced when a redundant uplink was patched without STP',
      taxonomy_category: 'Layer 2 Loop',
      evidence: [
        'Two ports on vlan 30 report identical MAC address flapping',
        'Onset matches a patch-panel change logged at 11:47 IST',
        'Traffic is entirely broadcast with no unicast payload',
      ],
    },
    refutation_exchange: [
      {
        challenged_agent: 'threat_hunting',
        challenge: 'If this is a denial of service, why is there no external source address?',
        response:
          'Every frame originates inside vlan 30, which does not fit an external denial of service attempt.',
      },
    ],
    recommended_action:
      'Enable spanning tree on the newly patched uplink of sw-access-12 and confirm broadcast volume returns to baseline.',
    affected_host: '10.30.0.4',
    timestamp: '2026-09-01T11:51:33Z',
  },
]
