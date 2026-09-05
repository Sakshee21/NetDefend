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
export const USE_MOCK_API = true

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
  return {
    ...MOCK_REPORT,
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

/** The canonical backend response shape. */
export const MOCK_REPORT = {
  incident_id: 'INC-2026-0847',
  classification: 'ATTACK',
  risk_level: 'HIGH',
  confidence: 0.89,
  mitre_ttp: {
    id: 'T1021.002',
    name: 'SMB/Windows Admin Shares',
  },
  threat_hypothesis: {
    summary: 'Port 445 traffic indicates SMB lateral movement',
    evidence: [
      'Unusual internal SMB session volume',
      'Sequential host access pattern across 5 hosts in 40 seconds',
    ],
  },
  misconfig_hypothesis: {
    summary: 'ACL rule change may have misrouted backup traffic',
    taxonomy_category: 'ACL Misconfiguration',
    evidence: ['ACL rule pushed at 14:02 IST', 'Timestamp correlates with anomaly onset'],
  },
  refutation_exchange: [
    {
      challenged_agent: 'threat_hunting',
      challenge: 'If this is an attack, where is the outbound C2 beacon in the PCAP?',
      response:
        'No outbound C2 beacon found, but sequential access pattern across 5 hosts is inconsistent with normal backup behavior.',
    },
    {
      challenged_agent: 'troubleshooting',
      challenge:
        'If this is a misconfiguration, why do TCP flags show non-standard SYN scan behavior?',
      response:
        'SYN pattern is consistent with backup software reconnection attempts due to misrouted subnet.',
    },
  ],
  recommended_action:
    'Block outbound UDP port 53 on host 192.168.1.45; inspect DNS query history for the last 72 hours.',
  affected_host: '192.168.1.45',
  timestamp: '2026-09-05T14:23:41Z',
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
