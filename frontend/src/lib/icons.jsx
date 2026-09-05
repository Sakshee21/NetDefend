/* Inline SVG icon set. Stroke-based, inherits currentColor and font size. */

const base = {
  width: 16,
  height: 16,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
  focusable: false,
}

export const IconShield = (props) => (
  <svg {...base} {...props}>
    <path d="M12 3 5 6v5.5c0 4.6 3 7.9 7 9 4-1.1 7-4.4 7-9V6l-7-3Z" />
    <path d="m9 12 2.2 2.2L15.5 10" />
  </svg>
)

export const IconUpload = (props) => (
  <svg {...base} {...props}>
    <path d="M12 15V4" />
    <path d="m8 8 4-4 4 4" />
    <path d="M4 14v4.5A1.5 1.5 0 0 0 5.5 20h13a1.5 1.5 0 0 0 1.5-1.5V14" />
  </svg>
)

export const IconFlow = (props) => (
  <svg {...base} {...props}>
    <circle cx="5" cy="12" r="2.2" />
    <circle cx="19" cy="6" r="2.2" />
    <circle cx="19" cy="18" r="2.2" />
    <path d="M7.2 11.2 16.8 6.8" />
    <path d="m7.2 12.8 9.6 4.4" />
  </svg>
)

export const IconDebate = (props) => (
  <svg {...base} {...props}>
    <path d="M4 5h9a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H8l-4 3V5Z" />
    <path d="M17 9h3v6a2 2 0 0 1-2 2h-1l-3 2v-2" />
  </svg>
)

export const IconReport = (props) => (
  <svg {...base} {...props}>
    <path d="M14 3H7a1.5 1.5 0 0 0-1.5 1.5v15A1.5 1.5 0 0 0 7 21h10a1.5 1.5 0 0 0 1.5-1.5V7.5L14 3Z" />
    <path d="M14 3v4.5h4.5" />
    <path d="M8.5 13h7M8.5 16.5h4.5" />
  </svg>
)

export const IconHistory = (props) => (
  <svg {...base} {...props}>
    <path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1" />
    <path d="M3.5 4.5V9h4.5" />
    <path d="M12 8v4.4l3 1.8" />
  </svg>
)

export const IconCheck = (props) => (
  <svg {...base} {...props}>
    <path d="m5 12.5 4.5 4.5L19 7" />
  </svg>
)

export const IconAlert = (props) => (
  <svg {...base} {...props}>
    <path d="M12 4.5 3.2 19.5h17.6L12 4.5Z" />
    <path d="M12 10v4" />
    <path d="M12 17.2h.01" />
  </svg>
)

export const IconFile = (props) => (
  <svg {...base} {...props}>
    <path d="M13.5 3H7a1.5 1.5 0 0 0-1.5 1.5v15A1.5 1.5 0 0 0 7 21h10a1.5 1.5 0 0 0 1.5-1.5V8L13.5 3Z" />
    <path d="M13.5 3v5H18.5" />
  </svg>
)

export const IconX = (props) => (
  <svg {...base} {...props}>
    <path d="m6 6 12 12M18 6 6 18" />
  </svg>
)

export const IconDownload = (props) => (
  <svg {...base} {...props}>
    <path d="M12 4v10" />
    <path d="m8 10 4 4 4-4" />
    <path d="M5 19h14" />
  </svg>
)

export const IconCopy = (props) => (
  <svg {...base} {...props}>
    <rect x="9" y="9" width="11" height="11" rx="2" />
    <path d="M15 5.5A1.5 1.5 0 0 0 13.5 4h-7A2.5 2.5 0 0 0 4 6.5v7A1.5 1.5 0 0 0 5.5 15" />
  </svg>
)

export const IconTarget = (props) => (
  <svg {...base} {...props}>
    <circle cx="12" cy="12" r="8" />
    <circle cx="12" cy="12" r="3.2" />
    <path d="M12 2v3M12 19v3M2 12h3M19 12h3" />
  </svg>
)

export const IconWrench = (props) => (
  <svg {...base} {...props}>
    <path d="M15.5 3.8a5 5 0 0 0-6.1 6.4L3.9 15.7a2 2 0 0 0 2.8 2.8l5.5-5.5a5 5 0 0 0 6.4-6.1l-3 3-2.6-.7-.7-2.6 3.2-2.8Z" />
  </svg>
)

export const IconGavel = (props) => (
  <svg {...base} {...props}>
    <path d="M4 20h9" />
    <path d="m6.5 9.5 5 5" />
    <rect x="8.2" y="4.6" width="7" height="4" rx="1" transform="rotate(45 11.7 6.6)" />
    <rect x="13.4" y="9.8" width="7" height="4" rx="1" transform="rotate(45 16.9 11.8)" />
  </svg>
)

export const IconPackets = (props) => (
  <svg {...base} {...props}>
    <rect x="3" y="9" width="5" height="6" rx="1" />
    <rect x="16" y="9" width="5" height="6" rx="1" />
    <path d="M9.5 12h5" />
    <path d="M11 5.5h2M11 18.5h2" />
  </svg>
)

export const IconBrain = (props) => (
  <svg {...base} {...props}>
    <path d="M9.5 4.5A2.5 2.5 0 0 0 7 7a2.5 2.5 0 0 0-1.5 4.5A2.5 2.5 0 0 0 7 16a2.5 2.5 0 0 0 2.5 3.5V4.5Z" />
    <path d="M14.5 4.5A2.5 2.5 0 0 1 17 7a2.5 2.5 0 0 1 1.5 4.5A2.5 2.5 0 0 1 17 16a2.5 2.5 0 0 1-2.5 3.5V4.5Z" />
  </svg>
)

export const IconSiren = (props) => (
  <svg {...base} {...props}>
    <path d="M6.5 15a5.5 5.5 0 0 1 11 0v2h-11v-2Z" />
    <path d="M4.5 20h15" />
    <path d="M12 5.5V3M5.6 8 4 6.6M18.4 8 20 6.6" />
  </svg>
)
