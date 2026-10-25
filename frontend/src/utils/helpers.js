export const getValue = (source, keys) => {
  for (const key of keys) {
    if (source?.[key] !== undefined && source[key] !== null && source[key] !== '') {
      return source[key]
    }
  }
  return null
}

export const normalizeList = (payload, key) => {
  if (Array.isArray(payload)) {
    return payload
  }
  if (Array.isArray(payload?.[key])) {
    return payload[key]
  }
  if (Array.isArray(payload?.data)) {
    return payload.data
  }
  return []
}

export const formatValue = (value) => value ?? 'Not reported'

export const formatWithUnit = (value, unit) =>
  value === undefined || value === null ? 'Not reported' : `${value} ${unit}`

export const formatProbability = (value) => {
  if (value === undefined || value === null || Number.isNaN(Number(value))) {
    return 'Not reported'
  }
  return `${(Number(value) * 100).toFixed(1)}%`
}

export const formatConfidence = (value) => {
  if (value === undefined || value === null || Number.isNaN(Number(value))) {
    return 'Not reported'
  }
  const num = Number(value)
  if (num > 0 && num <= 1.0) {
    return `${(num * 100).toFixed(1)}%`
  }
  return `${num.toFixed(1)}%`
}

export const formatDateTime = (value) => {
  if (!value) {
    return 'Not reported'
  }
  try {
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) {
      return String(value)
    }
    return date.toLocaleString()
  } catch {
    return String(value)
  }
}

export const getSeverityBadgeClass = (severity) => {
  const normalized = String(severity ?? '').toLowerCase()
  if (normalized === 'high') {
    return 'badge badge-severity-high'
  }
  if (normalized === 'medium') {
    return 'badge badge-severity-medium'
  }
  if (normalized === 'low') {
    return 'badge badge-severity-low'
  }
  return 'badge badge-default'
}

export const getStatusBadgeClass = (status) => {
  const normalized = String(status ?? '').toLowerCase()
  if (normalized === 'new') {
    return 'badge badge-status-new'
  }
  if (normalized === 'resolved') {
    return 'badge badge-status-resolved'
  }
  return 'badge badge-default'
}

export const normalizeScannerStatus = (payload) => payload?.scanner ?? payload?.status ?? payload ?? {}

export const normalizeCaptureStatus = (payload) => payload?.capture ?? payload?.status ?? payload ?? {}

export const getInterfaceName = (source) => getValue(source, ['name', 'interface', 'interface_name'])

export const getScannerState = (scannerStatus) =>
  String(getValue(scannerStatus, ['state', 'scanner_state', 'status']) ?? 'stopped').toLowerCase()

export const getCaptureState = (captureStatus) =>
  String(getValue(captureStatus, ['state', 'capture_state', 'status']) ?? 'stopped').toLowerCase()

export const normalizeCounts = (counts) =>
  counts && typeof counts === 'object' && !Array.isArray(counts) ? counts : {}

export const formatFileSize = (bytes) => {
  if (!bytes || Number.isNaN(Number(bytes))) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  let size = Number(bytes)
  let unitIndex = 0
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024
    unitIndex++
  }
  return `${size.toFixed(1)} ${units[unitIndex]}`
}

export const getCategoryBadgeClass = (category) => {
  const norm = String(category || '').toLowerCase()
  if (norm.includes('deauth')) return 'badge badge-cat-deauth'
  if (norm.includes('disas')) return 'badge badge-cat-disas'
  if (norm.includes('assoc')) return 'badge badge-cat-reassoc'
  if (norm.includes('rogue')) return 'badge badge-cat-rogueap'
  if (norm.includes('attack')) return 'badge badge-cat-attack'
  return 'badge badge-cat-normal'
}

export const getRecommendationBadgeClass = (classification) => {
  const normalized = String(classification ?? '').toUpperCase()
  if (normalized === 'EXCELLENT') return 'badge badge-rec-excellent'
  if (normalized === 'GOOD') return 'badge badge-rec-good'
  if (normalized === 'FAIR') return 'badge badge-rec-fair'
  if (normalized === 'POOR') return 'badge badge-rec-poor'
  return 'badge badge-default'
}

export const generateAdvisorResponse = (rawQuery, networks, bestNet, _modelInfo) => {
  const q = String(rawQuery || '').toLowerCase().trim()
  const totalNets = networks?.length || 0

  if (!networks || networks.length === 0) {
    return 'No active Wi-Fi networks found in the current scan snapshot. Please run a Wi-Fi scan in the "Wi-Fi Scan" tab first.'
  }

  if (q.includes('best') || q.includes('recommend') || q.includes('top') || q.includes('which should i connect')) {
    if (!bestNet) {
      return 'The ML recommendation engine is currently evaluating networks. Please wait for inference to complete.'
    }
    const reasons = bestNet.positive_factors?.length ? bestNet.positive_factors.join('; ') : 'High signal strength and robust WPA security'
    return `Top Recommendation: **${bestNet.ssid || 'Hidden SSID'}** (${bestNet.bssid || 'Unknown BSSID'})\n\n• ML Quality Tier: ${bestNet.classification}\n• ML Score: ${bestNet.score?.toFixed(1) || '--'}/100\n• Signal: ${bestNet.signal}\n• Band: ${bestNet.band || '2.4 GHz'} (Ch ${bestNet.channel})\n• Security: ${bestNet.security}\n• Why: ${reasons}`
  }

  if (q.includes('5ghz') || q.includes('5 ghz') || q.includes('fast')) {
    const fiveGhz = networks.filter((n) => n.band === '5 GHz' || (n.channel && n.channel >= 36))
    if (!fiveGhz.length) {
      return `Currently, none of the ${totalNets} scanned networks are on the 5 GHz band. All observed APs are operating on 2.4 GHz (channels 1-14).`
    }
    const list = fiveGhz.slice(0, 3).map((n) => `• **${n.ssid}** (Ch ${n.channel}, ${n.signal}, Tier: ${n.classification})`).join('\n')
    return `Found ${fiveGhz.length} network(s) on the 5 GHz band:\n\n${list}\n\n5 GHz networks generally offer wider channel bandwidth and lower interference.`
  }

  if (q.includes('secure') || q.includes('safe') || q.includes('risk') || q.includes('hack') || q.includes('threat')) {
    const openNets = networks.filter((n) => String(n.security || '').toLowerCase().includes('open') || !n.security)
    if (openNets.length > 0) {
      const names = openNets.map((n) => n.ssid || '<Hidden>').join(', ')
      return `Security Warning: ${openNets.length} network(s) are completely OPEN without encryption (${names}). Connecting to open Wi-Fi exposes traffic to eavesdropping and evil twin attacks.`
    }
    return `All ${totalNets} scanned networks currently use WPA/WPA2/WPA3 encryption. No unencrypted open networks were detected.`
  }

  if (q.includes('model') || q.includes('accuracy') || q.includes('features') || q.includes('algorithm')) {
    return `The Wi-Fi Network Recommendation model is a Random Forest classifier trained on 12 IEEE 802.11 QoS and security metrics, separate from the AWID3 intrusion detection model. It classifies networks into EXCELLENT, GOOD, FAIR, or POOR tiers.`
  }

  return `I analyzed all ${totalNets} scanned networks. The highest rated network is **${bestNet?.ssid || 'None'}** with an ML score of ${bestNet?.score?.toFixed(1) || '--'}/100 (${bestNet?.classification || 'N/A'}). Ask me about 5 GHz networks, security risks, or ranking criteria!`
}
