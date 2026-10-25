import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import './App.css'

const sidebarItems = [
  'Dashboard',
  'WiFi Scan',
  'Live Monitor',
  'ML Engine',
  'PCAP Analysis',
  'Network Recommendations',
  'Incidents',
  'Reports',
  'Settings',
]


const API_BASE_URL = 'http://127.0.0.1:5000/api'
const ACTIVE_SCANNER_STATES = ['starting', 'running', 'stopping']
const ACTIVE_CAPTURE_STATES = ['starting', 'running', 'stopping']

const getValue = (source, keys) => {
  for (const key of keys) {
    if (source?.[key] !== undefined && source[key] !== null && source[key] !== '') {
      return source[key]
    }
  }

  return null
}

const normalizeList = (payload, key) => {
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

const formatValue = (value) => value ?? 'Not reported'

const formatWithUnit = (value, unit) => (value === undefined || value === null ? 'Not reported' : `${value} ${unit}`)

const formatProbability = (value) => {
  if (value === undefined || value === null || Number.isNaN(Number(value))) {
    return 'Not reported'
  }

  return `${(Number(value) * 100).toFixed(1)}%`
}

const formatConfidence = (value) => {
  if (value === undefined || value === null || Number.isNaN(Number(value))) {
    return 'Not reported'
  }
  const num = Number(value)
  if (num > 0 && num <= 1.0) {
    return `${(num * 100).toFixed(1)}%`
  }
  return `${num.toFixed(1)}%`
}

const formatDateTime = (value) => {
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

const getSeverityBadgeClass = (severity) => {
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

const getStatusBadgeClass = (status) => {
  const normalized = String(status ?? '').toLowerCase()
  if (normalized === 'new') {
    return 'badge badge-status-new'
  }
  if (normalized === 'resolved') {
    return 'badge badge-status-resolved'
  }

  return 'badge badge-default'
}

const normalizeScannerStatus = (payload) => payload?.scanner ?? payload?.status ?? payload ?? {}

const normalizeCaptureStatus = (payload) => payload?.capture ?? payload?.status ?? payload ?? {}

const getInterfaceName = (source) => getValue(source, ['name', 'interface', 'interface_name'])

const getScannerState = (scannerStatus) =>
  String(getValue(scannerStatus, ['state', 'scanner_state', 'status']) ?? 'stopped').toLowerCase()

const getCaptureState = (captureStatus) =>
  String(getValue(captureStatus, ['state', 'capture_state', 'status']) ?? 'stopped').toLowerCase()

const normalizeCounts = (counts) =>
  counts && typeof counts === 'object' && !Array.isArray(counts) ? counts : {}

const formatFileSize = (bytes) => {
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

const getCategoryBadgeClass = (category) => {
  const norm = String(category || '').toLowerCase()
  if (norm.includes('deauth')) return 'badge badge-cat-deauth'
  if (norm.includes('disas')) return 'badge badge-cat-disas'
  if (norm.includes('assoc')) return 'badge badge-cat-reassoc'
  if (norm.includes('rogue')) return 'badge badge-cat-rogueap'
  if (norm.includes('attack')) return 'badge badge-cat-attack'
  return 'badge badge-cat-normal'
}

const getRecommendationBadgeClass = (classification) => {
  const norm = String(classification || '').toUpperCase()
  if (norm === 'EXCELLENT') return 'badge badge-rec-excellent'
  if (norm === 'GOOD') return 'badge badge-rec-good'
  if (norm === 'FAIR') return 'badge badge-rec-fair'
  if (norm === 'POOR') return 'badge badge-rec-poor'
  return 'badge badge-default'
}

const generateAdvisorResponse = (rawQuery, networks, bestNet, modelInfo) => {
  const query = (rawQuery || '').toLowerCase().trim()
  const total = networks ? networks.length : 0

  if (!networks || total === 0 || !bestNet) {
    return 'No Wi-Fi scan data is currently available. Please click "Run Wi-Fi Scan" to discover nearby access points, or "Refresh Recommendations" if a scan was already conducted.'
  }

  // 1. Why is #1 recommended / ranking factors
  if (query.includes('why') || query.includes('recommend') || query.includes('#1') || query.includes('best') || query.includes('winner') || query.includes('top')) {
    const strengths = (bestNet.positive_factors && bestNet.positive_factors.length > 0)
      ? bestNet.positive_factors.map((f) => `• ${f}`).join('\n')
      : '• Strong signal and standard encryption.'
    const caveats = (bestNet.negative_factors && bestNet.negative_factors.length > 0)
      ? `\n\nPotential caveats to note:\n${bestNet.negative_factors.map((f) => `• ${f}`).join('\n')}`
      : ''
    return `Based on empirical IEEE 802.11 scan metrics evaluated by NetShield's 100-tree Random Forest model, **${bestNet.ssid}** is ranked #1 with an ML Recommendation Score of **${bestNet.score.toFixed(1)}/100** (${bestNet.classification} tier, ${formatConfidence(bestNet.confidence_pct)} model confidence).\n\nKey empirical factors:\n${strengths}\n• Link Budget: ${bestNet.signal} (${bestNet.band}, Channel ${bestNet.channel})\n• Encryption: ${bestNet.security}${caveats}`
  }

  // 2. Security / Safety / Banking / Work
  if (query.includes('safe') || query.includes('secure') || query.includes('security') || query.includes('bank') || query.includes('work') || query.includes('hack') || query.includes('vpn')) {
    const isWpa3 = String(bestNet.security).toUpperCase().includes('WPA3')
    const isOpen = String(bestNet.security).toLowerCase().includes('open')
    const encRank = bestNet.security_rank ?? (isWpa3 ? 4 : isOpen ? 0 : 3)

    return `Security Assessment for **${bestNet.ssid}**:\n• Protocol: **${bestNet.security}** (Security Rank: ${encRank}/4)\n• ML Classification: **${bestNet.classification}** (Confidence: ${formatConfidence(bestNet.confidence_pct)})\n\n⚠️ **Important Security Note**: High ML confidence represents algorithmic certainty across the 12 extracted IEEE 802.11 features—it does **NOT** guarantee immunity from active attacks, rogue AP evil-twins, or packet injection. For sensitive activities like banking or corporate access, always verify the AP identity and use an encrypted VPN alongside TLS/HTTPS.`
  }

  // 3. 5 GHz vs 2.4 GHz / Speed / Band
  if (query.includes('5 ghz') || query.includes('5g') || query.includes('2.4') || query.includes('speed') || query.includes('band') || query.includes('fast')) {
    const fiveGList = networks.filter((n) => n.band === '5 GHz')
    if (fiveGList.length > 0) {
      const top5g = fiveGList[0]
      const names = fiveGList.map((n) => `**${n.ssid}** (${n.signal}, Ch ${n.channel})`).slice(0, 4).join(', ')
      return `Found **${fiveGList.length}** access point(s) operating on the **5 GHz band**: ${names}.\n\n5 GHz networks provide wider channel bandwidth (20/40/80 MHz) and lower co-channel interference compared to the crowded 2.4 GHz spectrum. The top 5 GHz network is **${top5g.ssid}** (Score: ${top5g.score.toFixed(1)}/100).`
    }
    return `No 5 GHz networks were detected in this scan snapshot. All **${total}** detected networks operate on the 2.4 GHz band (Channels 1–14), which has higher range but greater susceptibility to microwave/Bluetooth interference.`
  }

  // 4. Open / Unencrypted networks
  if (query.includes('open') || query.includes('public') || query.includes('free') || query.includes('unencrypt') || query.includes('password')) {
    const openList = networks.filter((n) => String(n.security).toLowerCase().includes('open') || n.is_open_network === 1)
    if (openList.length > 0) {
      const names = openList.map((n) => `**${n.ssid}** (${n.signal})`).join(', ')
      return `⚠️ Found **${openList.length}** unencrypted Open network(s): ${names}.\n\nOpen networks transmit all data without 802.11 frame encryption, making sessions vulnerable to eavesdropping and evil-twin interception. The Random Forest model strictly enforces a **maximum score cap of 58/100** for Open networks.`
    }
    return `Excellent: All **${total}** scanned networks enforce password authentication (WPA2/WPA3). No unencrypted Open networks were detected in this scan.`
  }

  // 5. ML Confidence explanation
  if (query.includes('confidence') || query.includes('pct') || query.includes('probability') || query.includes('model') || query.includes('accuracy')) {
    return `The model confidence (${formatConfidence(bestNet.confidence_pct)}) is the posterior class probability produced by the 100 Random Forest decision trees for the predicted category (${bestNet.classification}).\n\n• High confidence means the network's 12 IEEE 802.11 features match typical training examples of that quality tier.\n• Model Accuracy: ${modelInfo?.metrics?.accuracy_pct ?? '88.1'}% (evaluated on 320 unseen propagation test samples).\n• Critical distinction: Confidence measures **statistical classification certainty**, not physical security or trustworthiness.`
  }

  // 6. Compare networks / runner-up
  if (query.includes('compare') || query.includes('runner') || query.includes('second') || query.includes('versus') || query.includes('vs') || query.includes('other')) {
    if (networks.length < 2) {
      return `Only one network (**${bestNet.ssid}**) was found in the current scan snapshot. There are no runner-up networks to compare.`
    }
    const r2 = networks[1]
    const delta = (bestNet.score - r2.score).toFixed(1)
    return `Comparison between Rank #1 and Rank #2:\n• **#1 ${bestNet.ssid}**: Score ${bestNet.score.toFixed(1)}/100, Signal ${bestNet.signal}, ${bestNet.band} (Ch ${bestNet.channel}), ${bestNet.security}\n• **#2 ${r2.ssid}**: Score ${r2.score.toFixed(1)}/100, Signal ${r2.signal}, ${r2.band} (Ch ${r2.channel}), ${r2.security}\n\n**Score Delta**: ${bestNet.ssid} scored **+${delta} points** higher primarily due to ${bestNet.signal_dbm > r2.signal_dbm ? 'stronger link budget' : 'superior frequency band and lower channel contention'}.`
  }

  // 7. Channel / Congestion
  if (query.includes('channel') || query.includes('congestion') || query.includes('interference')) {
    const chCounts = {}
    networks.forEach((n) => {
      chCounts[n.channel] = (chCounts[n.channel] || 0) + 1
    })
    const crowded = Object.entries(chCounts).filter(([, count]) => count > 1)
    const crowdedSummary = crowded.length > 0
      ? crowded.map(([ch, count]) => `Channel ${ch} (${count} APs)`).join(', ')
      : 'No crowded channels detected'
    return `Channel Analysis:\n• Channel distribution: ${crowdedSummary}.\n• Top network **${bestNet.ssid}** is operating on **Channel ${bestNet.channel}** (${bestNet.band}).\n• Optimal non-overlapping 2.4 GHz channels are 1, 6, and 11. 5 GHz channels (36–165) provide cleaner dedicated spectrum.`
  }

  // Default overview
  const fiveGCount = networks.filter((n) => n.band === '5 GHz').length
  const secureCount = networks.filter((n) => !String(n.security).toLowerCase().includes('open')).length
  return `Current Wi-Fi Scan Summary:\n• Total Networks Analyzed: **${total}**\n• #1 Best Recommended: **${bestNet.ssid}** (${bestNet.score.toFixed(1)}/100, ${bestNet.classification})\n• 5 GHz High-Speed APs: **${fiveGCount}**\n• Secured Networks: **${secureCount}**\n\nYou can ask:\n• "Why is #1 recommended?"\n• "Is the best network safe for banking?"\n• "Which networks are on 5 GHz?"\n• "Are there any open Wi-Fi risks?"\n• "What does the ML confidence percentage mean?"`
}

function App() {
  const [uiPrefs, setUiPrefs] = useState(() => {
    try {
      const saved = localStorage.getItem('netshield_ui_prefs')
      if (saved) return JSON.parse(saved)
    } catch {}
    return {
      pollInterval: 2000,
      visualAlerts: true,
      soundAlerts: false,
      defaultView: 'Dashboard',
      tableDensity: 'compact',
    }
  })

  const [activeView, setActiveView] = useState(() => {
    try {
      const saved = localStorage.getItem('netshield_ui_prefs')
      if (saved) {
        const parsed = JSON.parse(saved)
        if (parsed.defaultView && sidebarItems.includes(parsed.defaultView)) {
          return parsed.defaultView
        }
      }
    } catch {}
    return 'Dashboard'
  })
  const [interfaces, setInterfaces] = useState([])
  const [adapterState, setAdapterState] = useState(null)
  const [networks, setNetworks] = useState([])
  const [scannerStatus, setScannerStatus] = useState({})
  const [captureStatus, setCaptureStatus] = useState({})
  const [packets, setPackets] = useState([])
  const [selectedInterfaceName, setSelectedInterfaceName] = useState('')
  const [selectedCaptureInterfaceName, setSelectedCaptureInterfaceName] = useState('')
  const [wifiScanLoading, setWifiScanLoading] = useState(false)
  const [wifiScanError, setWifiScanError] = useState('')
  const [scanSearch, setScanSearch] = useState('')
  const [scanFilter, setScanFilter] = useState('all')
  const [scannerActionLoading, setScannerActionLoading] = useState(false)
  const [liveMonitorLoading, setLiveMonitorLoading] = useState(false)
  const [liveMonitorError, setLiveMonitorError] = useState('')
  const [captureActionLoading, setCaptureActionLoading] = useState(false)
  const [mlLiveStatus, setMlLiveStatus] = useState(null)
  const [mlDetectionLoading, setMlDetectionLoading] = useState(false)
  const [mlDetectionError, setMlDetectionError] = useState('')
  const [mlDetectionTab, setMlDetectionTab] = useState('overview')
  const [mlEngineTab, setMlEngineTab] = useState('live')
  const [incidents, setIncidents] = useState([])
  const [incidentsLoading, setIncidentsLoading] = useState(false)
  const [incidentsError, setIncidentsError] = useState('')
  const [incidentSearch, setIncidentSearch] = useState('')
  const [incidentSeverityFilter, setIncidentSeverityFilter] = useState('all')
  const [incidentStatusFilter, setIncidentStatusFilter] = useState('all')
  const [selectedIncident, setSelectedIncident] = useState(null)
  const [incidentCopyStatus, setIncidentCopyStatus] = useState(null)
  const [incidentJsonExpanded, setIncidentJsonExpanded] = useState(false)
  const [reportIncidents, setReportIncidents] = useState([])
  const [reportsLoading, setReportsLoading] = useState(false)
  const [reportsError, setReportsError] = useState('')

  // Settings Configuration Center state
  const [settingsTab, setSettingsTab] = useState('general')
  const [settingsSaveMsg, setSettingsSaveMsg] = useState('')
  const [diagnosticsLoading, setDiagnosticsLoading] = useState(false)
  const [diagnosticsResult, setDiagnosticsResult] = useState(null)

  // PCAP Analysis state
  const [pcapSamples, setPcapSamples] = useState([])
  const [selectedPcapSample, setSelectedPcapSample] = useState('')
  const [selectedPcapFile, setSelectedPcapFile] = useState(null)
  const [pcapAnalyzing, setPcapAnalyzing] = useState(false)
  const [pcapError, setPcapError] = useState('')
  const [pcapResult, setPcapResult] = useState(null)
  const [pcapHistory, setPcapHistory] = useState([])
  const [pcapFilter, setPcapFilter] = useState('all')
  const [pcapTab, setPcapTab] = useState('timeline')
  const [pcapHistoryLoading, setPcapHistoryLoading] = useState(false)

  // ML Testing & Evaluation state
  const [mlDatasets, setMlDatasets] = useState([])
  const [selectedDataset, setSelectedDataset] = useState('')
  const [mlTestingLoading, setMlTestingLoading] = useState(false)
  const [mlTestingError, setMlTestingError] = useState('')
  const [mlTestingTab, setMlTestingTab] = useState('matrix')
  const [mlTestResult, setMlTestResult] = useState(null)
  const [mlTestRuns, setMlTestRuns] = useState([])
  const [mlSchemaInfo, setMlSchemaInfo] = useState(null)

  // Wi-Fi Recommendation & Connect state
  const [recommendationsData, setRecommendationsData] = useState(null)
  const [recommendationsLoading, setRecommendationsLoading] = useState(false)
  const [recommendationsError, setRecommendationsError] = useState('')
  const [recommendationModelInfo, setRecommendationModelInfo] = useState(null)
  const [recommendationFilter, setRecommendationFilter] = useState('all')
  const [recommendationSort, setRecommendationSort] = useState('score')
  const [connectModalNetwork, setConnectModalNetwork] = useState(null)
  const [connectPassword, setConnectPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [connectLoading, setConnectLoading] = useState(false)
  const [connectStatus, setConnectStatus] = useState(null)

  // Network Recommendations expandable sections (collapsed by default)
  const [showRankingExplanation, setShowRankingExplanation] = useState(false)
  const [showRunnerUpComparison, setShowRunnerUpComparison] = useState(false)
  const [showModelBreakdown, setShowModelBreakdown] = useState(false)

  // Floating AI Wi-Fi Advisor state
  const [advisorOpen, setAdvisorOpen] = useState(false)
  const [advisorMessages, setAdvisorMessages] = useState([
    {
      sender: 'advisor',
      text: 'Hello! I am NetShield’s AI Wi-Fi Advisor. I can analyze your scanned networks, explain why specific networks were ranked, evaluate security risks, and answer questions grounded strictly in your current Wi-Fi scan data.',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ])
  const [advisorInput, setAdvisorInput] = useState('')

  const fetchJson = async (path, options = {}) => {
    const response = await fetch(`${API_BASE_URL}${path}`, options)

    if (!response.ok) {
      throw new Error(`Request failed: ${path}`)
    }

    return response.json()
  }

  const updateSelectedInterface = (availableInterfaces) => {
    setSelectedInterfaceName((currentInterfaceName) => {
      if (availableInterfaces.some((adapter) => getInterfaceName(adapter) === currentInterfaceName)) {
        return currentInterfaceName
      }

      return getInterfaceName(availableInterfaces[0]) ?? ''
    })

    setSelectedCaptureInterfaceName((currentInterfaceName) => {
      if (availableInterfaces.some((adapter) => getInterfaceName(adapter) === currentInterfaceName)) {
        return currentInterfaceName
      }

      return getInterfaceName(availableInterfaces[0]) ?? ''
    })
  }

  const loadInterfaces = async (signal) => {
    const interfacesPayload = await fetchJson('/interfaces', { signal })
    const availableInterfaces = normalizeList(interfacesPayload, 'interfaces')

    setAdapterState(getValue(interfacesPayload, ['state']))
    setInterfaces(availableInterfaces)
    updateSelectedInterface(availableInterfaces)
  }

  const loadNetworks = async (signal) => {
    const networksPayload = await fetchJson('/networks', { signal })
    setNetworks(normalizeList(networksPayload, 'networks'))
  }

  const loadScannerStatus = async (signal) => {
    const statusPayload = await fetchJson('/scanner/status', { signal })
    const normalizedStatus = normalizeScannerStatus(statusPayload)

    setScannerStatus(normalizedStatus)

    return normalizedStatus
  }

  const loadCaptureStatus = async (signal) => {
    const statusPayload = await fetchJson('/capture/status', { signal })
    const normalizedStatus = normalizeCaptureStatus(statusPayload)

    setCaptureStatus(normalizedStatus)

    return normalizedStatus
  }

  const loadPackets = async (signal) => {
    const packetsPayload = await fetchJson('/packets?limit=20', { signal })
    setPackets(normalizeList(packetsPayload, 'packets'))
  }

  useEffect(() => {
    if (activeView !== 'Dashboard') {
      return
    }

    const controller = new AbortController()

    const loadDashboardData = async () => {
      try {
        await Promise.all([
          loadInterfaces(controller.signal),
          loadNetworks(controller.signal),
          loadCaptureStatus(controller.signal),
          loadPackets(controller.signal),
          fetchJson('/incidents', { signal: controller.signal })
            .then((data) => setIncidents(normalizeList(data, 'incidents')))
            .catch(() => {}),
          fetchJson('/ml/live-status', { signal: controller.signal })
            .then((data) => setMlLiveStatus(data))
            .catch(() => {}),
          fetchJson('/pcap/analyses', { signal: controller.signal })
            .then((data) => setPcapHistory(normalizeList(data, 'analyses')))
            .catch(() => {}),
        ])
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }
      }
    }

    loadDashboardData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'WiFi Scan') {
      return
    }

    const controller = new AbortController()

    const loadWifiScanData = async () => {
      setWifiScanLoading(true)
      setWifiScanError('')

      try {
        const [interfacesPayload, networksPayload, statusPayload, capturePayload] = await Promise.all([
          fetchJson('/interfaces', { signal: controller.signal }),
          fetchJson('/networks', { signal: controller.signal }),
          fetchJson('/scanner/status', { signal: controller.signal }),
          fetchJson('/capture/status', { signal: controller.signal }),
        ])

        const availableInterfaces = normalizeList(interfacesPayload, 'interfaces')

        setInterfaces(availableInterfaces)
        setAdapterState(getValue(interfacesPayload, ['state']))
        setNetworks(normalizeList(networksPayload, 'networks'))
        setScannerStatus(normalizeScannerStatus(statusPayload))
        setCaptureStatus(normalizeCaptureStatus(capturePayload))
        updateSelectedInterface(availableInterfaces)
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }

        setInterfaces([])
        setNetworks([])
        setWifiScanError(
          'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
        )
      } finally {
        if (!controller.signal.aborted) {
          setWifiScanLoading(false)
        }
      }
    }

    loadWifiScanData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'Live Monitor') {
      return
    }

    const controller = new AbortController()

    const loadLiveMonitorData = async () => {
      setLiveMonitorLoading(true)
      setLiveMonitorError('')

      try {
        const [interfacesPayload, scannerPayload, capturePayload] = await Promise.all([
          fetchJson('/interfaces', { signal: controller.signal }),
          fetchJson('/scanner/status', { signal: controller.signal }),
          fetchJson('/capture/status', { signal: controller.signal }),
        ])
        const availableInterfaces = normalizeList(interfacesPayload, 'interfaces')
        const normalizedCaptureStatus = normalizeCaptureStatus(capturePayload)

        setInterfaces(availableInterfaces)
        setAdapterState(getValue(interfacesPayload, ['state']))
        setScannerStatus(normalizeScannerStatus(scannerPayload))
        setCaptureStatus(normalizedCaptureStatus)
        updateSelectedInterface(availableInterfaces)

        if (ACTIVE_CAPTURE_STATES.includes(getCaptureState(normalizedCaptureStatus))) {
          await loadPackets(controller.signal)
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }

        setPackets([])
        setLiveMonitorError(
          'Unable to connect to the NetShield capture backend at http://127.0.0.1:5000. Start the Flask server and try again.',
        )
      } finally {
        if (!controller.signal.aborted) {
          setLiveMonitorLoading(false)
        }
      }
    }

    loadLiveMonitorData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'Live Monitor') {
      return
    }

    let activePollController = null

    const pollLiveMonitor = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      Promise.all([
        loadCaptureStatus(controller.signal),
        loadScannerStatus(controller.signal),
        loadInterfaces(controller.signal),
      ])
        .then(([latestCaptureStatus]) => {
          if (ACTIVE_CAPTURE_STATES.includes(getCaptureState(latestCaptureStatus))) {
            return loadPackets(controller.signal)
          }

          return null
        })
        .catch((error) => {
          if (error.name !== 'AbortError') {
            setLiveMonitorError(
              'Unable to refresh capture data from http://127.0.0.1:5000. Check that the Flask backend is running.',
            )
          }
        })
    }

    const intervalId = setInterval(pollLiveMonitor, Number(uiPrefs.pollInterval) || 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
  }, [activeView, uiPrefs.pollInterval])

  useEffect(() => {
    if (activeView !== 'WiFi Scan') {
      return
    }

    let activePollController = null

    const pollWifiScan = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      Promise.all([
        loadScannerStatus(controller.signal),
        loadInterfaces(controller.signal),
        loadCaptureStatus(controller.signal),
      ])
        .then(([latestScannerStatus]) => {
          if (ACTIVE_SCANNER_STATES.includes(getScannerState(latestScannerStatus))) {
            return loadNetworks(controller.signal)
          }

          return null
        })
        .catch((error) => {
          if (error.name !== 'AbortError') {
            setWifiScanError(
              'Unable to refresh scanner data from http://127.0.0.1:5000. Check that the Flask backend is running.',
            )
          }
        })

    }

    const intervalId = setInterval(pollWifiScan, Number(uiPrefs.pollInterval) || 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
  }, [activeView, uiPrefs.pollInterval])

  useEffect(() => {
    if (activeView !== 'ML Engine' && activeView !== 'Dashboard') {
      return
    }

    const controller = new AbortController()

    const loadMlDetectionData = async () => {
      setMlDetectionLoading(true)
      setMlDetectionError('')

      try {
        const payload = await fetchJson('/ml/live-status', { signal: controller.signal })
        setMlLiveStatus(payload)

        if (!mlSchemaInfo) {
          fetchJson('/ml/test/schema', { signal: controller.signal })
            .then((info) => setMlSchemaInfo(info))
            .catch(() => {})
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }

        setMlLiveStatus(null)
        setMlDetectionError(
          'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
        )
      } finally {
        if (!controller.signal.aborted) {
          setMlDetectionLoading(false)
        }
      }
    }

    loadMlDetectionData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'ML Engine' && activeView !== 'Dashboard') {
      return
    }

    let activePollController = null

    const pollMlDetection = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      fetchJson('/ml/live-status', { signal: controller.signal })
        .then((payload) => {
          setMlDetectionError('')
          setMlLiveStatus(payload)
        })
        .catch((error) => {
          if (error.name !== 'AbortError') {
            setMlDetectionError(
              'Unable to refresh ML inference data from http://127.0.0.1:5000. Check that the Flask backend is running.',
            )
          }
        })
    }

    const intervalId = setInterval(pollMlDetection, Number(uiPrefs.pollInterval) || 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
  }, [activeView, uiPrefs.pollInterval])

  const loadIncidentsData = async (signal) => {
    setIncidentsLoading(true)
    setIncidentsError('')

    try {
      const payload = await fetchJson('/incidents', signal ? { signal } : undefined)
      setIncidents(normalizeList(payload, 'incidents'))
    } catch (error) {
      if (error?.name === 'AbortError') {
        return
      }

      setIncidents([])
      setIncidentsError(
        'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
      )
    } finally {
      if (!signal || !signal.aborted) {
        setIncidentsLoading(false)
      }
    }
  }

  useEffect(() => {
    if (activeView !== 'Incidents' && activeView !== 'Dashboard') {
      return
    }

    const controller = new AbortController()
    loadIncidentsData(controller.signal)

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'Incidents' && activeView !== 'Dashboard') {
      return
    }

    let activePollController = null

    const pollIncidents = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      fetchJson('/incidents', { signal: controller.signal })
        .then((payload) => {
          setIncidents(normalizeList(payload, 'incidents'))
        })
        .catch(() => {})
    }

    const intervalId = setInterval(pollIncidents, Number(uiPrefs.pollInterval) || 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
  }, [activeView, uiPrefs.pollInterval])

  const loadReportsData = async (signal) => {
    setReportsLoading(true)
    setReportsError('')

    try {
      const payload = await fetchJson('/incidents', { signal })
      setReportIncidents(normalizeList(payload, 'incidents'))
    } catch (error) {
      if (error.name === 'AbortError') {
        return
      }

      setReportIncidents([])
      setReportsError(
        'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
      )
    } finally {
      if (!signal?.aborted) {
        setReportsLoading(false)
      }
    }
  }

  useEffect(() => {
    if (activeView !== 'Reports') {
      return
    }

    const controller = new AbortController()
    loadReportsData(controller.signal)

    return () => controller.abort()
  }, [activeView])

  const loadPcapData = async (signal) => {
    setPcapHistoryLoading(true)
    setPcapError('')
    try {
      const [samplesRes, historyRes] = await Promise.all([
        fetchJson('/pcap/samples', { signal }),
        fetchJson('/pcap/analyses', { signal }),
      ])
      const samplesList = samplesRes?.samples || []
      setPcapSamples(samplesList)
      if (samplesList.length > 0 && !selectedPcapSample) {
        setSelectedPcapSample(samplesList[0].filename)
      }
      const historyList = historyRes?.analyses || []
      setPcapHistory(historyList)
      if (historyList.length > 0 && !pcapResult) {
        try {
          const detail = await fetchJson(`/pcap/results/${historyList[0].id}`, { signal })
          setPcapResult(detail)
        } catch {}
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        setPcapError('Unable to connect to PCAP service at http://127.0.0.1:5000.')
      }
    } finally {
      if (!signal?.aborted) {
        setPcapHistoryLoading(false)
      }
    }
  }

  const loadMlTestingData = async (signal) => {
    setMlTestingError('')
    try {
      const [datasetsRes, schemaRes, runsRes] = await Promise.all([
        fetchJson('/ml/test/datasets', { signal }),
        fetchJson('/ml/test/schema', { signal }),
        fetchJson('/ml/test/runs', { signal }),
      ])
      const dList = datasetsRes?.datasets || []
      setMlDatasets(dList)
      if (dList.length > 0 && !selectedDataset) {
        const preferred = dList.find((d) => d.name === 'awid3_v3_test_combined.csv') || dList[0]
        setSelectedDataset(preferred.name || preferred.filename)
      }
      setMlSchemaInfo(schemaRes)
      const rList = runsRes?.runs || []
      setMlTestRuns(rList)
      if (rList.length > 0 && !mlTestResult) {
        try {
          const detail = await fetchJson(`/ml/test/results/${rList[0].id}`, { signal })
          setMlTestResult(detail)
        } catch {}
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        setMlTestingError('Unable to connect to ML evaluation service at http://127.0.0.1:5000.')
      }
    }
  }

  useEffect(() => {
    if (activeView !== 'PCAP Analysis') {
      return
    }
    const controller = new AbortController()
    loadPcapData(controller.signal)
    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'ML Engine') {
      return
    }
    const controller = new AbortController()
    loadMlTestingData(controller.signal)
    return () => controller.abort()
  }, [activeView])

  const loadRecommendationsData = async (signal) => {
    setRecommendationsLoading(true)
    setRecommendationsError('')
    try {
      const [recsRes, modelRes] = await Promise.all([
        fetchJson('/wifi/recommendations', { signal }),
        fetchJson('/wifi/recommendations/model', { signal }),
      ])
      setRecommendationsData(recsRes)
      setRecommendationModelInfo(modelRes)
    } catch (err) {
      if (err.name !== 'AbortError') {
        setRecommendationsError('Unable to load Wi-Fi recommendations. Ensure the Flask backend is running.')
      }
    } finally {
      if (!signal?.aborted) {
        setRecommendationsLoading(false)
      }
    }
  }

  useEffect(() => {
    if (activeView !== 'Network Recommendations') {
      return
    }
    const controller = new AbortController()
    loadRecommendationsData(controller.signal)
    return () => controller.abort()
  }, [activeView])

  const handleOpenConnectModal = (network) => {
    setConnectModalNetwork(network)
    setConnectPassword('')
    setShowPassword(false)
    setConnectStatus(null)
  }

  const handleCopyIncidentJson = async (incident) => {
    if (!incident) return
    const text = JSON.stringify(incident, null, 2)
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(text)
      } else {
        const textArea = document.createElement('textarea')
        textArea.value = text
        textArea.style.position = 'fixed'
        textArea.style.left = '-999999px'
        document.body.appendChild(textArea)
        textArea.focus()
        textArea.select()
        const successful = document.execCommand('copy')
        document.body.removeChild(textArea)
        if (!successful) throw new Error('execCommand failed')
      }
      setIncidentCopied(true)
      setIncidentCopyStatus('success')
      setTimeout(() => {
        setIncidentCopied(false)
        setIncidentCopyStatus(null)
      }, 2000)
    } catch {
      setIncidentCopyStatus('error')
      setTimeout(() => setIncidentCopyStatus(null), 3000)
    }
  }

  const handleUpdateIncidentStatus = (id, newStatus) => {
    if (!id || !newStatus) return
    setIncidents((prev) =>
      prev.map((inc) => (inc.id === id ? { ...inc, status: newStatus } : inc))
    )
    setSelectedIncident((prev) =>
      prev && prev.id === id ? { ...prev, status: newStatus } : prev
    )
  }

  const handleCloseConnectModal = () => {
    if (connectLoading) return
    setConnectModalNetwork(null)
    setConnectPassword('')
    setShowPassword(false)
    setConnectStatus(null)
  }

  const handleConnectSubmit = async (e) => {
    e?.preventDefault()
    if (!connectModalNetwork) return
    setConnectLoading(true)
    setConnectStatus(null)

    try {
      const payload = {
        ssid: connectModalNetwork.ssid,
        password: connectPassword,
        bssid: connectModalNetwork.bssid,
        encryption: connectModalNetwork.encryption,
      }
      const res = await fetch(`${API_BASE_URL}/wifi/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const data = await res.json()
      if (!res.ok || !data.success) {
        setConnectStatus({
          success: false,
          message: data.message || data.error || 'Failed to connect to network.',
        })
      } else {
        setConnectStatus({
          success: true,
          message: data.message || `Successfully connected to ${connectModalNetwork.ssid}!`,
        })
      }
    } catch (err) {
      setConnectStatus({
        success: false,
        message: err.message || 'Network connection request failed.',
      })
    } finally {
      setConnectLoading(false)
    }
  }

  const handlePcapAnalyze = async (e) => {
    e?.preventDefault()
    setPcapAnalyzing(true)
    setPcapError('')

    try {
      let data
      if (selectedPcapFile) {
        const formData = new FormData()
        formData.append('file', selectedPcapFile)
        const res = await fetch(`${API_BASE_URL}/pcap/analyze`, {
          method: 'POST',
          body: formData,
        })
        if (!res.ok) {
          const errPayload = await res.json().catch(() => ({}))
          throw new Error(errPayload.error || `HTTP ${res.status}`)
        }
        data = await res.json()
      } else if (selectedPcapSample) {
        data = await fetchJson('/pcap/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sample: selectedPcapSample }),
        })
      } else {
        throw new Error('Please select a file to upload or choose a bundled sample PCAP.')
      }

      setPcapResult(data)
      setPcapTab('timeline')
      const histRes = await fetchJson('/pcap/analyses')
      setPcapHistory(histRes?.analyses || [])
    } catch (err) {
      setPcapError(err.message || 'PCAP analysis failed. Verify packet capture file.')
    } finally {
      setPcapAnalyzing(false)
    }
  }

  const handleSelectHistoryPcap = async (id) => {
    setPcapError('')
    try {
      const detail = await fetchJson(`/pcap/results/${id}`)
      setPcapResult(detail)
      setPcapTab('timeline')
    } catch (err) {
      setPcapError('Failed to load past PCAP analysis.')
    }
  }

  const handleRunMlTest = async () => {
    if (!selectedDataset) {
      setMlTestingError('Please select a dataset to evaluate.')
      return
    }
    setMlTestingLoading(true)
    setMlTestingError('')
    try {
      const data = await fetchJson('/ml/test/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dataset_name: selectedDataset }),
      })
      setMlTestResult(data)
      setMlTestingTab('matrix')
      const runsRes = await fetchJson('/ml/test/runs')
      setMlTestRuns(runsRes?.runs || [])
    } catch (err) {
      setMlTestingError(err.message || 'Model evaluation failed.')
    } finally {
      setMlTestingLoading(false)
    }
  }

  const handleSelectPastTestRun = async (id) => {
    setMlTestingError('')
    try {
      const detail = await fetchJson(`/ml/test/results/${id}`)
      setMlTestResult(detail)
      setMlTestingTab('matrix')
    } catch (err) {
      setMlTestingError('Failed to load past evaluation run.')
    }
  }

  const wirelessAdapter =
    interfaces.find((adapter) => getInterfaceName(adapter) === selectedInterfaceName) ?? interfaces[0] ?? null
  const selectedInterface = getInterfaceName(wirelessAdapter)
  const scannerState = getScannerState(scannerStatus)
  const scannerProgress = scannerStatus.progress ?? {}
  const isScannerActive = ACTIVE_SCANNER_STATES.includes(scannerState)
  const isScannerStarting = scannerState === 'starting'
  const isScannerRunning = scannerState === 'running'
  const isScannerStopping = scannerState === 'stopping'
  const selectableInterfaces = interfaces.filter((adapter) => getInterfaceName(adapter))
  const captureAdapter =
    interfaces.find((adapter) => getInterfaceName(adapter) === selectedCaptureInterfaceName) ??
    interfaces[0] ??
    null
  const selectedCaptureInterface = getInterfaceName(captureAdapter)
  const captureState = getCaptureState(captureStatus)
  const isCaptureActive = ACTIVE_CAPTURE_STATES.includes(captureState)
  const isCaptureStarting = captureState === 'starting'
  const isCaptureRunning = captureState === 'running'
  const isCaptureStopping = captureState === 'stopping'
  const captureProgress = captureStatus.progress ?? {}
  const packetTypeCounts = normalizeCounts(captureProgress.packet_type_counts)
  const startScanDisabled =
    !selectedInterface ||
    scannerActionLoading ||
    isCaptureActive ||
    isScannerStarting ||
    isScannerRunning ||
    isScannerStopping
  const stopScanDisabled = !isScannerActive || scannerActionLoading
  const startCaptureDisabled =
    !selectedCaptureInterface ||
    isScannerActive ||
    captureActionLoading ||
    isCaptureStarting ||
    isCaptureRunning ||
    isCaptureStopping
  const stopCaptureDisabled = !isCaptureActive || captureActionLoading
  const totalIncidents = incidents.length
  const newIncidents = incidents.filter(
    (incident) => String(incident?.status ?? '').toLowerCase() === 'new',
  ).length
  const highSeverityIncidents = incidents.filter(
    (incident) => String(incident?.severity ?? '').toLowerCase() === 'high',
  ).length

  const avgAttackProb =
    incidents.length > 0
      ? (
          (incidents.reduce((sum, inc) => {
            const p = Number(inc?.attack_probability)
            return Number.isFinite(p) ? sum + p : sum
          }, 0) /
            incidents.length) *
          100
        ).toFixed(1)
      : '--'

  const filteredIncidents = incidents.filter((incident) => {
    if (
      incidentSeverityFilter !== 'all' &&
      String(incident?.severity || '').toLowerCase() !== incidentSeverityFilter.toLowerCase()
    ) {
      return false
    }
    if (
      incidentStatusFilter !== 'all' &&
      String(incident?.status || '').toLowerCase() !== incidentStatusFilter.toLowerCase()
    ) {
      return false
    }
    if (incidentSearch.trim()) {
      const q = incidentSearch.toLowerCase().trim()
      const idMatch = String(incident?.id || '').toLowerCase().includes(q)
      const labelMatch = String(incident?.label || incident?.prediction || '').toLowerCase().includes(q)
      const sevMatch = String(incident?.severity || '').toLowerCase().includes(q)
      const statMatch = String(incident?.status || '').toLowerCase().includes(q)
      const dateMatch = String(incident?.created_at || '').toLowerCase().includes(q)
      if (!idMatch && !labelMatch && !sevMatch && !statMatch && !dateMatch) {
        return false
      }
    }
    return true
  })

  const monitoringStatus =
    getValue(captureStatus, ['state', 'capture_state', 'status']) ??
    (captureState === 'stopped' ? 'Stopped' : captureState)
  const monitoringNetwork =
    getValue(captureProgress, ['network', 'ssid']) ?? 'None'
  const monitoringInterface =
    getValue(captureStatus, ['interface', 'interface_name']) ??
    getValue(captureProgress, ['interface']) ??
    (selectedCaptureInterface || 'Not Selected')

  const dashboardKpis = [
    {
      label: 'Security Alerts',
      value: formatValue(totalIncidents),
      sub: totalIncidents === 0
        ? 'All clear (0 alerts)'
        : `${newIncidents} Unresolved · ${highSeverityIncidents} High Severity`,
      border: highSeverityIncidents > 0 ? '#ef4444' : totalIncidents > 0 ? '#f59e0b' : '#10b981',
      valColor: highSeverityIncidents > 0 ? '#f87171' : 'var(--text-strong)',
    },
    {
      label: 'Latest ML Verdict',
      value: mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined
        ? (mlLiveStatus.prediction === 1 ? 'Attack Detected' : 'Normal Traffic')
        : 'Awaiting Ingest',
      sub: mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.attack_probability !== undefined
        ? `${formatProbability(mlLiveStatus.attack_probability)} attack probability`
        : 'No active inference stream',
      border: mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined
        ? (mlLiveStatus.prediction === 1 ? '#ef4444' : '#10b981')
        : 'var(--border)',
      valColor: mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined
        ? (mlLiveStatus.prediction === 1 ? '#f87171' : '#34d399')
        : 'var(--text-muted)',
    },
    {
      label: 'Capture Status',
      value: isCaptureRunning ? 'Active Capture' : 'Standby / Idle',
      sub: isCaptureRunning
        ? `${monitoringInterface} · ${getValue(captureProgress, ['packet_rate']) ?? 0} pkt/s`
        : `${monitoringInterface || 'No adapter selected'} · 0 pkt/s`,
      border: isCaptureRunning ? '#14b8a6' : 'var(--border)',
      valColor: isCaptureRunning ? '#2dd4bf' : 'var(--text-strong)',
    },
    {
      label: 'Networks Found',
      value: formatValue(networks.length),
      sub: networks.length > 0
        ? `${networks.filter((n) => String(getValue(n, ['encryption', 'security']) || '').toUpperCase().includes('WPA')).length} Secured · ${networks.filter((n) => !String(getValue(n, ['encryption', 'security']) || '').toUpperCase().includes('WPA')).length} Open`
        : 'Run Wi-Fi scan to discover',
      border: '#0284c7',
      valColor: '#38bdf8',
    },
  ]

  const filteredScanNetworks = networks.filter((network) => {
    const ssid = String(getValue(network, ['ssid', 'SSID']) || '').toLowerCase()
    const bssid = String(getValue(network, ['bssid', 'BSSID']) || '').toLowerCase()
    const vendor = String(getValue(network, ['vendor', 'Vendor']) || '').toLowerCase()
    const channel = Number(getValue(network, ['channel', 'Channel'])) || 0
    const enc = String(getValue(network, ['encryption', 'security']) || '').toUpperCase()

    if (scanSearch.trim()) {
      const q = scanSearch.toLowerCase().trim()
      if (!ssid.includes(q) && !bssid.includes(q) && !vendor.includes(q)) {
        return false
      }
    }

    if (scanFilter === '5ghz') {
      return channel >= 36
    }
    if (scanFilter === '2ghz') {
      return channel > 0 && channel <= 14
    }
    if (scanFilter === 'secured') {
      return enc.includes('WPA') || enc.includes('WEP') || enc.includes('802.1X')
    }
    if (scanFilter === 'open') {
      return enc.includes('OPEN') || enc === '' || enc === 'NONE'
    }

    return true
  })

  const reportTotalIncidents = reportIncidents.length
  const reportHighSeverity = reportIncidents.filter(
    (incident) => String(incident?.severity ?? '').toLowerCase() === 'high',
  ).length
  const reportTotalPackets = reportIncidents.reduce((sum, inc) => {
    const val = Number(inc?.total_packets)
    return Number.isFinite(val) ? sum + val : sum
  }, 0)
  const reportAvgAttackProb =
    reportIncidents.length > 0
      ? reportIncidents.reduce((sum, inc) => {
          const val = Number(inc?.attack_probability)
          return Number.isFinite(val) ? sum + val : sum
        }, 0) / reportIncidents.length
      : null

  const attackCountsByLabel = reportIncidents.reduce((acc, inc) => {
    const label = String(inc?.label ?? (inc?.prediction !== undefined ? `Class ${inc.prediction}` : 'Unknown'))
    acc[label] = (acc[label] || 0) + 1
    return acc
  }, {})

  const handleRefreshReports = () => {
    loadReportsData()
  }

  const handleExportCsv = () => {
    if (!reportIncidents || reportIncidents.length === 0) {
      return
    }

    const headers = [
      'ID',
      'Created At',
      'Label',
      'Attack Probability',
      'Normal Probability',
      'Total Packets',
      'Window Start',
      'Window End',
      'Feature Count',
      'Severity',
      'Status',
    ]

    const formatCsvField = (val) => {
      if (val === undefined || val === null) {
        return ''
      }
      const str = String(val)
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return `"${str.replace(/"/g, '""')}"`
      }
      return str
    }

    const rows = reportIncidents.map((incident) => [
      formatCsvField(incident.id),
      formatCsvField(incident.created_at),
      formatCsvField(incident.label ?? (incident.prediction !== undefined ? `Class ${incident.prediction}` : '')),
      formatCsvField(incident.attack_probability),
      formatCsvField(incident.normal_probability),
      formatCsvField(incident.total_packets),
      formatCsvField(incident.window_start),
      formatCsvField(incident.window_end),
      formatCsvField(incident.feature_count),
      formatCsvField(incident.severity),
      formatCsvField(incident.status),
    ])

    const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\r\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', `netshield_incident_report_${new Date().toISOString().slice(0, 10)}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  const handleSaveUiPrefs = (updated) => {
    setUiPrefs(updated)
    try {
      localStorage.setItem('netshield_ui_prefs', JSON.stringify(updated))
      setSettingsSaveMsg('Preferences saved to local browser storage.')
      setTimeout(() => setSettingsSaveMsg(''), 2500)
    } catch {
      setSettingsSaveMsg('Failed to save preferences to localStorage.')
    }
  }

  const handleRunDiagnostics = async () => {
    setDiagnosticsLoading(true)
    setDiagnosticsResult(null)
    const start = performance.now()
    try {
      const healthData = await fetchJson('/health')
      const latencyMs = Math.round(performance.now() - start)
      setDiagnosticsResult({
        ok: true,
        latencyMs,
        data: healthData,
        timestamp: new Date().toISOString(),
      })
    } catch (err) {
      const latencyMs = Math.round(performance.now() - start)
      setDiagnosticsResult({
        ok: false,
        latencyMs,
        error: String(err?.message || 'Backend connection failed at http://127.0.0.1:5000'),
        timestamp: new Date().toISOString(),
      })
    } finally {
      setDiagnosticsLoading(false)
    }
  }

  const handleStartScan = async () => {
    if (startScanDisabled) {
      return
    }

    setScannerActionLoading(true)
    setWifiScanError('')

    try {
      await fetchJson('/scanner/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedInterface }),
      })
      await loadScannerStatus()
      await loadNetworks()
    } catch {
      setWifiScanError('Unable to start the scanner. Check the selected interface and Flask backend logs.')
    } finally {
      setScannerActionLoading(false)
    }
  }

  const handleStopScan = async () => {
    if (stopScanDisabled) {
      return
    }

    setScannerActionLoading(true)
    setWifiScanError('')

    try {
      await fetchJson('/scanner/stop', { method: 'POST' })
      await Promise.all([loadScannerStatus(), loadNetworks()])
      await loadInterfaces()
    } catch {
      setWifiScanError('Unable to stop the scanner. Check that the Flask backend is running.')
    } finally {
      setScannerActionLoading(false)
    }
  }

  const handleStartCapture = async () => {
    if (startCaptureDisabled) {
      return
    }

    setCaptureActionLoading(true)
    setLiveMonitorError('')

    try {
      await fetchJson('/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedCaptureInterface }),
      })
      await loadCaptureStatus()
      await loadPackets()
    } catch {
      setLiveMonitorError('Unable to start packet capture. Check the selected interface and Flask backend logs.')
    } finally {
      setCaptureActionLoading(false)
    }
  }

  const handleStopCapture = async () => {
    if (stopCaptureDisabled) {
      return
    }

    setCaptureActionLoading(true)
    setLiveMonitorError('')

    try {
      await fetchJson('/capture/stop', { method: 'POST' })
      await Promise.all([loadCaptureStatus(), loadPackets(), loadInterfaces()])
    } catch {
      setLiveMonitorError('Unable to stop packet capture. Check that the Flask backend is running.')
    } finally {
      setCaptureActionLoading(false)
    }
  }

  const rawNetworks =
    recommendationsData?.networks ||
    recommendationsData?.recommendations ||
    []

  const recList = rawNetworks.map((net, idx) => {
    const rawScore = Number(net.recommendation_score ?? net.score ?? 0)
    const rawConfidence = net.confidence_pct ?? (net.confidence != null ? Number(net.confidence) * (Number(net.confidence) <= 1 ? 100 : 1) : null)
    const cls = net.ml_classification || net.classification || 'POOR'
    const sigDbm = net.signal_dbm ?? parseInt(String(net.signal || '-100').replace(/[^0-9-]/g, ''), 10)
    const ch = Number(net.channel || net.Channel || 0)
    const is5g = Boolean(net.band_is_5ghz || ch > 14 || String(net.frequency || '').includes('5'))
    const bandStr = net.band || (is5g ? '5 GHz' : '2.4 GHz')
    const enc = net.security || net.encryption || net.Encryption || 'Open'

    return {
      ...net,
      ssid: net.ssid || net.SSID || '<Hidden SSID>',
      bssid: net.bssid || net.BSSID || '',
      classification: cls,
      ml_classification: cls,
      score: rawScore,
      recommendation_score: rawScore,
      confidence_pct: rawConfidence,
      signal: net.signal || `${sigDbm} dBm`,
      signal_dbm: sigDbm,
      channel: ch,
      frequency: net.frequency || net.Frequency || `${ch} (${bandStr})`,
      band: bandStr,
      security: enc,
      encryption: enc,
      vendor: net.vendor || net.Vendor || 'Unknown Vendor',
      positive_factors: net.positive_factors || net.positive_reasons || [],
      negative_factors: net.negative_factors || net.negative_reasons || [],
      recommendation_reason: net.recommendation_reason || net.summary || '',
      is_recommended: Boolean(net.is_best_recommendation || net.is_recommended || cls === 'EXCELLENT' || cls === 'GOOD'),
      rank: net.rank || idx + 1,
    }
  })

  const totalScannedRecs =
    recommendationsData?.scanned_count ??
    recommendationsData?.count ??
    recList.length

  const bestNetwork =
    recList.length > 0
      ? (recommendationsData?.best_network
          ? recList.find((n) => n.bssid && recommendationsData.best_network.bssid && n.bssid.toUpperCase() === String(recommendationsData.best_network.bssid).toUpperCase()) || recList[0]
          : recList[0])
      : null

  const recommendedRecsCount = recList.filter((n) => n.is_recommended).length
  const fiveGhzRecsCount = recList.filter((n) => n.band === '5 GHz').length

  const filteredRecommendations = recList.filter((net) => {
    if (recommendationFilter === 'recommended') return net.is_recommended
    if (recommendationFilter === '5ghz') return net.band === '5 GHz'
    if (recommendationFilter === 'secure') return !String(net.security || '').toLowerCase().includes('open')
    return true
  }).sort((a, b) => {
    if (recommendationSort === 'score') return (b.score || 0) - (a.score || 0)
    if (recommendationSort === 'signal') return (b.signal_dbm || -100) - (a.signal_dbm || -100)
    if (recommendationSort === 'security') {
      const getRank = (c) => (c === 'EXCELLENT' ? 4 : c === 'GOOD' ? 3 : c === 'FAIR' ? 2 : 1)
      return getRank(b.classification) - getRank(a.classification)
    }
    if (recommendationSort === 'channel') return (a.channel || 0) - (b.channel || 0)
    return 0
  })

  const handleSendAdvisorMessage = (customQuery) => {
    const textToSend = typeof customQuery === 'string' ? customQuery : advisorInput
    if (!textToSend || !textToSend.trim()) return

    const userMsg = {
      sender: 'user',
      text: textToSend.trim(),
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }

    const botResponseText = generateAdvisorResponse(textToSend, recList, bestNetwork, recommendationModelInfo)
    const botMsg = {
      sender: 'advisor',
      text: botResponseText,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }

    setAdvisorMessages((prev) => [...prev, userMsg, botMsg])
    setAdvisorInput('')
  }

  return (
    <div className={`app-shell ui-density-${uiPrefs.tableDensity || 'compact'}`}>
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand">
          <span className="brand-mark">NS</span>
          <div>
            <p className="brand-name">NetShield</p>
            <p className="brand-subtitle">WiFi IDS</p>
          </div>
        </div>

        <nav className="nav-list">
          {sidebarItems.map((item) => (
            <button
              className={item === activeView ? 'nav-item active' : 'nav-item'}
              key={item}
              onClick={() => setActiveView(item)}
              type="button"
            >
              {item}
            </button>
          ))}
        </nav>
      </aside>

      <div className="workspace">
        <header className="top-header">
          <div>
            <p className="eyebrow">ML-Based WiFi Intrusion Detection</p>
            <h1>NetShield</h1>
            <p className="page-title">{activeView}</p>
          </div>
          <div className="header-status-group">
            {uiPrefs.visualAlerts && highSeverityIncidents > 0 ? (
              <button
                type="button"
                className="header-alert-badge"
                onClick={() => setActiveView('Incidents')}
                title="High severity incidents require immediate triage"
              >
                <span className="status-dot dot-alert" />
                <span>{highSeverityIncidents} HIGH ALERT{highSeverityIncidents > 1 ? 'S' : ''}</span>
              </button>
            ) : null}
            <div className="header-status">
              <span className={`status-dot ${isCaptureRunning ? 'active' : ''}`}></span>
              {isCaptureRunning
                ? 'Live Capture Active'
                : isCaptureStarting
                ? 'Starting Capture...'
                : isCaptureStopping
                ? 'Stopping Capture...'
                : 'Monitoring not started'}
            </div>
          </div>
        </header>

        <main className="main-content">
          {activeView === 'Dashboard' ? (
            <section className="dashboard-view" aria-label="Dashboard overview">
              {/* Header */}
              <section className="panel dashboard-header-panel" style={{ padding: '16px 20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <h2 style={{ margin: 0, fontSize: '17px', fontWeight: 700, color: 'var(--text-strong)' }}>
                        NetShield Security Overview
                      </h2>
                      <span className={isCaptureRunning ? 'badge badge-status-new' : 'badge badge-default'}>
                        {isCaptureRunning ? 'Live Capture Running' : 'System Standby'}
                      </span>
                    </div>
                    <p style={{ margin: '4px 0 0', fontSize: '12.5px', color: 'var(--text-muted)' }}>
                      Real-time IEEE 802.11 wireless intrusion detection, live frame telemetry, and AWID3 Random Forest classification.
                    </p>
                  </div>

                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
                    <span className="scan-meta-pill">
                      Adapter: <strong>{monitoringInterface || 'No Adapter'}</strong>
                    </span>
                    <span className="scan-meta-pill">
                      Pipeline: <strong>{isCaptureRunning ? 'Streaming Frames' : 'Idle'}</strong>
                    </span>
                    <span className="scan-meta-pill">
                      Model: <strong>AWID3 (31 Features)</strong>
                    </span>
                  </div>
                </div>
              </section>

              {/* Compact 4-KPI Grid */}
              <div className="dashboard-kpi-grid">
                {dashboardKpis.map((kpi) => (
                  <article
                    className="dashboard-kpi-card"
                    key={kpi.label}
                    style={{ borderTop: kpi.border ? `3px solid ${kpi.border}` : undefined }}
                  >
                    <span className="dashboard-kpi-label">{kpi.label}</span>
                    <strong className="dashboard-kpi-val" style={{ color: kpi.valColor || 'var(--text-strong)' }}>
                      {kpi.value}
                    </strong>
                    <span className="dashboard-kpi-sub">{kpi.sub}</span>
                  </article>
                ))}
              </div>

              {/* Quick Actions Navigation Bar */}
              <div className="quick-actions-bar">
                <span style={{ fontSize: '11.5px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginRight: '4px' }}>
                  Quick Actions:
                </span>
                <button
                  type="button"
                  className="quick-action-btn"
                  onClick={() => setActiveView('Live Monitor')}
                >
                  <span className="quick-action-icon">📡</span>
                  <span>Live Monitor</span>
                  {isCaptureRunning ? <span className="live-pulse-dot" style={{ width: '6px', height: '6px', backgroundColor: '#34d399' }} /> : null}
                </button>
                <button
                  type="button"
                  className="quick-action-btn"
                  onClick={() => {
                    setActiveView('ML Engine')
                    setMlEngineTab('live')
                  }}
                >
                  <span className="quick-action-icon">🧠</span>
                  <span>ML Engine</span>
                </button>
                <button
                  type="button"
                  className="quick-action-btn"
                  onClick={() => setActiveView('PCAP Analysis')}
                >
                  <span className="quick-action-icon">📁</span>
                  <span>PCAP Analysis</span>
                </button>
                <button
                  type="button"
                  className="quick-action-btn"
                  onClick={() => setActiveView('Incidents')}
                >
                  <span className="quick-action-icon">🚨</span>
                  <span>Incidents</span>
                  {newIncidents > 0 ? (
                    <span className="badge badge-severity-high" style={{ padding: '1px 6px', fontSize: '10px' }}>
                      {newIncidents}
                    </span>
                  ) : null}
                </button>
                <button
                  type="button"
                  className="quick-action-btn"
                  onClick={() => setActiveView('Reports')}
                >
                  <span className="quick-action-icon">📊</span>
                  <span>Reports</span>
                </button>
              </div>

              {/* Two-Column Operational Section: Detection Status vs Recent Incidents Overview */}
              <div className="panel-grid">
                {/* Column 1: Live Threat & Detection Monitor */}
                <section className="panel" style={{ display: 'flex', flexDirection: 'column' }}>
                  <div className="panel-header">
                    <div>
                      <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                        Live Threat Detection &amp; Telemetry
                      </h3>
                      <p style={{ margin: '2px 0 0', fontSize: '11.5px', color: 'var(--text-muted)' }}>
                        Current 5-second streaming window analyzed by the AWID3 classifier.
                      </p>
                    </div>
                    <span className={isCaptureRunning ? 'badge badge-status-new' : 'badge badge-status-resolved'}>
                      {isCaptureRunning ? 'Capture Active' : 'Standby / Idle'}
                    </span>
                  </div>

                  {mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined ? (
                    <div className="detection-active-box" style={{ marginTop: '12px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                        <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Latest Inference Window</span>
                        <span className={mlLiveStatus.prediction === 0 ? 'badge badge-status-resolved' : 'badge badge-severity-high'}>
                          {mlLiveStatus.prediction === 0 ? 'Normal Traffic' : (mlLiveStatus.label ?? 'Attack Detected')}
                        </span>
                      </div>

                      {/* Probability Bars */}
                      <div className="prob-meter-row">
                        <div className="prob-meter-label">
                          <span>Attack Probability</span>
                          <strong style={{ color: mlLiveStatus.attack_probability > 0.5 ? '#f87171' : 'var(--text-strong)' }}>
                            {formatProbability(mlLiveStatus.attack_probability)}
                          </strong>
                        </div>
                        <div className="prob-meter-bar">
                          <div
                            className="prob-meter-fill"
                            style={{
                              width: `${Math.min(100, Math.max(0, (mlLiveStatus.attack_probability || 0) * 100))}%`,
                              background: mlLiveStatus.attack_probability > 0.5 ? '#ef4444' : '#14b8a6',
                            }}
                          />
                        </div>
                      </div>

                      <div className="prob-meter-row" style={{ marginTop: '8px' }}>
                        <div className="prob-meter-label">
                          <span>Normal Probability</span>
                          <strong>{formatProbability(mlLiveStatus.normal_probability)}</strong>
                        </div>
                        <div className="prob-meter-bar">
                          <div
                            className="prob-meter-fill"
                            style={{
                              width: `${Math.min(100, Math.max(0, (mlLiveStatus.normal_probability || 0) * 100))}%`,
                              background: '#10b981',
                            }}
                          />
                        </div>
                      </div>

                      <dl className="status-list" style={{ marginTop: '14px' }}>
                        <div>
                          <dt>Packets in Window</dt>
                          <dd>{formatValue(mlLiveStatus.total_packets)}</dd>
                        </div>
                        <div>
                          <dt>Window Span</dt>
                          <dd>{mlLiveStatus.window_start ?? '--'}s - {mlLiveStatus.window_end ?? '--'}s</dd>
                        </div>
                        <div>
                          <dt>Active Interface</dt>
                          <dd>{formatValue(monitoringInterface)}</dd>
                        </div>
                      </dl>
                    </div>
                  ) : (
                    <div className="empty-state" style={{ padding: '24px 16px', margin: 'auto 0' }}>
                      <p style={{ fontWeight: 600, color: 'var(--text-strong)' }}>Awaiting Live Inference Traffic</p>
                      <p style={{ fontSize: '12px', marginTop: '6px', color: 'var(--text-muted)' }}>
                        Start Live Capture to feed real-time 802.11 frames into the 5-second Random Forest detection pipeline.
                      </p>
                      <div style={{ display: 'flex', gap: '8px', justifyContent: 'center', marginTop: '14px' }}>
                        <button
                          type="button"
                          className="scan-button primary"
                          style={{ fontSize: '12px', padding: '6px 14px' }}
                          onClick={() => setActiveView('Live Monitor')}
                        >
                          Open Live Monitor →
                        </button>
                        <button
                          type="button"
                          className="scan-button"
                          style={{ fontSize: '12px', padding: '6px 14px' }}
                          onClick={() => {
                            setActiveView('ML Engine')
                            setMlEngineTab('live')
                          }}
                        >
                          Inspect ML Engine →
                        </button>
                      </div>
                    </div>
                  )}
                </section>

                {/* Column 2: Recent Security Incidents Summary Feed */}
                <section className="panel" style={{ display: 'flex', flexDirection: 'column' }}>
                  <div className="panel-header">
                    <div>
                      <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                        Recent Security Incidents
                      </h3>
                      <p style={{ margin: '2px 0 0', fontSize: '11.5px', color: 'var(--text-muted)' }}>
                        Click any incident row to inspect complete 31-feature forensics.
                      </p>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="badge badge-default">{incidents.length} Logged</span>
                      <button
                        type="button"
                        className="btn btn-secondary"
                        style={{ fontSize: '11.5px', padding: '4px 10px' }}
                        onClick={() => setActiveView('Incidents')}
                      >
                        View All Incidents →
                      </button>
                    </div>
                  </div>

                  {incidents.length > 0 ? (
                    <div className="table-wrap dashboard-table-scroll" style={{ marginTop: '10px' }}>
                      <table>
                        <thead>
                          <tr>
                            <th>ID</th>
                            <th>Time</th>
                            <th>Attack Label</th>
                            <th>Attack Probability</th>
                            <th>Packets</th>
                            <th>Severity</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {incidents.slice(0, 6).map((incident, idx) => (
                            <tr
                              key={incident.id ?? idx}
                              className="dashboard-incident-row"
                              onClick={() => setSelectedIncident(incident)}
                              title="Click to inspect incident forensics drawer"
                            >
                              <td style={{ fontFamily: 'var(--mono)', fontWeight: 600 }}>#{incident.id}</td>
                              <td style={{ fontSize: '12px' }}>{formatDateTime(incident.created_at)}</td>
                              <td>
                                <span className="badge badge-detection">
                                  {formatValue(incident.label ?? incident.prediction)}
                                </span>
                              </td>
                              <td style={{ fontFamily: 'var(--mono)' }}>{formatProbability(incident.attack_probability)}</td>
                              <td style={{ fontFamily: 'var(--mono)' }}>{formatValue(incident.total_packets)}</td>
                              <td>
                                <span className={getSeverityBadgeClass(incident.severity)}>
                                  {formatValue(incident.severity)}
                                </span>
                              </td>
                              <td>
                                <span className={getStatusBadgeClass(incident.status)}>
                                  {formatValue(incident.status)}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="empty-state" style={{ padding: '24px 16px', margin: 'auto 0' }}>
                      <p style={{ fontWeight: 600, color: 'var(--text-strong)' }}>No Security Incidents Logged</p>
                      <p style={{ fontSize: '12px', marginTop: '6px', color: 'var(--text-muted)' }}>
                        When the ML detector classifies anomalous 802.11 attack patterns (such as Deauth or Disassoc bursts), incidents appear here with forensic evidence.
                      </p>
                    </div>
                  )}
                </section>
              </div>
            </section>
          ) : activeView === 'WiFi Scan' ? (
            <section className="wifi-scan-view" aria-label="WiFi scan">
              {wifiScanError ? <p className="error-banner">{wifiScanError}</p> : null}

              {/* Unified Control & Telemetry Bar */}
              <section className="panel wifi-scan-control-panel">
                <div className="scan-control-row">
                  <div className="scan-control-left">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <h2 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--text-strong)' }}>
                        Wi-Fi Spectrum Scanner
                      </h2>
                      <span
                        className={
                          isScannerRunning
                            ? 'badge badge-status-resolved'
                            : isScannerStarting || isScannerStopping
                              ? 'badge badge-severity-medium'
                              : 'badge badge-default'
                        }
                      >
                        {formatValue(
                          getValue(scannerStatus, ['state', 'scanner_state', 'status']) ||
                            (isScannerRunning ? 'Running' : 'Idle'),
                        )}
                      </span>
                    </div>

                    {selectableInterfaces.length > 1 ? (
                      <label className="adapter-select-inline">
                        <span>Interface:</span>
                        <select
                          disabled={isScannerActive}
                          onChange={(e) => setSelectedInterfaceName(e.target.value)}
                          value={selectedInterfaceName}
                        >
                          {selectableInterfaces.map((adapter) => {
                            const adapterName = getInterfaceName(adapter)
                            return (
                              <option key={adapterName} value={adapterName}>
                                {adapterName}
                              </option>
                            )
                          })}
                        </select>
                      </label>
                    ) : (
                      <span className="scan-meta-pill">
                        Interface: <strong>{selectedInterface || 'None'}</strong>
                      </span>
                    )}

                    {wirelessAdapter ? (
                      <span className="scan-meta-pill">
                        Mode: <strong>{formatValue(getValue(wirelessAdapter, ['mode']))}</strong>
                      </span>
                    ) : null}

                    <span className="scan-meta-pill">
                      Sweep: <strong>#{formatValue(getValue(scannerProgress, ['sweep_number']) || 1)}</strong> (Ch{' '}
                      {formatValue(getValue(scannerProgress, ['current_channel']) || '--')} &bull;{' '}
                      {formatValue(getValue(scannerProgress, ['channels_completed']) || 0)}/
                      {formatValue(getValue(scannerProgress, ['total_channels']) || 14)})
                    </span>

                    <span className="scan-meta-pill">
                      Discovered:{' '}
                      <strong style={{ color: 'var(--accent-text)' }}>
                        {formatValue(getValue(scannerProgress, ['session_network_count']) || networks.length)} APs
                      </strong>
                    </span>
                  </div>

                  <div className="scan-control-right">
                    <button
                      className="scan-button primary"
                      disabled={startScanDisabled}
                      onClick={handleStartScan}
                      type="button"
                    >
                      {isScannerStarting ? 'Starting...' : isScannerRunning ? 'Scanning...' : 'Start Scan'}
                    </button>
                    <button
                      className="scan-button"
                      disabled={stopScanDisabled}
                      onClick={handleStopScan}
                      type="button"
                    >
                      {isScannerStopping ? 'Stopping...' : 'Stop Scan'}
                    </button>
                  </div>
                </div>

                {!wirelessAdapter && !wifiScanLoading ? (
                  <div className="empty-state" style={{ padding: '8px 12px', margin: '4px 0 0' }}>
                    <p style={{ margin: 0, fontSize: '12.5px', color: '#fca5a5' }}>
                      No wireless adapter detected. Connect a compatible Wi-Fi adapter to enable channel sweeping.
                    </p>
                  </div>
                ) : null}

                {/* Filter & Search Toolbar */}
                <div className="scan-filter-toolbar">
                  <input
                    aria-label="Filter networks by SSID, BSSID, or Vendor"
                    className="scan-search-input"
                    onChange={(e) => setScanSearch(e.target.value)}
                    placeholder="Search SSID, BSSID, Vendor..."
                    type="text"
                    value={scanSearch}
                  />

                  <div className="filter-chips">
                    <button
                      className={`filter-chip ${scanFilter === 'all' ? 'active' : ''}`}
                      onClick={() => setScanFilter('all')}
                      type="button"
                    >
                      All ({networks.length})
                    </button>
                    <button
                      className={`filter-chip ${scanFilter === '5ghz' ? 'active' : ''}`}
                      onClick={() => setScanFilter('5ghz')}
                      type="button"
                    >
                      5 GHz ({networks.filter((n) => Number(getValue(n, ['channel', 'Channel'])) >= 36).length})
                    </button>
                    <button
                      className={`filter-chip ${scanFilter === '2ghz' ? 'active' : ''}`}
                      onClick={() => setScanFilter('2ghz')}
                      type="button"
                    >
                      2.4 GHz ({networks.filter((n) => {
                        const ch = Number(getValue(n, ['channel', 'Channel'])) || 0
                        return ch > 0 && ch <= 14
                      }).length})
                    </button>
                    <button
                      className={`filter-chip ${scanFilter === 'secured' ? 'active' : ''}`}
                      onClick={() => setScanFilter('secured')}
                      type="button"
                    >
                      Secured ({networks.filter((n) => {
                        const enc = String(getValue(n, ['encryption', 'security']) || '').toUpperCase()
                        return enc.includes('WPA') || enc.includes('WEP') || enc.includes('802.1X')
                      }).length})
                    </button>
                    <button
                      className={`filter-chip ${scanFilter === 'open' ? 'active' : ''}`}
                      onClick={() => setScanFilter('open')}
                      type="button"
                    >
                      Open ({networks.filter((n) => {
                        const enc = String(getValue(n, ['encryption', 'security']) || '').toUpperCase()
                        return enc.includes('OPEN') || enc === '' || enc === 'NONE'
                      }).length})
                    </button>
                  </div>
                </div>
              </section>

              {/* Scanned Networks Table Panel */}
              <section className="panel networks-panel" style={{ padding: 0, overflow: 'hidden' }}>
                {wifiScanLoading && networks.length === 0 ? (
                  <p className="muted-text" style={{ padding: '24px' }}>Loading scanned networks...</p>
                ) : networks.length > 0 ? (
                  <div className="table-wrap wifi-scan-table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>SSID &amp; Access Point</th>
                          <th>Band &amp; Channel</th>
                          <th>Signal Strength</th>
                          <th>Encryption / Security</th>
                          <th>Analysis Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredScanNetworks.length > 0 ? (
                          filteredScanNetworks.map((network, index) => {
                            const bssid = formatValue(getValue(network, ['bssid', 'BSSID']))
                            const ssid = formatValue(getValue(network, ['ssid', 'SSID']))
                            const vendor = getValue(network, ['vendor', 'Vendor'])
                            const ch = Number(getValue(network, ['channel', 'Channel'])) || 0
                            const band = ch >= 36 ? '5 GHz' : ch > 0 ? '2.4 GHz' : 'Auto'
                            const sigRaw = formatValue(getValue(network, ['signal', 'Signal']))
                            const sigNum = parseInt(String(sigRaw || '').replace(/[^0-9-]/g, ''), 10)
                            const enc = formatValue(getValue(network, ['encryption']))
                            const isOpen = String(enc || '').toUpperCase().includes('OPEN') || enc === 'None' || !enc
                            const analysisStatus = formatValue(
                              getValue(network, [
                                'analysis_status',
                                'analysisStatus',
                                'Analysis Status',
                              ]),
                            )

                            return (
                              <tr key={bssid || index}>
                                <td>
                                  <div className="net-ssid-cell">
                                    <strong>{ssid || '<Hidden SSID>'}</strong>
                                    <span className="net-bssid-sub">{bssid || 'Unknown BSSID'}</span>
                                    {vendor && vendor !== 'Unknown Vendor' && vendor !== 'Unknown' ? (
                                      <span className="net-vendor-chip">{vendor}</span>
                                    ) : null}
                                  </div>
                                </td>
                                <td>
                                  <span className="mono-val">Ch {ch || '?'}</span>
                                  <span className="band-sub">{band}</span>
                                </td>
                                <td>
                                  <span
                                    className="mono-val"
                                    style={{
                                      color:
                                        sigNum >= -65
                                          ? '#2dd4bf'
                                          : sigNum >= -75
                                            ? '#38bdf8'
                                            : sigNum >= -85
                                              ? '#fde047'
                                              : '#f87171',
                                    }}
                                  >
                                    {sigRaw || '--'}
                                  </span>
                                </td>
                                <td>
                                  <span
                                    className={`badge ${
                                      isOpen ? 'badge-severity-high' : 'badge-status-resolved'
                                    }`}
                                  >
                                    {enc || 'Open'}
                                  </span>
                                </td>
                                <td>
                                  <span
                                    className={`badge ${
                                      String(analysisStatus).toLowerCase() === 'analyzed'
                                        ? 'badge-status-resolved'
                                        : 'badge-default'
                                    }`}
                                  >
                                    {analysisStatus || 'Queued'}
                                  </span>
                                </td>
                              </tr>
                            )
                          })
                        ) : (
                          <tr>
                            <td colSpan={5} style={{ textAlign: 'center', padding: '32px' }}>
                              <p style={{ color: 'var(--text-strong)', marginBottom: '8px' }}>
                                No networks match &ldquo;{scanSearch}&rdquo;
                              </p>
                              <button
                                className="scan-button"
                                onClick={() => {
                                  setScanSearch('')
                                  setScanFilter('all')
                                }}
                                type="button"
                              >
                                Clear Filter
                              </button>
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state" style={{ padding: '36px 20px' }}>
                    <p style={{ fontWeight: 600, color: 'var(--text-strong)' }}>
                      No scanned networks are available.
                    </p>
                    <p className="muted-text">
                      Click &ldquo;Start Scan&rdquo; above to sweep wireless channels and discover nearby access points.
                    </p>
                  </div>
                )}
              </section>
            </section>
          ) : activeView === 'Live Monitor' ? (
            <section className="live-monitor-view" aria-label="Live packet monitor">
              {liveMonitorError ? <p className="error-banner">{liveMonitorError}</p> : null}

              {/* Unified Control & Status Bar */}
              <section className="panel wifi-scan-control-panel">
                <div className="scan-control-row">
                  <div className="scan-control-left">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <h2 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--text-strong)' }}>
                        Live Packet Monitor
                      </h2>
                      <span
                        className={
                          isCaptureRunning
                            ? 'badge badge-status-resolved'
                            : isCaptureStarting || isCaptureStopping
                              ? 'badge badge-severity-medium'
                              : 'badge badge-default'
                        }
                      >
                        {isCaptureRunning
                          ? 'Capturing'
                          : isCaptureStarting
                            ? 'Starting...'
                            : isCaptureStopping
                              ? 'Stopping...'
                              : 'Standby'}
                      </span>
                    </div>

                    {selectableInterfaces.length > 1 ? (
                      <label className="adapter-select-inline">
                        <span>Interface:</span>
                        <select
                          disabled={isCaptureActive}
                          onChange={(e) => setSelectedCaptureInterfaceName(e.target.value)}
                          value={selectedCaptureInterfaceName}
                        >
                          {selectableInterfaces.map((adapter) => {
                            const adapterName = getInterfaceName(adapter)
                            return (
                              <option key={adapterName} value={adapterName}>
                                {adapterName}
                              </option>
                            )
                          })}
                        </select>
                      </label>
                    ) : (
                      <span className="scan-meta-pill">
                        Interface: <strong>{selectedCaptureInterface || 'None'}</strong>
                      </span>
                    )}

                    <span className="scan-meta-pill">
                      Mode:{' '}
                      <strong>
                        {formatValue(getValue(captureStatus, ['mode']) ?? getValue(captureAdapter, ['mode']))}
                      </strong>
                    </span>

                    {getValue(captureStatus, ['pid', 'process_id']) ? (
                      <span className="scan-meta-pill">
                        PID: <strong>{formatValue(getValue(captureStatus, ['pid', 'process_id']))}</strong>
                      </span>
                    ) : null}

                    <span className="scan-meta-pill">
                      Sweep: <strong>#{formatValue(getValue(captureProgress, ['sweep_number']) || 1)}</strong> (Ch{' '}
                      {formatValue(getValue(captureProgress, ['current_channel']) || '--')} &bull;{' '}
                      {formatValue(getValue(captureProgress, ['channel_index']) || 0)}/
                      {formatValue(getValue(captureProgress, ['total_channels']) || 14)})
                    </span>
                  </div>

                  <div className="scan-control-right">
                    <button
                      className="scan-button primary"
                      disabled={startCaptureDisabled}
                      onClick={handleStartCapture}
                      type="button"
                    >
                      {isCaptureStarting ? 'Starting...' : isCaptureRunning ? 'Capturing...' : 'Start Capture'}
                    </button>
                    <button
                      className="scan-button"
                      disabled={stopCaptureDisabled}
                      onClick={handleStopCapture}
                      type="button"
                    >
                      {isCaptureStopping ? 'Stopping...' : 'Stop Capture'}
                    </button>
                  </div>
                </div>

                {!captureAdapter && !liveMonitorLoading ? (
                  <div className="empty-state" style={{ padding: '8px 12px', margin: '4px 0 0' }}>
                    <p style={{ margin: 0, fontSize: '12.5px', color: '#fca5a5' }}>
                      No wireless adapter detected. Connect a compatible monitor-mode Wi-Fi adapter to start packet capture.
                    </p>
                  </div>
                ) : null}
              </section>

              {/* Live Telemetry KPI Strip */}
              <div className="live-telemetry-grid">
                <article className="live-telemetry-card">
                  <p>Session Packets</p>
                  <strong>{formatValue(getValue(captureProgress, ['packet_count']) ?? packets.length)}</strong>
                </article>
                <article className="live-telemetry-card">
                  <p>Packet Rate</p>
                  <strong style={{ color: isCaptureRunning ? 'var(--accent-text)' : 'inherit' }}>
                    {formatWithUnit(getValue(captureProgress, ['packet_rate']), 'pkt/s')}
                  </strong>
                </article>
                <article className="live-telemetry-card">
                  <p>Elapsed Time</p>
                  <strong>{formatWithUnit(getValue(captureProgress, ['elapsed_seconds']), 's')}</strong>
                </article>
                <article className="live-telemetry-card">
                  <p>Last Frame Ingest</p>
                  <strong style={{ fontSize: '14px', lineHeight: '24px' }}>
                    {formatValue(getValue(captureProgress, ['last_packet_at'])) || 'No packets yet'}
                  </strong>
                </article>
              </div>

              {/* Streamlined Frame Type Counts Bar */}
              {Object.keys(packetTypeCounts).length > 0 ? (
                <section className="panel packet-types-panel">
                  <div className="packet-types-header">
                    <span className="packet-types-title">Live 802.11 Frame Distribution</span>
                    <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      {Object.keys(packetTypeCounts).length} types observed
                    </span>
                  </div>
                  <div className="count-grid" style={{ margin: 0 }}>
                    {Object.entries(packetTypeCounts).map(([packetType, count]) => {
                      const isAlert =
                        packetType.toLowerCase().includes('deauth') ||
                        packetType.toLowerCase().includes('disas')

                      return (
                        <div className={`packet-type-pill ${isAlert ? 'alert' : ''}`} key={packetType}>
                          <span>{packetType}</span>
                          <strong>{formatValue(count)}</strong>
                        </div>
                      )
                    })}
                  </div>
                </section>
              ) : null}

              {/* Bounded Monospace Packets Stream Table */}
              <section className="panel packets-panel" style={{ padding: 0, overflow: 'hidden' }}>
                <div
                  className="panel-header"
                  style={{ padding: '12px 18px', borderBottom: '1px solid var(--border)' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <h2 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--text-strong)' }}>
                      Live IEEE 802.11 Frame Stream
                    </h2>
                    <span className="badge badge-default">{packets.length} Packets Buffered</span>
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Monospace Real-Time Telemetry
                  </span>
                </div>

                {liveMonitorLoading && packets.length === 0 ? (
                  <p className="muted-text" style={{ padding: '24px' }}>Loading packet stream...</p>
                ) : packets.length > 0 ? (
                  <div className="table-wrap live-packets-table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Classification / Subtype</th>
                          <th>Source MAC</th>
                          <th>Destination MAC</th>
                          <th>BSSID</th>
                          <th>Frame Type</th>
                          <th>Signal</th>
                        </tr>
                      </thead>
                      <tbody>
                        {packets.map((packet, index) => {
                          const pType = formatValue(getValue(packet, ['packet_type', 'type', 'classification']))
                          const isDeauth =
                            String(pType).toLowerCase().includes('deauth') ||
                            String(pType).toLowerCase().includes('disas')
                          const sigRaw = getValue(packet, ['signal_strength'])
                          const sigNum = parseInt(String(sigRaw || '').replace(/[^0-9-]/g, ''), 10)

                          return (
                            <tr key={getValue(packet, ['id', 'packet_id']) ?? index}>
                              <td>
                                <span className="mono-val">
                                  {formatValue(getValue(packet, ['time', 'timestamp', 'captured_at']))}
                                </span>
                              </td>
                              <td>
                                <span className={`badge ${isDeauth ? 'badge-severity-high' : 'badge-default'}`}>
                                  {pType}
                                </span>
                              </td>
                              <td>
                                <span className="mono-val" style={{ fontSize: '12px' }}>
                                  {formatValue(getValue(packet, ['source_mac', 'src_mac', 'source']))}
                                </span>
                              </td>
                              <td>
                                <span className="mono-val" style={{ fontSize: '12px' }}>
                                  {formatValue(getValue(packet, ['destination_mac', 'dst_mac', 'destination']))}
                                </span>
                              </td>
                              <td>
                                <span className="mono-val" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                                  {formatValue(getValue(packet, ['bssid']))}
                                </span>
                              </td>
                              <td>
                                <span className="mono-val">
                                  {formatValue(getValue(packet, ['frame_type', 'frame']))}
                                </span>
                              </td>
                              <td>
                                <span
                                  className="mono-val"
                                  style={{
                                    color:
                                      sigNum >= -65
                                        ? '#2dd4bf'
                                        : sigNum >= -75
                                          ? '#38bdf8'
                                          : sigNum >= -85
                                            ? '#fde047'
                                            : '#f87171',
                                  }}
                                >
                                  {formatWithUnit(sigRaw, 'dBm')}
                                </span>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state" style={{ padding: '36px 20px' }}>
                    <p style={{ fontWeight: 600, color: 'var(--text-strong)' }}>
                      No captured packets are available.
                    </p>
                    <p className="muted-text">
                      Click &ldquo;Start Capture&rdquo; above to begin intercepting IEEE 802.11 wireless frames in monitor mode.
                    </p>
                  </div>
                )}
              </section>
            </section>
          ) : activeView === 'ML Engine' ? (
            <section className="ml-engine-view" aria-label="ML Engine">
              {mlEngineTab === 'live' && mlDetectionError ? <p className="error-banner">{mlDetectionError}</p> : null}
              {mlEngineTab === 'evaluation' && mlTestingError ? <p className="error-banner">{mlTestingError}</p> : null}

              {/* Unified ML Engine Header */}
              <section className="panel wifi-scan-control-panel">
                <div className="scan-control-row">
                  <div className="scan-control-left">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <h2 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--text-strong)' }}>
                        NetShield Machine Learning Engine
                      </h2>
                      <span
                        className={
                          mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined
                            ? mlLiveStatus.prediction === 0
                              ? 'badge badge-status-resolved'
                              : 'badge badge-severity-high'
                            : 'badge badge-default'
                        }
                      >
                        {mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined
                          ? mlLiveStatus.prediction === 0
                            ? 'Normal Traffic'
                            : (mlLiveStatus.label ?? 'Attack Detected')
                          : 'Awaiting 5s Window'}
                      </span>
                    </div>

                    <span className="scan-meta-pill">
                      Model: <strong>{mlSchemaInfo?.model_name || 'random_forest_awid3_v3_expanded'}</strong>
                    </span>

                    <span className="scan-meta-pill">
                      Cadence: <strong>5.0s Windows &bull; 2s Polling</strong>
                    </span>

                    <span className="scan-meta-pill">
                      Schema: <strong>{mlLiveStatus?.feature_count ?? mlSchemaInfo?.feature_count ?? 31} Canonical Features</strong>
                    </span>
                  </div>

                  <div className="scan-control-right">
                    <button
                      className="scan-button"
                      onClick={() => setActiveView('Live Monitor')}
                      type="button"
                    >
                      Live Sniffer Stream
                    </button>
                    {mlEngineTab !== 'evaluation' ? (
                      <button
                        className="scan-button"
                        onClick={() => setMlEngineTab('evaluation')}
                        type="button"
                      >
                        Offline Evaluation &rarr;
                      </button>
                    ) : (
                      <button
                        className="scan-button"
                        onClick={() => setMlEngineTab('live')}
                        type="button"
                      >
                        Live Detection &rarr;
                      </button>
                    )}
                  </div>
                </div>
              </section>

              {/* Master ML Engine Tab Bar */}
              <div className="soc-tab-bar" style={{ margin: '4px 0 0' }}>
                <button
                  className={`soc-tab-btn ${mlEngineTab === 'live' ? 'active' : ''}`}
                  onClick={() => setMlEngineTab('live')}
                  type="button"
                >
                  Live Threat Detection
                </button>
                <button
                  className={`soc-tab-btn ${mlEngineTab === 'evaluation' ? 'active' : ''}`}
                  onClick={() => setMlEngineTab('evaluation')}
                  type="button"
                >
                  Offline Dataset Evaluation
                </button>
                <button
                  className={`soc-tab-btn ${mlEngineTab === 'schema' ? 'active' : ''}`}
                  onClick={() => setMlEngineTab('schema')}
                  type="button"
                >
                  Feature Schema &amp; Model Spec
                </button>
              </div>

              {/* Tab 1: Live Threat Detection */}
              {mlEngineTab === 'live' ? (
                <>
                  {/* KPI Strip */}
              <div className="metric-grid">
                <article
                  className="metric-card"
                  style={{
                    borderTop:
                      mlLiveStatus?.prediction === 1
                        ? '3px solid #ef4444'
                        : mlLiveStatus?.prediction === 0
                          ? '3px solid #22c55e'
                          : '1px solid var(--border)',
                  }}
                >
                  <p>Inference Classification</p>
                  <strong
                    style={{
                      color:
                        mlLiveStatus?.prediction === 1
                          ? '#f87171'
                          : mlLiveStatus?.prediction === 0
                            ? '#34d399'
                            : 'var(--text-strong)',
                    }}
                  >
                    {mlLiveStatus?.label ??
                      (mlLiveStatus?.prediction === 1
                        ? 'Attack'
                        : mlLiveStatus?.prediction === 0
                          ? 'Normal'
                          : 'Awaiting Ingest')}
                  </strong>
                </article>

                <article className="metric-card">
                  <p>Prediction Class</p>
                  <strong>
                    {mlLiveStatus?.prediction !== undefined && mlLiveStatus?.prediction !== null
                      ? `Class ${mlLiveStatus.prediction}`
                      : '--'}
                  </strong>
                </article>

                <article className="metric-card">
                  <p>Attack Probability</p>
                  <strong
                    style={{
                      color:
                        (mlLiveStatus?.attack_probability || 0) > 0.5 ? '#f87171' : 'var(--text-strong)',
                    }}
                  >
                    {mlLiveStatus?.attack_probability !== undefined && mlLiveStatus?.attack_probability !== null
                      ? `${(mlLiveStatus.attack_probability * 100).toFixed(1)}%`
                      : '--'}
                  </strong>
                </article>

                <article className="metric-card">
                  <p>Normal Probability</p>
                  <strong
                    style={{
                      color:
                        (mlLiveStatus?.normal_probability || 0) > 0.5 ? '#34d399' : 'var(--text-strong)',
                    }}
                  >
                    {mlLiveStatus?.normal_probability !== undefined && mlLiveStatus?.normal_probability !== null
                      ? `${(mlLiveStatus.normal_probability * 100).toFixed(1)}%`
                      : '--'}
                  </strong>
                </article>
              </div>

              {/* Probability Meter Panel */}
              <section className="panel" style={{ padding: '16px 20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                    Random Forest Decision Probability Distribution
                  </h3>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Binary Classification Threshold: 0.50 (50%)
                  </span>
                </div>

                <div className="prob-meter-row">
                  <div className="prob-meter-label">
                    <span>Attack Probability</span>
                    <strong style={{ color: (mlLiveStatus?.attack_probability || 0) > 0.5 ? '#f87171' : 'var(--text-strong)' }}>
                      {mlLiveStatus?.attack_probability !== undefined && mlLiveStatus?.attack_probability !== null
                        ? `${(mlLiveStatus.attack_probability * 100).toFixed(1)}%`
                        : '0.0%'}
                    </strong>
                  </div>
                  <div className="prob-meter-bar" style={{ height: '8px', position: 'relative' }}>
                    <div
                      className="prob-meter-fill"
                      style={{
                        width: `${Math.min(100, Math.max(0, (mlLiveStatus?.attack_probability || 0) * 100))}%`,
                        background: (mlLiveStatus?.attack_probability || 0) > 0.5 ? '#ef4444' : '#14b8a6',
                      }}
                    />
                  </div>
                </div>

                <div className="prob-meter-row">
                  <div className="prob-meter-label">
                    <span>Normal Probability</span>
                    <strong>
                      {mlLiveStatus?.normal_probability !== undefined && mlLiveStatus?.normal_probability !== null
                        ? `${(mlLiveStatus.normal_probability * 100).toFixed(1)}%`
                        : '0.0%'}
                    </strong>
                  </div>
                  <div className="prob-meter-bar" style={{ height: '8px' }}>
                    <div
                      className="prob-meter-fill"
                      style={{
                        width: `${Math.min(100, Math.max(0, (mlLiveStatus?.normal_probability || 0) * 100))}%`,
                        background: '#2dd4bf',
                      }}
                    />
                  </div>
                </div>

                {mlLiveStatus?.status === 'no_inference' || mlLiveStatus === null ? (
                  <div className="empty-state" style={{ padding: '16px', marginTop: '12px' }}>
                    <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-strong)' }}>
                      Waiting for the first completed 5-second inference window.
                    </p>
                    <p className="muted-text" style={{ margin: '4px 0 0', fontSize: '12px' }}>
                      Start live packet capture from the Live Monitor page to feed 802.11 frames to the Random Forest model.
                    </p>
                  </div>
                ) : null}
              </section>

              {/* Navigation Tabs */}
              <div className="soc-tab-bar">
                <button
                  className={`soc-tab-btn ${mlDetectionTab === 'overview' ? 'active' : ''}`}
                  onClick={() => setMlDetectionTab('overview')}
                  type="button"
                >
                  Temporal Diagnostics
                </button>
                <button
                  className={`soc-tab-btn ${mlDetectionTab === 'features' ? 'active' : ''}`}
                  onClick={() => setMlDetectionTab('features')}
                  type="button"
                >
                  Canonical 31-Feature Schema
                </button>
                <button
                  className={`soc-tab-btn ${mlDetectionTab === 'signatures' ? 'active' : ''}`}
                  onClick={() => setMlDetectionTab('signatures')}
                  type="button"
                >
                  Threat Signatures &amp; Vectors
                </button>
              </div>

              {/* Tab 1: Temporal Diagnostics */}
              {mlDetectionTab === 'overview' ? (
                <section className="panel" style={{ padding: '16px 20px' }}>
                  <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                    Inference Window Specifications
                  </h3>

                  <dl className="status-list" style={{ marginBottom: '16px' }}>
                    <div>
                      <dt>Total Packets in Window</dt>
                      <dd>{formatValue(mlLiveStatus?.total_packets ?? 0)}</dd>
                    </div>
                    <div>
                      <dt>Feature Count</dt>
                      <dd>{formatValue(mlLiveStatus?.feature_count ?? mlSchemaInfo?.feature_count ?? 31)}</dd>
                    </div>
                    <div>
                      <dt>Window Start</dt>
                      <dd>
                        {mlLiveStatus?.window_start
                          ? `${new Date(mlLiveStatus.window_start * 1000).toLocaleTimeString()} (${mlLiveStatus.window_start})`
                          : '--'}
                      </dd>
                    </div>
                    <div>
                      <dt>Window End</dt>
                      <dd>
                        {mlLiveStatus?.window_end
                          ? `${new Date(mlLiveStatus.window_end * 1000).toLocaleTimeString()} (${mlLiveStatus.window_end})`
                          : '--'}
                      </dd>
                    </div>
                    <div>
                      <dt>Sampling Interval</dt>
                      <dd>5.0 Seconds Chronological</dd>
                    </div>
                    <div>
                      <dt>Model Engine</dt>
                      <dd>{mlSchemaInfo?.model_name || 'random_forest_awid3_v3_expanded.joblib'}</dd>
                    </div>
                  </dl>

                  {mlLiveStatus?.prediction === 1 ? (
                    <div
                      style={{
                        padding: '12px 16px',
                        borderRadius: '6px',
                        background: 'rgba(239, 68, 68, 0.12)',
                        border: '1px solid rgba(239, 68, 68, 0.35)',
                        color: '#fca5a5',
                        fontSize: '13px',
                      }}
                    >
                      <strong>Active Intrusion Flagged:</strong> The current 5-second traffic window breached the 50% attack threshold.
                      An incident was automatically dispatched to the Security Incidents log.
                    </div>
                  ) : mlLiveStatus?.prediction === 0 ? (
                    <div
                      style={{
                        padding: '12px 16px',
                        borderRadius: '6px',
                        background: 'rgba(34, 197, 94, 0.12)',
                        border: '1px solid rgba(34, 197, 94, 0.35)',
                        color: '#86efac',
                        fontSize: '13px',
                      }}
                    >
                      <strong>Benign Traffic Confirmed:</strong> Frame arrival intervals, management ratios, and burst counters
                      conform to expected non-malicious IEEE 802.11 operation.
                    </div>
                  ) : null}
                </section>
              ) : null}

              {/* Tab 2: Canonical 31-Feature Schema */}
              {mlDetectionTab === 'features' ? (
                <section className="panel" style={{ padding: '0', overflow: 'hidden' }}>
                  <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)' }}>
                    <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                      Canonical 31-Feature AWID3 Vector Definition
                    </h3>
                    <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>
                      Strictly ordered IEEE 802.11 feature vector utilized by the Random Forest model during 5-second window inference.
                    </p>
                  </div>

                  <div className="table-wrap schema-table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th style={{ width: '60px' }}>#</th>
                          <th>Feature Name</th>
                          <th>Scope / Category</th>
                          <th>Security &amp; Intrusion Rationale</th>
                        </tr>
                      </thead>
                      <tbody>
                        {[
                          { id: 1, name: 'total_packets', scope: '5s Window Base', desc: 'Total frames observed across the entire 5-second observation window.' },
                          { id: 2, name: 'packets_per_second', scope: '5s Window Base', desc: 'Overall frame arrival velocity across the channel.' },
                          { id: 3, name: 'beacon_count', scope: '5s Window Base', desc: 'Volume of AP beacon advertisements; detects beacon flooding or rogue APs.' },
                          { id: 4, name: 'probe_request_count', scope: '5s Window Base', desc: 'Client discovery requests; detects active probe mapping.' },
                          { id: 5, name: 'probe_response_count', scope: '5s Window Base', desc: 'AP responses to probes; detects rogue AP response poisoning.' },
                          { id: 6, name: 'authentication_count', scope: '5s Window Base', desc: '802.11 Open System / Shared Key authentication exchanges.' },
                          { id: 7, name: 'deauth_count', scope: '5s Window Base', desc: 'Deauthentication frames; key indicator of Wi-Fi DoS and handshake forcing.' },
                          { id: 8, name: 'disassociation_count', scope: '5s Window Base', desc: 'Disassociation frames indicating forced client severance.' },
                          { id: 9, name: 'reassociation_count', scope: '5s Window Base', desc: 'Reassociation attempts; flags fast-roaming hijackings.' },
                          { id: 10, name: 'data_count', scope: '5s Window Base', desc: 'Payload-bearing data frames (QoS and non-QoS).' },
                          { id: 11, name: 'control_count', scope: '5s Window Base', desc: 'Control frames (ACK, RTS, CTS); flags channel clearance jamming.' },
                          { id: 12, name: 'management_count', scope: '5s Window Base', desc: 'Aggregate Type 0 management frames across the window.' },
                          { id: 13, name: 'unique_source_macs', scope: '5s Window Base', desc: 'Count of unique transmitter addresses; detects MAC spoofing floods.' },
                          { id: 14, name: 'unique_destination_macs', scope: '5s Window Base', desc: 'Count of unique target addresses across the medium.' },
                          { id: 15, name: 'unique_bssids', scope: '5s Window Base', desc: 'Count of distinct basic service set identifiers active.' },
                          { id: 16, name: 'retry_count', scope: '5s Window Base', desc: 'Frames retransmitted due to missing ACK; indicates channel interference or jamming.' },
                          { id: 17, name: 'retry_ratio', scope: '5s Window Base', desc: 'Proportion of retried frames to total frames.' },
                          { id: 18, name: 'deauth_per_second', scope: '5s Window Base', desc: 'Sustained deauthentication frame rate.' },
                          { id: 19, name: 'disassociation_per_second', scope: '5s Window Base', desc: 'Sustained disassociation frame rate.' },
                          { id: 20, name: 'reassociation_per_second', scope: '5s Window Base', desc: 'Sustained reassociation frame rate.' },
                          { id: 21, name: 'beacon_per_second', scope: '5s Window Base', desc: 'AP beacon transmission frequency.' },
                          { id: 22, name: 'management_ratio', scope: '5s Window Base', desc: 'Proportion of management traffic relative to total frames.' },
                          { id: 23, name: 'control_ratio', scope: '5s Window Base', desc: 'Proportion of control traffic relative to total frames.' },
                          { id: 24, name: 'data_ratio', scope: '5s Window Base', desc: 'Proportion of data traffic relative to total frames.' },
                          { id: 25, name: 'clients_per_bssid', scope: '5s Window Base', desc: 'Client-to-AP ratio; flags fake client enumeration.' },
                          { id: 26, name: 'max_packets_1s', scope: '1s Sub-Window Burst', desc: 'Peak packet count in any 1-second interval; catches micro-burst floods.' },
                          { id: 27, name: 'max_deauth_1s', scope: '1s Sub-Window Burst', desc: 'Peak deauthentication frames in any 1-second interval.' },
                          { id: 28, name: 'max_disassoc_1s', scope: '1s Sub-Window Burst', desc: 'Peak disassociation frames in any 1-second interval.' },
                          { id: 29, name: 'packet_burst_ratio', scope: '1s Sub-Window Burst', desc: 'Ratio of 1-second peak packets to total window packets.' },
                          { id: 30, name: 'deauth_burst_ratio', scope: '1s Sub-Window Burst', desc: 'Ratio of 1-second peak deauth frames to window deauth frames.' },
                          { id: 31, name: 'disassoc_burst_ratio', scope: '1s Sub-Window Burst', desc: 'Ratio of 1-second peak disassoc frames to window disassoc frames.' },
                        ].map((feat) => (
                          <tr key={feat.id}>
                            <td>
                              <span className="mono-val" style={{ color: 'var(--text-muted)' }}>
                                #{feat.id}
                              </span>
                            </td>
                            <td>
                              <strong className="mono-val" style={{ color: '#38bdf8' }}>
                                {feat.name}
                              </strong>
                            </td>
                            <td>
                              <span
                                className={`badge ${
                                  feat.scope.includes('Burst') ? 'badge-severity-medium' : 'badge-default'
                                }`}
                              >
                                {feat.scope}
                              </span>
                            </td>
                            <td style={{ fontSize: '12.5px', color: 'var(--text)' }}>
                              {feat.desc}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              ) : null}

              {/* Tab 3: Threat Signatures & Vectors */}
              {mlDetectionTab === 'signatures' ? (
                <div className="threat-signature-grid">
                  <article className="threat-sig-card">
                    <h3>Deauthentication Flooding (DoS)</h3>
                    <p>
                      Adversaries forge spoofed 802.11 Deauth management frames purporting to originate from the AP or client,
                      forcing mutual disconnection to capture 4-way WPA handshakes or degrade connectivity.
                    </p>
                    <div className="threat-sig-features">
                      <span className="threat-sig-feat-pill">deauth_count</span>
                      <span className="threat-sig-feat-pill">max_deauth_1s</span>
                      <span className="threat-sig-feat-pill">deauth_burst_ratio</span>
                      <span className="threat-sig-feat-pill">deauth_per_second</span>
                    </div>
                  </article>

                  <article className="threat-sig-card">
                    <h3>Disassociation Attack</h3>
                    <p>
                      Similar to deauthentication, disassociation frames notify authenticated stations that their association
                      is terminated. High burst ratios indicate active automated disconnection scripts.
                    </p>
                    <div className="threat-sig-features">
                      <span className="threat-sig-feat-pill">disassociation_count</span>
                      <span className="threat-sig-feat-pill">max_disassoc_1s</span>
                      <span className="threat-sig-feat-pill">disassoc_burst_ratio</span>
                    </div>
                  </article>

                  <article className="threat-sig-card">
                    <h3>Rogue AP &amp; Beacon Flooding</h3>
                    <p>
                      Attackers broadcast thousands of fake SSIDs with high-frequency beacon intervals, overwhelming client
                      Wi-Fi drivers and creating visual clutter or rogue evil-twin honeypots.
                    </p>
                    <div className="threat-sig-features">
                      <span className="threat-sig-feat-pill">beacon_count</span>
                      <span className="threat-sig-feat-pill">beacon_per_second</span>
                      <span className="threat-sig-feat-pill">unique_bssids</span>
                      <span className="threat-sig-feat-pill">unique_source_macs</span>
                    </div>
                  </article>

                  <article className="threat-sig-card">
                    <h3>Traffic Flooding &amp; Jamming</h3>
                    <p>
                      Anomalous spikes in frame rates, extreme retry ratios, and high control frame proportions indicate RF
                      contention, intentional jamming, or raw frame injection attacks.
                    </p>
                    <div className="threat-sig-features">
                      <span className="threat-sig-feat-pill">packets_per_second</span>
                      <span className="threat-sig-feat-pill">max_packets_1s</span>
                      <span className="threat-sig-feat-pill">packet_burst_ratio</span>
                      <span className="threat-sig-feat-pill">retry_ratio</span>
                    </div>
                  </article>
                </div>
              ) : null}
            </>
          ) : null}

          {/* Tab 2: Offline Dataset Evaluation */}
          {mlEngineTab === 'evaluation' ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Model Specification & Evaluation Control Bar */}
              <section className="panel model-spec-panel" style={{ padding: '16px 20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '8px', marginBottom: '12px' }}>
                  <div>
                    <h2 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--text-strong)' }}>
                      AWID3 Machine Learning Model Evaluation
                    </h2>
                    <p style={{ margin: '3px 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>
                      Benchmark test Wi-Fi intrusion datasets against the frozen Random Forest model without retraining.
                    </p>
                  </div>

                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <span className="scan-meta-pill">
                      Model: <strong>{mlSchemaInfo?.model_name || 'random_forest_awid3_v3_expanded.joblib'}</strong>
                    </span>
                    <span className="scan-meta-pill">
                      Schema: <strong>{mlSchemaInfo?.feature_count ?? 31} Canonical Features</strong>
                    </span>
                    <span className="scan-meta-pill">
                      Target: <strong>{mlSchemaInfo?.classification_type || 'Binary (0=Normal, 1=Attack)'}</strong>
                    </span>
                  </div>
                </div>

                <div className="test-control-bar" style={{ marginTop: '12px' }}>
                  <label htmlFor="dataset-select" style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1 }}>
                    <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-strong)' }}>
                      Select Evaluation Dataset (backend/data/)
                    </span>
                    <select
                      id="dataset-select"
                      onChange={(e) => setSelectedDataset(e.target.value)}
                      value={selectedDataset}
                    >
                      {mlDatasets.map((d) => (
                        <option key={d.name || d.filename} value={d.name || d.filename}>
                          {d.name || d.filename} &mdash; {d.sample_count} samples ({d.normal_count} normal, {d.attack_count} attack)
                        </option>
                      ))}
                    </select>
                  </label>

                  <button
                    className="scan-button primary"
                    disabled={mlTestingLoading || !selectedDataset}
                    onClick={handleRunMlTest}
                    style={{ whiteSpace: 'nowrap', height: '38px', alignSelf: 'flex-end' }}
                    type="button"
                  >
                    {mlTestingLoading ? 'Evaluating Test Dataset...' : 'Run Model Evaluation'}
                  </button>
                </div>
              </section>

              {mlTestResult ? (
                <>
                  {/* KPI Summary Strip */}
                  <div className="metric-grid">
                    <article className="metric-card" style={{ borderTop: '3px solid var(--accent)' }}>
                      <p>Model Accuracy</p>
                      <strong style={{ color: 'var(--accent-text)' }}>
                        {mlTestResult.metrics?.accuracy !== undefined && mlTestResult.metrics?.accuracy !== null
                          ? `${mlTestResult.metrics.accuracy}%`
                          : '--'}
                      </strong>
                    </article>
                    <article className="metric-card">
                      <p>Precision (Attack)</p>
                      <strong>
                        {mlTestResult.metrics?.precision !== undefined && mlTestResult.metrics?.precision !== null
                          ? `${mlTestResult.metrics.precision}%`
                          : '--'}
                      </strong>
                    </article>
                    <article className="metric-card">
                      <p>Recall (Attack)</p>
                      <strong>
                        {mlTestResult.metrics?.recall !== undefined && mlTestResult.metrics?.recall !== null
                          ? `${mlTestResult.metrics.recall}%`
                          : '--'}
                      </strong>
                    </article>
                    <article className="metric-card">
                      <p>F1-Score (Attack)</p>
                      <strong>
                        {mlTestResult.metrics?.f1_score !== undefined && mlTestResult.metrics?.f1_score !== null
                          ? `${mlTestResult.metrics.f1_score}%`
                          : '--'}
                      </strong>
                    </article>
                    <article className="metric-card">
                      <p>Evaluated Samples</p>
                      <strong>{formatValue(mlTestResult.total_samples)}</strong>
                    </article>
                  </div>

                  {/* Tabs Bar */}
                  <div className="soc-tab-bar">
                    <button
                      className={`soc-tab-btn ${mlTestingTab === 'matrix' ? 'active' : ''}`}
                      onClick={() => setMlTestingTab('matrix')}
                      type="button"
                    >
                      Confusion Matrix &amp; Class Metrics
                    </button>
                    <button
                      className={`soc-tab-btn ${mlTestingTab === 'samples' ? 'active' : ''}`}
                      onClick={() => setMlTestingTab('samples')}
                      type="button"
                    >
                      Sample Predictions Preview ({mlTestResult.sample_preview?.length ?? 0})
                    </button>
                    <button
                      className={`soc-tab-btn ${mlTestingTab === 'history' ? 'active' : ''}`}
                      onClick={() => setMlTestingTab('history')}
                      type="button"
                    >
                      Past Evaluation Runs ({mlTestRuns.length})
                    </button>
                  </div>

                  {/* Tab 1: Confusion Matrix & Class Metrics */}
                  {mlTestingTab === 'matrix' ? (
                    <div className="panel-grid">
                      <section className="panel" style={{ padding: '16px 20px' }}>
                        <div className="panel-header" style={{ marginBottom: '12px' }}>
                          <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                            2x2 Confusion Matrix
                          </h2>
                          <span className="badge badge-status-resolved">Evaluated Benchmark</span>
                        </div>
                        <div className="cm-container">
                          <div className="cm-header-cols">
                            <span className="cm-col-label">Predicted Normal (0)</span>
                            <span className="cm-col-label">Predicted Attack (1)</span>
                          </div>
                          <div className="cm-row">
                            <span className="cm-row-label">Actual Normal (0)</span>
                            <div className="cm-cell cm-tn">
                              <span className="cm-val">{mlTestResult.confusion_matrix?.true_negatives ?? 0}</span>
                              <span className="cm-desc">True Negatives (TN)</span>
                            </div>
                            <div className="cm-cell cm-fp">
                              <span className="cm-val">{mlTestResult.confusion_matrix?.false_positives ?? 0}</span>
                              <span className="cm-desc">False Positives (FP)</span>
                            </div>
                          </div>
                          <div className="cm-row">
                            <span className="cm-row-label">Actual Attack (1)</span>
                            <div className="cm-cell cm-fn">
                              <span className="cm-val">{mlTestResult.confusion_matrix?.false_negatives ?? 0}</span>
                              <span className="cm-desc">False Negatives (FN)</span>
                            </div>
                            <div className="cm-cell cm-tp">
                              <span className="cm-val">{mlTestResult.confusion_matrix?.true_positives ?? 0}</span>
                              <span className="cm-desc">True Positives (TP)</span>
                            </div>
                          </div>
                        </div>
                      </section>

                      <section className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                        <div
                          className="panel-header"
                          style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)' }}
                        >
                          <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                            Per-Class Classification Report
                          </h2>
                          <span className="badge badge-default">AWID3 Metrics</span>
                        </div>
                        <div className="table-wrap" style={{ margin: 0, border: 'none', borderRadius: 0 }}>
                          <table>
                            <thead>
                              <tr>
                                <th>Class</th>
                                <th>Precision</th>
                                <th>Recall</th>
                                <th>F1-Score</th>
                                <th>Support</th>
                              </tr>
                            </thead>
                            <tbody>
                              <tr>
                                <td>
                                  <strong>Normal (0)</strong>
                                </td>
                                <td>
                                  {mlTestResult.per_class?.Normal?.precision !== undefined &&
                                  mlTestResult.per_class?.Normal?.precision !== null
                                    ? `${mlTestResult.per_class.Normal.precision}%`
                                    : '--'}
                                </td>
                                <td>
                                  {mlTestResult.per_class?.Normal?.recall !== undefined &&
                                  mlTestResult.per_class?.Normal?.recall !== null
                                    ? `${mlTestResult.per_class.Normal.recall}%`
                                    : '--'}
                                </td>
                                <td>
                                  {mlTestResult.per_class?.Normal?.f1_score !== undefined &&
                                  mlTestResult.per_class?.Normal?.f1_score !== null
                                    ? `${mlTestResult.per_class.Normal.f1_score}%`
                                    : '--'}
                                </td>
                                <td>
                                  {mlTestResult.per_class?.Normal?.support ??
                                    mlTestResult.normal_support ??
                                    '--'}
                                </td>
                              </tr>
                              <tr>
                                <td>
                                  <strong style={{ color: '#f87171' }}>Attack (1)</strong>
                                </td>
                                <td>
                                  {mlTestResult.per_class?.Attack?.precision !== undefined &&
                                  mlTestResult.per_class?.Attack?.precision !== null
                                    ? `${mlTestResult.per_class.Attack.precision}%`
                                    : '--'}
                                </td>
                                <td>
                                  {mlTestResult.per_class?.Attack?.recall !== undefined &&
                                  mlTestResult.per_class?.Attack?.recall !== null
                                    ? `${mlTestResult.per_class.Attack.recall}%`
                                    : '--'}
                                </td>
                                <td>
                                  {mlTestResult.per_class?.Attack?.f1_score !== undefined &&
                                  mlTestResult.per_class?.Attack?.f1_score !== null
                                    ? `${mlTestResult.per_class.Attack.f1_score}%`
                                    : '--'}
                                </td>
                                <td>
                                  {mlTestResult.per_class?.Attack?.support ??
                                    mlTestResult.attack_support ??
                                    '--'}
                                </td>
                              </tr>
                              <tr style={{ background: 'rgba(30, 41, 59, 0.4)' }}>
                                <td>
                                  <strong>Overall Accuracy</strong>
                                </td>
                                <td
                                  colSpan="3"
                                  style={{ textAlign: 'center', color: 'var(--accent-text)', fontWeight: 'bold' }}
                                >
                                  {mlTestResult.metrics?.accuracy !== undefined &&
                                  mlTestResult.metrics?.accuracy !== null
                                    ? `${mlTestResult.metrics.accuracy}% Accuracy`
                                    : '--'}
                                </td>
                                <td>
                                  <strong>{mlTestResult.total_samples}</strong>
                                </td>
                              </tr>
                            </tbody>
                          </table>
                        </div>
                      </section>
                    </div>
                  ) : null}

                  {/* Tab 2: Sample Predictions Preview */}
                  {mlTestingTab === 'samples' && mlTestResult.sample_preview && mlTestResult.sample_preview.length > 0 ? (
                    <section className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                      <div
                        className="panel-header"
                        style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)' }}
                      >
                        <div>
                          <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                            Sample Predictions Preview
                          </h2>
                          <p style={{ margin: '2px 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>
                            Direct evaluation against canonical 31 features
                          </p>
                        </div>
                      </div>
                      <div className="table-wrap ml-samples-table-scroll" style={{ margin: 0, border: 'none', borderRadius: 0 }}>
                        <table>
                          <thead>
                            <tr>
                              <th>#</th>
                              <th>Ground Truth</th>
                              <th>Model Prediction</th>
                              <th>Status</th>
                              <th>Attack Probability</th>
                              <th>Normal Probability</th>
                            </tr>
                          </thead>
                          <tbody>
                            {mlTestResult.sample_preview.slice(0, 30).map((s) => (
                              <tr key={s.index}>
                                <td>
                                  <span className="mono-val" style={{ color: 'var(--text-muted)' }}>
                                    #{s.index + 1}
                                  </span>
                                </td>
                                <td>
                                  <span
                                    className={
                                      s.actual === 1 ? 'badge badge-severity-high' : 'badge badge-status-resolved'
                                    }
                                  >
                                    {s.actual_label}
                                  </span>
                                </td>
                                <td>
                                  <span
                                    className={
                                      s.predicted === 1 ? 'badge badge-severity-high' : 'badge badge-status-resolved'
                                    }
                                  >
                                    {s.predicted_label}
                                  </span>
                                </td>
                                <td>
                                  {s.is_correct ? (
                                    <span style={{ color: '#34d399', fontWeight: 600 }}>&#10003; Correct</span>
                                  ) : (
                                    <span style={{ color: '#f87171', fontWeight: 600 }}>&#10007; Misclassified</span>
                                  )}
                                </td>
                                <td>
                                  <span className="mono-val">
                                    {s.attack_probability !== null ? formatProbability(s.attack_probability) : '--'}
                                  </span>
                                </td>
                                <td>
                                  <span className="mono-val">
                                    {s.normal_probability !== null ? formatProbability(s.normal_probability) : '--'}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  ) : null}

                  {/* Tab 3: Evaluation Runs History */}
                  {mlTestingTab === 'history' ? (
                    <section className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                      <div
                        className="panel-header"
                        style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)' }}
                      >
                        <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                          Past ML Test Runs History
                        </h2>
                      </div>
                      <div className="table-wrap ml-runs-table-scroll" style={{ margin: 0, border: 'none', borderRadius: 0 }}>
                        <table>
                          <thead>
                            <tr>
                              <th>Run ID</th>
                              <th>Dataset</th>
                              <th>Timestamp</th>
                              <th>Samples</th>
                              <th>Accuracy</th>
                              <th>Precision</th>
                              <th>Recall</th>
                              <th>F1-Score</th>
                              <th>Action</th>
                            </tr>
                          </thead>
                          <tbody>
                            {mlTestRuns.map((r) => (
                              <tr key={r.id}>
                                <td>
                                  <span className="mono-val">#{r.id}</span>
                                </td>
                                <td>
                                  <strong>{r.dataset_name}</strong>
                                </td>
                                <td>{formatDateTime(r.evaluated_at)}</td>
                                <td>{r.total_samples}</td>
                                <td>
                                  <strong style={{ color: 'var(--accent-text)' }}>
                                    {r.accuracy !== undefined && r.accuracy !== null ? `${r.accuracy}%` : '--'}
                                  </strong>
                                </td>
                                <td>
                                  {r.precision !== undefined && r.precision !== null ? `${r.precision}%` : '--'}
                                </td>
                                <td>
                                  {r.recall !== undefined && r.recall !== null ? `${r.recall}%` : '--'}
                                </td>
                                <td>
                                  {r.f1_score !== undefined && r.f1_score !== null ? `${r.f1_score}%` : '--'}
                                </td>
                                <td>
                                  <button
                                    className="scan-button"
                                    onClick={() => handleSelectPastTestRun(r.id)}
                                    style={{ padding: '4px 10px', fontSize: '12px' }}
                                    type="button"
                                  >
                                    View Report
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  ) : null}
                </>
              ) : (
                <>
                  <div className="empty-state" style={{ padding: '36px 20px' }}>
                    <p style={{ fontWeight: 600, color: 'var(--text-strong)' }}>
                      No dataset evaluation performed yet.
                    </p>
                    <p className="muted-text">
                      Select a test CSV dataset above and click &ldquo;Run Model Evaluation&rdquo; to benchmark the frozen Random Forest model.
                    </p>
                  </div>

                  {mlTestRuns.length > 0 ? (
                    <section className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                      <div
                        className="panel-header"
                        style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)' }}
                      >
                        <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                          Past ML Test Runs History
                        </h2>
                      </div>
                      <div className="table-wrap ml-runs-table-scroll" style={{ margin: 0, border: 'none', borderRadius: 0 }}>
                        <table>
                          <thead>
                            <tr>
                              <th>Run ID</th>
                              <th>Dataset</th>
                              <th>Timestamp</th>
                              <th>Samples</th>
                              <th>Accuracy</th>
                              <th>Precision</th>
                              <th>Recall</th>
                              <th>F1-Score</th>
                              <th>Action</th>
                            </tr>
                          </thead>
                          <tbody>
                            {mlTestRuns.map((r) => (
                              <tr key={r.id}>
                                <td>
                                  <span className="mono-val">#{r.id}</span>
                                </td>
                                <td>
                                  <strong>{r.dataset_name}</strong>
                                </td>
                                <td>{formatDateTime(r.evaluated_at)}</td>
                                <td>{r.total_samples}</td>
                                <td>
                                  <strong style={{ color: 'var(--accent-text)' }}>
                                    {r.accuracy !== undefined && r.accuracy !== null ? `${r.accuracy}%` : '--'}
                                  </strong>
                                </td>
                                <td>
                                  {r.precision !== undefined && r.precision !== null ? `${r.precision}%` : '--'}
                                </td>
                                <td>
                                  {r.recall !== undefined && r.recall !== null ? `${r.recall}%` : '--'}
                                </td>
                                <td>
                                  {r.f1_score !== undefined && r.f1_score !== null ? `${r.f1_score}%` : '--'}
                                </td>
                                <td>
                                  <button
                                    className="scan-button"
                                    onClick={() => handleSelectPastTestRun(r.id)}
                                    style={{ padding: '4px 10px', fontSize: '12px' }}
                                    type="button"
                                  >
                                    View Report
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  ) : null}
                </>
              )}
            </div>
          ) : null}

          {/* Tab 3: Feature Schema & Model Spec */}
          {mlEngineTab === 'schema' ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <section className="panel model-spec-panel" style={{ padding: '16px 20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '8px', marginBottom: '12px' }}>
                  <div>
                    <h2 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--text-strong)' }}>
                      AWID3 Random Forest Model Architecture &amp; Vector Specifications
                    </h2>
                    <p style={{ margin: '3px 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>
                      Authoritative 31-feature schema utilized during live streaming inference and offline model evaluation.
                    </p>
                  </div>

                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <span className="scan-meta-pill">
                      Model: <strong>{mlSchemaInfo?.model_name || 'random_forest_awid3_v3_expanded.joblib'}</strong>
                    </span>
                    <span className="scan-meta-pill">
                      Schema: <strong>{mlSchemaInfo?.feature_count ?? 31} Canonical Features</strong>
                    </span>
                    <span className="scan-meta-pill">
                      Target: <strong>{mlSchemaInfo?.classification_type || 'Binary (0=Normal, 1=Attack)'}</strong>
                    </span>
                    <span className="scan-meta-pill">
                      Order Strictness: <strong>Strict (Positional 1-31)</strong>
                    </span>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '12px', marginTop: '12px' }}>
                  <div className="spec-card">
                    <span className="spec-label">Classifier Class</span>
                    <strong style={{ fontSize: '13px' }}>sklearn RandomForest</strong>
                  </div>
                  <div className="spec-card">
                    <span className="spec-label">Ensemble Estimators</span>
                    <strong style={{ fontSize: '13px' }}>200 Decision Trees</strong>
                  </div>
                  <div className="spec-card">
                    <span className="spec-label">Temporal Window Size</span>
                    <strong style={{ fontSize: '13px' }}>5.0 Seconds</strong>
                  </div>
                  <div className="spec-card">
                    <span className="spec-label">Burst Granularity</span>
                    <strong style={{ fontSize: '13px' }}>1.0s Sub-Windows</strong>
                  </div>
                </div>
              </section>

              {/* Canonical 31-Feature Table */}
              <section className="panel" style={{ padding: '0', overflow: 'hidden' }}>
                <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)' }}>
                  <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                    Canonical 31-Feature AWID3 Vector Definition
                  </h3>
                  <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>
                    Strictly ordered IEEE 802.11 feature vector utilized by the Random Forest model during 5-second window inference.
                  </p>
                </div>

                <div className="table-wrap schema-table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th style={{ width: '60px' }}>#</th>
                        <th>Feature Name</th>
                        <th>Scope / Category</th>
                        <th>Security &amp; Intrusion Rationale</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[
                        { id: 1, name: 'total_packets', scope: '5s Window Base', desc: 'Total frames observed across the entire 5-second observation window.' },
                        { id: 2, name: 'packets_per_second', scope: '5s Window Base', desc: 'Overall frame arrival velocity across the channel.' },
                        { id: 3, name: 'beacon_count', scope: '5s Window Base', desc: 'Volume of AP beacon advertisements; detects beacon flooding or rogue APs.' },
                        { id: 4, name: 'probe_request_count', scope: '5s Window Base', desc: 'Client discovery requests; detects active probe mapping.' },
                        { id: 5, name: 'probe_response_count', scope: '5s Window Base', desc: 'AP responses to probes; detects rogue AP response poisoning.' },
                        { id: 6, name: 'authentication_count', scope: '5s Window Base', desc: '802.11 Open System / Shared Key authentication exchanges.' },
                        { id: 7, name: 'deauth_count', scope: '5s Window Base', desc: 'Deauthentication frames; key indicator of Wi-Fi DoS and handshake forcing.' },
                        { id: 8, name: 'disassociation_count', scope: '5s Window Base', desc: 'Disassociation frames indicating forced client severance.' },
                        { id: 9, name: 'reassociation_count', scope: '5s Window Base', desc: 'Reassociation attempts; flags fast-roaming hijackings.' },
                        { id: 10, name: 'data_count', scope: '5s Window Base', desc: 'Payload-bearing data frames (QoS and non-QoS).' },
                        { id: 11, name: 'control_count', scope: '5s Window Base', desc: 'Control frames (ACK, RTS, CTS); flags channel clearance jamming.' },
                        { id: 12, name: 'management_count', scope: '5s Window Base', desc: 'Aggregate Type 0 management frames across the window.' },
                        { id: 13, name: 'unique_source_macs', scope: '5s Window Base', desc: 'Count of unique transmitter addresses; detects MAC spoofing floods.' },
                        { id: 14, name: 'unique_destination_macs', scope: '5s Window Base', desc: 'Count of unique target addresses across the medium.' },
                        { id: 15, name: 'unique_bssids', scope: '5s Window Base', desc: 'Count of distinct basic service set identifiers active.' },
                        { id: 16, name: 'retry_count', scope: '5s Window Base', desc: 'Frames retransmitted due to missing ACK; indicates channel interference or jamming.' },
                        { id: 17, name: 'retry_ratio', scope: '5s Window Base', desc: 'Proportion of retried frames to total frames.' },
                        { id: 18, name: 'deauth_per_second', scope: '5s Window Base', desc: 'Sustained deauthentication frame rate.' },
                        { id: 19, name: 'disassociation_per_second', scope: '5s Window Base', desc: 'Sustained disassociation frame rate.' },
                        { id: 20, name: 'reassociation_per_second', scope: '5s Window Base', desc: 'Sustained reassociation frame rate.' },
                        { id: 21, name: 'beacon_per_second', scope: '5s Window Base', desc: 'AP beacon transmission frequency.' },
                        { id: 22, name: 'management_ratio', scope: '5s Window Base', desc: 'Proportion of management traffic relative to total frames.' },
                        { id: 23, name: 'control_ratio', scope: '5s Window Base', desc: 'Proportion of control traffic relative to total frames.' },
                        { id: 24, name: 'data_ratio', scope: '5s Window Base', desc: 'Proportion of data traffic relative to total frames.' },
                        { id: 25, name: 'clients_per_bssid', scope: '5s Window Base', desc: 'Client-to-AP ratio; flags fake client enumeration.' },
                        { id: 26, name: 'max_packets_1s', scope: '1s Sub-Window Burst', desc: 'Peak packet count in any 1-second interval; catches micro-burst floods.' },
                        { id: 27, name: 'max_deauth_1s', scope: '1s Sub-Window Burst', desc: 'Peak deauthentication frames in any 1-second interval.' },
                        { id: 28, name: 'max_disassoc_1s', scope: '1s Sub-Window Burst', desc: 'Peak disassociation frames in any 1-second interval.' },
                        { id: 29, name: 'packet_burst_ratio', scope: '1s Sub-Window Burst', desc: 'Ratio of 1-second peak packets to total window packets.' },
                        { id: 30, name: 'deauth_burst_ratio', scope: '1s Sub-Window Burst', desc: 'Ratio of 1-second peak deauth frames to window deauth frames.' },
                        { id: 31, name: 'disassoc_burst_ratio', scope: '1s Sub-Window Burst', desc: 'Ratio of 1-second peak disassoc frames to window disassoc frames.' },
                      ].map((feat) => (
                        <tr key={feat.id}>
                          <td>
                            <span className="mono-val" style={{ color: 'var(--text-muted)' }}>
                              #{feat.id}
                            </span>
                          </td>
                          <td>
                            <strong className="mono-val" style={{ color: '#38bdf8' }}>
                              {feat.name}
                            </strong>
                          </td>
                          <td>
                            <span
                              className={`badge ${
                                feat.scope.includes('Burst') ? 'badge-severity-medium' : 'badge-default'
                              }`}
                            >
                              {feat.scope}
                            </span>
                          </td>
                          <td style={{ fontSize: '12.5px', color: 'var(--text)' }}>
                            {feat.desc}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>
          ) : null}
        </section>
      ) : activeView === 'PCAP Analysis' ? (
            <section className="pcap-analysis-view" aria-label="PCAP Analysis">
              {pcapError ? <p className="error-banner">{pcapError}</p> : null}

              {/* Compact PCAP Ingest Bar */}
              <section className="panel pcap-upload-panel" style={{ padding: '16px 20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '8px', marginBottom: '12px' }}>
                  <div>
                    <h2 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--text-strong)' }}>
                      PCAP / PCAPNG Offline Packet Analysis
                    </h2>
                    <p style={{ margin: '3px 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>
                      Extract canonical 31 AWID3 features across 5-second windows and detect intrusion patterns.
                    </p>
                  </div>
                  {pcapResult?.id ? (
                    <button
                      className="scan-button"
                      onClick={() => window.open(`${API_BASE_URL}/pcap/download/${pcapResult.id}/csv`)}
                      type="button"
                    >
                      Export Windows to CSV
                    </button>
                  ) : null}
                </div>

                <form className="pcap-upload-form" onSubmit={handlePcapAnalyze}>
                  <div className="pcap-input-row" style={{ alignItems: 'center' }}>
                    <label className="file-upload-compact">
                      <span style={{ fontWeight: 600, color: 'var(--text-strong)' }}>Upload PCAP:</span>
                      <input
                        accept=".pcap,.pcapng,.cap"
                        onChange={(e) => {
                          const file = e.target.files?.[0]
                          setSelectedPcapFile(file || null)
                        }}
                        type="file"
                      />
                      {selectedPcapFile ? (
                        <span className="selected-filename">
                          {selectedPcapFile.name} ({formatFileSize(selectedPcapFile.size)})
                        </span>
                      ) : (
                        <span className="file-placeholder">Choose .pcap or .pcapng file...</span>
                      )}
                    </label>

                    <div className="sample-select-box" style={{ gap: '4px' }}>
                      <select
                        disabled={!!selectedPcapFile}
                        id="pcap-sample-select"
                        onChange={(e) => {
                          setSelectedPcapSample(e.target.value)
                          setSelectedPcapFile(null)
                        }}
                        value={selectedPcapFile ? '' : selectedPcapSample}
                      >
                        <option value="">-- Or choose bundled sample --</option>
                        {pcapSamples.map((s) => (
                          <option key={s.filename} value={s.filename}>
                            {s.filename} ({formatFileSize(s.file_size_bytes)})
                          </option>
                        ))}
                      </select>
                    </div>

                    <button
                      className="scan-button primary"
                      disabled={pcapAnalyzing || (!selectedPcapFile && !selectedPcapSample)}
                      style={{ whiteSpace: 'nowrap', height: '38px' }}
                      type="submit"
                    >
                      {pcapAnalyzing ? 'Analyzing 31 Features...' : 'Run PCAP Analysis'}
                    </button>
                  </div>
                </form>
              </section>

              {pcapResult ? (
                <>
                  {/* KPI Summary Strip */}
                  <div className="metric-grid">
                    <article className="metric-card">
                      <p>Total Packets</p>
                      <strong>{formatValue(pcapResult.total_packets ?? pcapResult.summary?.total_packets)}</strong>
                    </article>
                    <article className="metric-card">
                      <p>Analyzed Windows (5s)</p>
                      <strong>{formatValue(pcapResult.total_windows ?? pcapResult.summary?.analyzed_windows)}</strong>
                    </article>
                    <article
                      className="metric-card"
                      style={{
                        borderTop:
                          (pcapResult.attack_windows ?? pcapResult.summary?.attack_windows) > 0
                            ? '3px solid #ef4444'
                            : '3px solid #22c55e',
                      }}
                    >
                      <p>Attack Windows</p>
                      <strong>
                        {formatValue(pcapResult.attack_windows ?? pcapResult.summary?.attack_windows ?? 0)}
                        <span className="metric-sub" style={{ fontSize: '13px', color: 'var(--text-muted)', fontWeight: 400 }}>
                          {' '}
                          (
                          {formatValue(
                            pcapResult.attack_percentage ?? pcapResult.summary?.attack_percentage ?? 0,
                          )}
                          %)
                        </span>
                      </strong>
                    </article>
                    <article className="metric-card">
                      <p>Dominant Threat</p>
                      <strong style={{ fontSize: '18px' }}>
                        {formatValue(
                          pcapResult.dominant_category ?? pcapResult.summary?.dominant_category ?? 'None',
                        )}
                      </strong>
                    </article>
                    <article className="metric-card">
                      <p>Canonical Schema</p>
                      <strong style={{ color: 'var(--accent-text)', fontSize: '18px' }}>
                        31 / 31 Features
                      </strong>
                    </article>
                  </div>

                  {/* PCAP Tab Bar */}
                  <div className="soc-tab-bar">
                    <button
                      className={`soc-tab-btn ${pcapTab === 'timeline' ? 'active' : ''}`}
                      onClick={() => setPcapTab('timeline')}
                      type="button"
                    >
                      Classification Timeline ({pcapResult.windows?.length ?? 0})
                    </button>
                    <button
                      className={`soc-tab-btn ${pcapTab === 'threats' ? 'active' : ''}`}
                      onClick={() => setPcapTab('threats')}
                      type="button"
                    >
                      Threat Categories Breakdown
                    </button>
                    <button
                      className={`soc-tab-btn ${pcapTab === 'history' ? 'active' : ''}`}
                      onClick={() => setPcapTab('history')}
                      type="button"
                    >
                      Past Analyses History ({pcapHistory.length})
                    </button>
                  </div>

                  {/* Tab 1: Timeline */}
                  {pcapTab === 'timeline' ? (
                    <section className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                      <div
                        className="panel-header"
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          padding: '12px 18px',
                          borderBottom: '1px solid var(--border)',
                        }}
                      >
                        <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                          Time-Window Classification Timeline
                        </h2>
                        <div className="filter-button-group">
                          <button
                            className={pcapFilter === 'all' ? 'filter-btn active' : 'filter-btn'}
                            onClick={() => setPcapFilter('all')}
                            type="button"
                          >
                            All Windows ({pcapResult.windows?.length ?? 0})
                          </button>
                          <button
                            className={pcapFilter === 'attacks' ? 'filter-btn active' : 'filter-btn'}
                            onClick={() => setPcapFilter('attacks')}
                            type="button"
                          >
                            Attacks Only ({pcapResult.attack_windows ?? pcapResult.summary?.attack_windows ?? 0})
                          </button>
                        </div>
                      </div>

                      <div className="table-wrap pcap-table-scroll" style={{ margin: 0, border: 'none', borderRadius: 0 }}>
                        <table>
                          <thead>
                            <tr>
                              <th>Window</th>
                              <th>Time Interval</th>
                              <th>Packets</th>
                              <th>Verdict</th>
                              <th>Threat Category</th>
                              <th>Confidence</th>
                              <th>Deauth / Disas</th>
                              <th>1s Burst Ratio</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(pcapResult.windows ?? [])
                              .filter((w) => pcapFilter === 'all' || w.prediction === 1)
                              .map((w) => (
                                <tr key={w.window_index}>
                                  <td>
                                    <span className="mono-val" style={{ color: 'var(--text-muted)' }}>
                                      #{w.window_index + 1}
                                    </span>
                                  </td>
                                  <td>
                                    <span className="mono-val">
                                      {w.window_start}s &ndash; {w.window_end}s
                                    </span>
                                  </td>
                                  <td>{w.total_packets ?? w.packet_count}</td>
                                  <td>
                                    <span
                                      className={
                                        w.prediction === 1 ? 'badge badge-severity-high' : 'badge badge-status-resolved'
                                      }
                                    >
                                      {w.label ?? (w.prediction === 1 ? 'Attack' : 'Normal')}
                                    </span>
                                  </td>
                                  <td>
                                    <span className={getCategoryBadgeClass(w.category ?? w.attack_category)}>
                                      {w.category ?? w.attack_category ?? 'Normal'}
                                    </span>
                                  </td>
                                  <td>
                                    <span className="mono-val">
                                      {w.prediction === 1
                                        ? formatProbability(w.attack_probability)
                                        : formatProbability(w.normal_probability)}
                                    </span>
                                  </td>
                                  <td>
                                    <span className="mono-val">
                                      {w.deauth_count ?? 0} / {w.disassoc_count ?? 0}
                                    </span>
                                  </td>
                                  <td>
                                    <span className="mono-val">
                                      {w.packet_burst_ratio !== undefined
                                        ? Number(w.packet_burst_ratio).toFixed(2)
                                        : '--'}
                                    </span>
                                  </td>
                                </tr>
                              ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  ) : null}

                  {/* Tab 2: Threat Categories */}
                  {pcapTab === 'threats' ? (
                    <section className="panel" style={{ padding: '16px 20px' }}>
                      <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                        Observed Attack Categories
                      </h3>
                      {pcapResult.attack_categories && Object.keys(pcapResult.attack_categories).length > 0 ? (
                        <div className="attack-summary-grid">
                          {Object.entries(pcapResult.attack_categories).map(([cat, count]) => (
                            <div className="attack-summary-item" key={cat}>
                              <span className={getCategoryBadgeClass(cat)}>{cat}</span>
                              <span className="attack-count">
                                {count} {count === 1 ? 'window' : 'windows'}
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="empty-state" style={{ padding: '24px' }}>
                          <p style={{ margin: 0, color: '#34d399', fontWeight: 600 }}>
                            100% Clean Frame Capture
                          </p>
                          <p className="muted-text" style={{ margin: '4px 0 0' }}>
                            Zero malicious patterns detected. All packets conformed to benign IEEE 802.11 standards.
                          </p>
                        </div>
                      )}
                    </section>
                  ) : null}

                  {/* Tab 3: History */}
                  {pcapTab === 'history' ? (
                    <section className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                      <div className="panel-header" style={{ padding: '12px 18px', borderBottom: '1px solid var(--border)' }}>
                        <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                          Past PCAP Analyses
                        </h2>
                      </div>
                      <div className="table-wrap pcap-table-scroll" style={{ margin: 0, border: 'none', borderRadius: 0 }}>
                        <table>
                          <thead>
                            <tr>
                              <th>ID</th>
                              <th>Filename</th>
                              <th>Analyzed Time</th>
                              <th>Packets</th>
                              <th>Windows</th>
                              <th>Attacks</th>
                              <th>Threats</th>
                              <th>Action</th>
                            </tr>
                          </thead>
                          <tbody>
                            {pcapHistory.map((hist) => (
                              <tr key={hist.id}>
                                <td>
                                  <span className="mono-val">#{hist.id}</span>
                                </td>
                                <td>
                                  <strong>{hist.filename}</strong>
                                </td>
                                <td>{formatDateTime(hist.created_at)}</td>
                                <td>{hist.total_packets}</td>
                                <td>{hist.analyzed_windows}</td>
                                <td>
                                  <span
                                    className={
                                      hist.attack_windows > 0
                                        ? 'badge badge-severity-high'
                                        : 'badge badge-status-resolved'
                                    }
                                  >
                                    {hist.attack_windows}
                                  </span>
                                </td>
                                <td>
                                  {Object.keys(hist.attack_categories || {}).length > 0
                                    ? Object.keys(hist.attack_categories).join(', ')
                                    : 'Normal'}
                                </td>
                                <td>
                                  <button
                                    className="scan-button"
                                    onClick={() => handleSelectHistoryPcap(hist.id)}
                                    style={{ padding: '4px 10px', fontSize: '12px' }}
                                    type="button"
                                  >
                                    View Results
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  ) : null}
                </>
              ) : (
                <>
                  <div className="empty-state" style={{ padding: '36px 20px' }}>
                    <p style={{ fontWeight: 600, color: 'var(--text-strong)' }}>
                      No PCAP file analyzed yet.
                    </p>
                    <p className="muted-text">
                      Select a capture file above or choose a bundled sample to perform offline ML intrusion inspection.
                    </p>
                  </div>

                  {pcapHistory.length > 0 ? (
                    <section className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                      <div
                        className="panel-header"
                        style={{ padding: '12px 18px', borderBottom: '1px solid var(--border)' }}
                      >
                        <h2 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-strong)' }}>
                          Past PCAP Analyses History
                        </h2>
                      </div>
                      <div className="table-wrap pcap-table-scroll" style={{ margin: 0, border: 'none', borderRadius: 0 }}>
                        <table>
                          <thead>
                            <tr>
                              <th>ID</th>
                              <th>Filename</th>
                              <th>Analyzed Time</th>
                              <th>Packets</th>
                              <th>Windows</th>
                              <th>Attacks</th>
                              <th>Threats</th>
                              <th>Action</th>
                            </tr>
                          </thead>
                          <tbody>
                            {pcapHistory.map((hist) => (
                              <tr key={hist.id}>
                                <td>
                                  <span className="mono-val">#{hist.id}</span>
                                </td>
                                <td>
                                  <strong>{hist.filename}</strong>
                                </td>
                                <td>{formatDateTime(hist.created_at)}</td>
                                <td>{hist.total_packets}</td>
                                <td>{hist.analyzed_windows}</td>
                                <td>
                                  <span
                                    className={
                                      hist.attack_windows > 0
                                        ? 'badge badge-severity-high'
                                        : 'badge badge-status-resolved'
                                    }
                                  >
                                    {hist.attack_windows}
                                  </span>
                                </td>
                                <td>
                                  {Object.keys(hist.attack_categories || {}).length > 0
                                    ? Object.keys(hist.attack_categories).join(', ')
                                    : 'Normal'}
                                </td>
                                <td>
                                  <button
                                    className="scan-button"
                                    onClick={() => handleSelectHistoryPcap(hist.id)}
                                    style={{ padding: '4px 10px', fontSize: '12px' }}
                                    type="button"
                                  >
                                    View Results
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  ) : null}
                </>
              )}
            </section>
          ) : activeView === 'Network Recommendations' ? (
            <section className="recommendations-view" aria-label="Network Recommendations">
              {recommendationsError ? <p className="error-banner">{recommendationsError}</p> : null}

              <div className="reports-header-panel panel">
                <div className="panel-header">
                  <div>
                    <div className="rec-live-badge-row">
                      <span className="live-pulse-dot" />
                      <span className="rec-live-text">Real Wi-Fi Ingestion Active</span>
                    </div>
                    <h2>ML-Based Wi-Fi Network Recommendations</h2>
                    <p className="panel-subtitle">
                      Automated scan-level QoS &amp; security evaluation powered by Random Forest classifier trained on 12 IEEE 802.11 metrics.
                    </p>
                  </div>
                  <div className="report-controls">
                    <button
                      className="scan-button"
                      disabled={recommendationsLoading}
                      onClick={() => loadRecommendationsData()}
                      type="button"
                    >
                      {recommendationsLoading ? 'Analyzing Networks...' : 'Refresh Recommendations'}
                    </button>
                    <button
                      className="scan-button primary"
                      onClick={() => setActiveView('WiFi Scan')}
                      type="button"
                    >
                      Run Wi-Fi Scan
                    </button>
                    <button
                      className={`scan-button advisor-toggle-btn ${advisorOpen ? 'active' : ''}`}
                      onClick={() => setAdvisorOpen(!advisorOpen)}
                      type="button"
                      title="Toggle NetShield AI Wi-Fi Advisor"
                    >
                      🤖 AI Advisor
                    </button>
                  </div>
                </div>
              </div>

              {/* Scan-to-recommendation pipeline banner */}
              <div className="pipeline-banner">
                <span className="pipeline-step"><span className="pipe-num">1</span> Wi-Fi Scan Ingestion</span>
                <span className="pipeline-arrow">&#10140;</span>
                <span className="pipeline-step"><span className="pipe-num">2</span> 12-Feature Extraction</span>
                <span className="pipeline-arrow">&#10140;</span>
                <span className="pipeline-step"><span className="pipe-num">3</span> Random Forest ML Inference</span>
                <span className="pipeline-arrow">&#10140;</span>
                <span className="pipeline-step"><span className="pipe-num">4</span> 4-Tier Classification</span>
                <span className="pipeline-arrow">&#10140;</span>
                <span className="pipeline-step"><span className="pipe-num">5</span> Ranked Recommendation</span>
              </div>

              {/* Best Recommended Network Hero Card */}
              {bestNetwork ? (
                <section className="best-rec-card panel">
                  <div className="best-rec-header-row">
                    <div className="best-rec-badge-group">
                      <span className="best-choice-pill">&#9733; #1 TOP RECOMMENDED NETWORK</span>
                      <span className={getRecommendationBadgeClass(bestNetwork.classification)}>
                        {bestNetwork.classification}
                      </span>
                    </div>
                    <div className="best-rec-score-group">
                      <div className="score-pill">
                        <span className="score-pill-label">ML Score:</span>
                        <strong className="score-pill-val">{bestNetwork.score.toFixed(1)}</strong>
                        <span className="score-pill-max">/ 100</span>
                      </div>
                      <div className="conf-pill">
                        <span className="conf-pill-label">Confidence:</span>
                        <strong>{formatConfidence(bestNetwork.confidence_pct)}</strong>
                      </div>
                    </div>
                  </div>

                  <div className="best-rec-main">
                    <div className="best-rec-info">
                      <div className="best-rec-identity">
                        <h3 className="best-rec-ssid">{bestNetwork.ssid}</h3>
                        <div className="best-rec-bssid-row">
                          <span className="best-rec-bssid">{bestNetwork.bssid || 'BSSID Unknown'}</span>
                          {bestNetwork.vendor && bestNetwork.vendor !== 'Unknown Vendor' && (
                            <span className="rec-vendor-tag">{bestNetwork.vendor}</span>
                          )}
                        </div>
                      </div>

                      {bestNetwork.recommendation_reason && (
                        <p className="best-rec-summary-text">
                          {bestNetwork.recommendation_reason}
                        </p>
                      )}

                      <div className="best-rec-metrics-grid">
                        <div className="mini-stat">
                          <span className="stat-label">Signal Level</span>
                          <span className="stat-value">{bestNetwork.signal}</span>
                        </div>
                        <div className="mini-stat">
                          <span className="stat-label">Band</span>
                          <span className="stat-value">{bestNetwork.band}</span>
                        </div>
                        <div className="mini-stat">
                          <span className="stat-label">Channel</span>
                          <span className="stat-value">Channel {bestNetwork.channel || '?'}</span>
                        </div>
                        <div className="mini-stat">
                          <span className="stat-label">Encryption</span>
                          <span className="stat-value">{bestNetwork.security}</span>
                        </div>
                        <div className="mini-stat">
                          <span className="stat-label">Contention</span>
                          <span className="stat-value">
                            {bestNetwork.features?.channel_congestion_count !== undefined
                              ? `${bestNetwork.features.channel_congestion_count} APs on channel`
                              : 'Low Congestion'}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="best-rec-actions">
                      <button
                        type="button"
                        className="connect-btn-large"
                        onClick={() => handleOpenConnectModal(bestNetwork)}
                      >
                        &#9889; Connect to Network
                      </button>
                    </div>
                  </div>

                  {/* Explainability Factors - Individually Wrapped Items */}
                  <div className="best-rec-factors">
                    {bestNetwork.positive_factors && bestNetwork.positive_factors.length > 0 ? (
                      <div className="rec-factor-group">
                        <span className="factor-heading positive">Strengths &amp; Selection Factors:</span>
                        <div className="rec-factor-chips">
                          {bestNetwork.positive_factors.map((r, i) => (
                            <span key={i} className="rec-factor-chip positive">
                              <span className="factor-icon">&#10003;</span>
                              <span>{r}</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    {bestNetwork.negative_factors && bestNetwork.negative_factors.length > 0 ? (
                      <div className="rec-factor-group" style={{ marginTop: '10px' }}>
                        <span className="factor-heading negative">Risks &amp; Caveats:</span>
                        <div className="rec-factor-chips">
                          {bestNetwork.negative_factors.map((r, i) => (
                            <span key={i} className="rec-factor-chip negative">
                              <span className="factor-icon">&#9888;</span>
                              <span>{r}</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : null}
                  </div>
                </section>
              ) : !recommendationsLoading ? (
                <div className="empty-state panel" style={{ marginBottom: '20px', padding: '36px 24px', textAlign: 'center' }}>
                  <p style={{ fontWeight: 600, fontSize: '16px', color: '#f8fafc', marginBottom: '8px' }}>
                    No Wi-Fi networks scanned yet.
                  </p>
                  <p className="muted-text" style={{ marginBottom: '16px' }}>
                    Run Wi-Fi Scan to discover nearby networks and then refresh recommendations.
                  </p>
                  <button
                    type="button"
                    className="scan-button primary"
                    onClick={() => setActiveView('WiFi Scan')}
                  >
                    Go to Wi-Fi Scan
                  </button>
                </div>
              ) : null}

              {/* Expandable Technical Sections (Collapsed by default) */}
              <div className="rec-expandables-container">
                {/* 1. Detailed Ranking Explanation */}
                <div className="rec-accordion-item panel">
                  <button
                    type="button"
                    className={`rec-accordion-header ${showRankingExplanation ? 'expanded' : ''}`}
                    onClick={() => setShowRankingExplanation(!showRankingExplanation)}
                    aria-expanded={showRankingExplanation}
                  >
                    <div className="accordion-title-wrap">
                      <span className="accordion-icon">ℹ️</span>
                      <div>
                        <h4>Detailed ML Ranking Explanation</h4>
                        <p>How the 12-feature Random Forest model scores and classifies IEEE 802.11 QoS</p>
                      </div>
                    </div>
                    <span className="accordion-chevron">{showRankingExplanation ? '▲' : '▼'}</span>
                  </button>
                  {showRankingExplanation && (
                    <div className="rec-accordion-content">
                      <div className="explanation-grid">
                        <div className="explanation-block">
                          <h5>1. Feature Extraction &amp; Representation</h5>
                          <p>
                            Raw IEEE 802.11 frame captures (Beacon &amp; Probe Responses) are ingested to extract 12 canonical QoS &amp; security features: RSSI signal strength, SNR proxy, channel number, 5 GHz band flag, security protocol rank (0=Open, 1=WEP, 2=WPA, 3=WPA2, 4=WPA3), channel congestion count, and vendor identification.
                          </p>
                        </div>
                        <div className="explanation-block">
                          <h5>2. Random Forest Classification (100 Trees)</h5>
                          <p>
                            The model runs an ensemble of 100 decision trees to produce a posterior probability distribution over four discrete quality classes: <code>POOR</code>, <code>FAIR</code>, <code>GOOD</code>, and <code>EXCELLENT</code>.
                          </p>
                        </div>
                        <div className="explanation-block">
                          <h5>3. Probability-Weighted 0–100 Score Formula</h5>
                          <p>
                            To break ties cleanly and create a continuous score, NetShield calculates the probability-weighted expectation:
                          </p>
                          <div className="formula-box">
                            Score = (P[POOR] × 18) + (P[FAIR] × 50) + (P[GOOD] × 78) + (P[EXCELLENT] × 96) + SNR_Adjustment - Congestion_Penalty
                          </div>
                        </div>
                        <div className="explanation-block">
                          <h5>4. Hard Security Guardrails</h5>
                          <p>
                            Heuristic security guardrails enforce strict quality ceilings regardless of raw signal strength:
                          </p>
                          <ul className="explanation-list">
                            <li><strong>Unencrypted Open Networks</strong>: Hard-capped at a maximum score of <strong>58.0/100</strong>.</li>
                            <li><strong>Deprecated WEP Encryption</strong>: Hard-capped at a maximum score of <strong>45.0/100</strong> due to known cryptanalytic breaks.</li>
                            <li><strong>WPA3 SAE &amp; 5 GHz APs</strong>: Receive natural classification advantages due to forward secrecy and wider spectrum bandwidth.</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* 2. Runner-Up Network Comparison */}
                <div className="rec-accordion-item panel">
                  <button
                    type="button"
                    className={`rec-accordion-header ${showRunnerUpComparison ? 'expanded' : ''}`}
                    onClick={() => setShowRunnerUpComparison(!showRunnerUpComparison)}
                    aria-expanded={showRunnerUpComparison}
                  >
                    <div className="accordion-title-wrap">
                      <span className="accordion-icon">⚖️</span>
                      <div>
                        <h4>Runner-Up Network Comparison</h4>
                        <p>Direct side-by-side comparative analysis of the top-ranked candidates</p>
                      </div>
                    </div>
                    <span className="accordion-chevron">{showRunnerUpComparison ? '▲' : '▼'}</span>
                  </button>
                  {showRunnerUpComparison && (
                    <div className="rec-accordion-content">
                      {recList.length < 2 ? (
                        <p className="muted-text">
                          Only one network was captured in the scan snapshot. Run a Wi-Fi scan in an area with multiple access points to see comparative runner-up telemetry.
                        </p>
                      ) : (
                        <div className="table-wrap">
                          <table className="comparison-table">
                            <thead>
                              <tr>
                                <th>Comparison Dimension</th>
                                <th>★ #1 Winner: {bestNetwork?.ssid}</th>
                                <th>🥈 #2 Runner-Up: {recList[1]?.ssid}</th>
                                {recList[2] && <th>🥉 #3 Third: {recList[2]?.ssid}</th>}
                              </tr>
                            </thead>
                            <tbody>
                              <tr>
                                <td><strong>ML Recommendation Score</strong></td>
                                <td><span className="score-delta winner">{bestNetwork?.score.toFixed(1)} / 100</span></td>
                                <td>
                                  <span className="score-delta runner">
                                    {recList[1]?.score.toFixed(1)} ({(recList[1]?.score - (bestNetwork?.score || 0)).toFixed(1)})
                                  </span>
                                </td>
                                {recList[2] && (
                                  <td>
                                    <span className="score-delta third">
                                      {recList[2]?.score.toFixed(1)} ({(recList[2]?.score - (bestNetwork?.score || 0)).toFixed(1)})
                                    </span>
                                  </td>
                                )}
                              </tr>
                              <tr>
                                <td><strong>Classification Tier</strong></td>
                                <td><span className={getRecommendationBadgeClass(bestNetwork?.classification)}>{bestNetwork?.classification}</span></td>
                                <td><span className={getRecommendationBadgeClass(recList[1]?.classification)}>{recList[1]?.classification}</span></td>
                                {recList[2] && <td><span className={getRecommendationBadgeClass(recList[2]?.classification)}>{recList[2]?.classification}</span></td>}
                              </tr>
                              <tr>
                                <td><strong>Model Confidence</strong></td>
                                <td>{formatConfidence(bestNetwork?.confidence_pct)}</td>
                                <td>{formatConfidence(recList[1]?.confidence_pct)}</td>
                                {recList[2] && <td>{formatConfidence(recList[2]?.confidence_pct)}</td>}
                              </tr>
                              <tr>
                                <td><strong>Signal Strength</strong></td>
                                <td><strong>{bestNetwork?.signal}</strong></td>
                                <td>{recList[1]?.signal}</td>
                                {recList[2] && <td>{recList[2]?.signal}</td>}
                              </tr>
                              <tr>
                                <td><strong>Band &amp; Channel</strong></td>
                                <td>{bestNetwork?.band} (Ch {bestNetwork?.channel})</td>
                                <td>{recList[1]?.band} (Ch {recList[1]?.channel})</td>
                                {recList[2] && <td>{recList[2]?.band} (Ch {recList[2]?.channel})</td>}
                              </tr>
                              <tr>
                                <td><strong>Security Protocol</strong></td>
                                <td>{bestNetwork?.security}</td>
                                <td>{recList[1]?.security}</td>
                                {recList[2] && <td>{recList[2]?.security}</td>}
                              </tr>
                              <tr>
                                <td><strong>Key Advantage</strong></td>
                                <td className="advantage-highlight">
                                  {bestNetwork?.signal_dbm > (recList[1]?.signal_dbm || -100)
                                    ? `Superior signal (+${bestNetwork?.signal_dbm - (recList[1]?.signal_dbm || 0)} dBm)`
                                    : bestNetwork?.band === '5 GHz' && recList[1]?.band !== '5 GHz'
                                      ? '5 GHz wider channel & lower interference'
                                      : 'Higher overall IEEE 802.11 QoS score'}
                                </td>
                                <td>
                                  {recList[1]?.band !== bestNetwork?.band
                                    ? `Operates on ${recList[1]?.band}`
                                    : `Higher channel contention`}
                                </td>
                                {recList[2] && (
                                  <td>
                                    {recList[2]?.security !== bestNetwork?.security
                                      ? `${recList[2]?.security} encryption`
                                      : `${recList[2]?.signal} signal`}
                                  </td>
                                )}
                              </tr>
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* 3. Model Architecture & Feature Importance Breakdown */}
                <div className="rec-accordion-item panel">
                  <button
                    type="button"
                    className={`rec-accordion-header ${showModelBreakdown ? 'expanded' : ''}`}
                    onClick={() => setShowModelBreakdown(!showModelBreakdown)}
                    aria-expanded={showModelBreakdown}
                  >
                    <div className="accordion-title-wrap">
                      <span className="accordion-icon">📊</span>
                      <div>
                        <h4>ML Model Architecture &amp; 12 Feature Importances</h4>
                        <p>Ensemble specifications, training metadata, and Gini importance predictors</p>
                      </div>
                    </div>
                    <span className="accordion-chevron">{showModelBreakdown ? '▲' : '▼'}</span>
                  </button>
                  {showModelBreakdown && (
                    <div className="rec-accordion-content">
                      <div className="panel-grid">
                        <div>
                          <h5 style={{ fontSize: '13px', marginBottom: '12px', color: '#f8fafc', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                            Model Specification
                          </h5>
                          <dl className="status-list">
                            <div>
                              <dt>Model Class</dt>
                              <dd>{recommendationModelInfo?.model_type ?? 'RandomForestClassifier'}</dd>
                            </div>
                            <div>
                              <dt>Artifact File</dt>
                              <dd>{recommendationModelInfo?.model_file ?? 'wifi_network_recommendation.joblib'}</dd>
                            </div>
                            <div>
                              <dt>Validation Accuracy</dt>
                              <dd style={{ color: '#2dd4bf', fontWeight: 600 }}>
                                {recommendationModelInfo?.metrics?.accuracy !== undefined
                                  ? `${recommendationModelInfo.metrics.accuracy}%`
                                  : recommendationModelInfo?.metrics?.accuracy_pct !== undefined
                                    ? `${recommendationModelInfo.metrics.accuracy_pct}%`
                                    : '88.12%'}
                              </dd>
                            </div>
                            <div>
                              <dt>Macro F1-Score</dt>
                              <dd style={{ color: '#2dd4bf', fontWeight: 600 }}>
                                {recommendationModelInfo?.metrics?.macro_f1 !== undefined
                                  ? `${recommendationModelInfo.metrics.macro_f1}%`
                                  : recommendationModelInfo?.metrics?.macro_f1_pct !== undefined
                                    ? `${recommendationModelInfo.metrics.macro_f1_pct}%`
                                    : '88.07%'}
                              </dd>
                            </div>
                            <div>
                              <dt>Classification Tiers</dt>
                              <dd>EXCELLENT, GOOD, FAIR, POOR</dd>
                            </div>
                            <div>
                              <dt>Training Dataset</dt>
                              <dd>wifi_scan_recommendation_synthetic_train.csv (1,600 samples)</dd>
                            </div>
                            <div>
                              <dt>Pipeline Decoupling</dt>
                              <dd style={{ color: '#94a3b8' }}>Decoupled from the 31-feature packet IDS model</dd>
                            </div>
                          </dl>
                        </div>

                        <div>
                          <h5 style={{ fontSize: '13px', marginBottom: '12px', color: '#f8fafc', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                            Feature Importances (Top IEEE 802.11 Predictors)
                          </h5>
                          <div className="feature-weight-list">
                            {recommendationModelInfo?.feature_importances && Object.keys(recommendationModelInfo.feature_importances).length > 0 ? (
                              Object.entries(recommendationModelInfo.feature_importances)
                                .sort(([, a], [, b]) => (Number(b) || 0) - (Number(a) || 0))
                                .map(([feat, imp]) => {
                                  const impVal = Number(imp) || 0
                                  const pct = impVal > 1 ? impVal.toFixed(1) : (impVal * 100).toFixed(1)
                                  const barWidth = impVal > 1 ? Math.min(100, impVal * 3.5) : Math.min(100, impVal * 100 * 3.5)
                                  return (
                                    <div key={feat} className="feature-weight-item">
                                      <div className="feat-info">
                                        <span className="feat-name">{feat}</span>
                                        <span className="feat-pct">{pct}%</span>
                                      </div>
                                      <div className="feat-bar-bg">
                                        <div className="feat-bar-fill" style={{ width: `${barWidth}%` }} />
                                      </div>
                                    </div>
                                  )
                                })
                            ) : (
                              <p className="muted-text">Feature weights loading...</p>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Metrics Summary Grid */}
              <div className="metric-grid">
                <article className="metric-card">
                  <p>Scanned Networks</p>
                  <strong>{totalScannedRecs}</strong>
                </article>
                <article className="metric-card">
                  <p>Recommended Networks</p>
                  <strong style={{ color: '#2dd4bf' }}>{recommendedRecsCount}</strong>
                </article>
                <article className="metric-card">
                  <p>5 GHz High-Speed APs</p>
                  <strong>{fiveGhzRecsCount}</strong>
                </article>
                <article className="metric-card">
                  <p>Model Accuracy</p>
                  <strong style={{ color: '#2dd4bf' }}>
                    {recommendationModelInfo?.metrics?.accuracy !== undefined
                      ? `${recommendationModelInfo.metrics.accuracy}%`
                      : recommendationModelInfo?.metrics?.accuracy_pct !== undefined
                        ? `${recommendationModelInfo.metrics.accuracy_pct}%`
                        : '88.1%'}
                  </strong>
                </article>
                <article className="metric-card">
                  <p>Features Evaluated</p>
                  <strong>{recommendationModelInfo?.features?.length ?? 12} Features</strong>
                </article>
              </div>

              {/* Toolbar: Filters and Sorting */}
              <div className="rec-toolbar panel">
                <div className="rec-filters">
                  <span className="toolbar-label">Filter:</span>
                  <button
                    type="button"
                    className={`filter-chip ${recommendationFilter === 'all' ? 'active' : ''}`}
                    onClick={() => setRecommendationFilter('all')}
                  >
                    All Networks ({recList.length})
                  </button>
                  <button
                    type="button"
                    className={`filter-chip ${recommendationFilter === 'recommended' ? 'active' : ''}`}
                    onClick={() => setRecommendationFilter('recommended')}
                  >
                    Recommended Only ({recommendedRecsCount})
                  </button>
                  <button
                    type="button"
                    className={`filter-chip ${recommendationFilter === '5ghz' ? 'active' : ''}`}
                    onClick={() => setRecommendationFilter('5ghz')}
                  >
                    5 GHz Band ({fiveGhzRecsCount})
                  </button>
                  <button
                    type="button"
                    className={`filter-chip ${recommendationFilter === 'secure' ? 'active' : ''}`}
                    onClick={() => setRecommendationFilter('secure')}
                  >
                    Secured Only
                  </button>
                </div>

                <div className="rec-sorting">
                  <label htmlFor="rec-sort-select">
                    <span className="toolbar-label">Sort By:</span>
                    <select
                      id="rec-sort-select"
                      className="rec-select"
                      value={recommendationSort}
                      onChange={(e) => setRecommendationSort(e.target.value)}
                    >
                      <option value="score">ML Recommendation Score</option>
                      <option value="signal">Signal Strength</option>
                      <option value="security">Security Grade</option>
                      <option value="channel">Channel Number</option>
                    </select>
                  </label>
                </div>
              </div>

              {/* Ranked Networks Table */}
              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Ranked Wi-Fi Networks ({filteredRecommendations.length})</h2>
                    <p className="panel-subtitle">Sorted based on Random Forest QoS and security classification</p>
                  </div>
                </div>

                {recommendationsLoading ? (
                  <p className="muted-text" style={{ padding: '24px' }}>Loading and analyzing Wi-Fi scan data...</p>
                ) : filteredRecommendations.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Rank</th>
                          <th>Network / SSID</th>
                          <th>Classification</th>
                          <th>ML Score</th>
                          <th>Signal</th>
                          <th>Channel &amp; Band</th>
                          <th>Security</th>
                          <th>Explainability Factors</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredRecommendations.map((net, idx) => {
                          const scoreVal = Number(net.score || 0)
                          return (
                            <tr key={net.bssid || idx} className={net.is_recommended ? 'recommended-row' : ''}>
                              <td>
                                <span className={`rank-badge ${idx === 0 ? 'gold' : idx === 1 ? 'silver' : idx === 2 ? 'bronze' : ''}`}>
                                  #{net.rank ?? idx + 1}
                                </span>
                              </td>
                              <td>
                                <div className="net-ssid-cell">
                                  <strong>{net.ssid || '<Hidden SSID>'}</strong>
                                  <span className="net-bssid-sub">{net.bssid || 'Unknown BSSID'}</span>
                                  {net.vendor && net.vendor !== 'Unknown Vendor' && (
                                    <span className="net-vendor-chip">{net.vendor}</span>
                                  )}
                                </div>
                              </td>
                              <td>
                                <span className={getRecommendationBadgeClass(net.classification)}>
                                  {net.classification}
                                </span>
                              </td>
                              <td>
                                <div className="score-cell">
                                  <div className="score-num-row">
                                    <strong>{scoreVal.toFixed(1)}</strong>
                                    <span className="score-sub">/ 100</span>
                                  </div>
                                  <div className="score-bar-bg">
                                    <div
                                      className={`score-bar-fill ${scoreVal >= 80 ? 'high' : scoreVal >= 60 ? 'med' : scoreVal >= 40 ? 'fair' : 'low'}`}
                                      style={{ width: `${Math.max(5, Math.min(100, scoreVal))}%` }}
                                    />
                                  </div>
                                </div>
                              </td>
                              <td>
                                <span className="mono-val">{net.signal || '--'}</span>
                              </td>
                              <td>
                                <span className="mono-val">Ch {net.channel || '?'}</span>
                                <span className="band-sub">{net.band}</span>
                              </td>
                              <td>
                                <span className={`badge ${String(net.security || '').toLowerCase().includes('open') ? 'badge-severity-high' : 'badge-status-resolved'}`}>
                                  {net.security || 'Open'}
                                </span>
                              </td>
                              <td style={{ maxWidth: '320px' }}>
                                <div className="mini-factors">
                                  {(net.positive_factors || []).slice(0, 2).map((r, i) => (
                                    <span key={i} className="mini-factor positive">&#10003; {r}</span>
                                  ))}
                                  {(net.negative_factors || []).slice(0, 1).map((r, i) => (
                                    <span key={i} className="mini-factor negative">&#9888; {r}</span>
                                  ))}
                                </div>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  className="connect-btn-table"
                                  onClick={() => handleOpenConnectModal(net)}
                                >
                                  Connect
                                </button>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state">
                    <p style={{ fontWeight: 600, fontSize: '15px', color: '#f8fafc', marginBottom: '6px' }}>
                      No Wi-Fi networks scanned yet.
                    </p>
                    <p>Run Wi-Fi Scan to discover nearby networks and then refresh recommendations.</p>
                  </div>
                )}
              </section>

              {/* Floating AI Wi-Fi Advisor Chat Panel */}
              <div className="floating-advisor-container">
                {!advisorOpen && (
                  <button
                    type="button"
                    className="floating-advisor-fab"
                    onClick={() => setAdvisorOpen(true)}
                    aria-label="Open NetShield AI Wi-Fi Advisor"
                  >
                    <span className="fab-icon">🤖</span>
                    <span className="fab-label">AI Wi-Fi Advisor</span>
                    <span className="fab-indicator" />
                  </button>
                )}

                {advisorOpen && (
                  <div className="floating-advisor-card" role="dialog" aria-label="AI Wi-Fi Advisor Chat">
                    <div className="advisor-header">
                      <div className="advisor-title-row">
                        <span className="advisor-avatar">🤖</span>
                        <div>
                          <h4 className="advisor-title">NetShield AI Wi-Fi Advisor</h4>
                          <span className="advisor-status">
                            <span className="status-live-dot" /> Grounded in Real Scan Data
                          </span>
                        </div>
                      </div>
                      <button
                        type="button"
                        className="advisor-close-btn"
                        onClick={() => setAdvisorOpen(false)}
                        aria-label="Close Advisor"
                      >
                        &#10005;
                      </button>
                    </div>

                    <div className="advisor-messages">
                      {advisorMessages.map((msg, i) => (
                        <div key={i} className={`advisor-msg-row ${msg.sender === 'user' ? 'user' : 'advisor'}`}>
                          <div className="advisor-msg-bubble">
                            <p style={{ whiteSpace: 'pre-line' }}>{msg.text}</p>
                            <span className="advisor-msg-time">{msg.timestamp}</span>
                          </div>
                        </div>
                      ))}
                    </div>

                    <div className="advisor-quick-prompts">
                      <span className="quick-prompt-label">Quick Questions:</span>
                      <div className="quick-prompts-scroll">
                        <button
                          type="button"
                          className="prompt-chip"
                          onClick={() => handleSendAdvisorMessage('Why is the #1 network recommended?')}
                        >
                          Why is #1 recommended?
                        </button>
                        <button
                          type="button"
                          className="prompt-chip"
                          onClick={() => handleSendAdvisorMessage('Is the best network safe for banking?')}
                        >
                          Is #1 safe for banking?
                        </button>
                        <button
                          type="button"
                          className="prompt-chip"
                          onClick={() => handleSendAdvisorMessage('Which networks are on 5 GHz?')}
                        >
                          Which APs are 5 GHz?
                        </button>
                        <button
                          type="button"
                          className="prompt-chip"
                          onClick={() => handleSendAdvisorMessage('Are there any open Wi-Fi risks?')}
                        >
                          Open Wi-Fi risks?
                        </button>
                        <button
                          type="button"
                          className="prompt-chip"
                          onClick={() => handleSendAdvisorMessage('What does the ML confidence percentage mean?')}
                        >
                          Explain ML confidence
                        </button>
                      </div>
                    </div>

                    <form
                      onSubmit={(e) => {
                        e.preventDefault()
                        handleSendAdvisorMessage()
                      }}
                      className="advisor-input-form"
                    >
                      <input
                        type="text"
                        className="advisor-input"
                        placeholder="Ask about signal, security, bands..."
                        value={advisorInput}
                        onChange={(e) => setAdvisorInput(e.target.value)}
                      />
                      <button
                        type="submit"
                        className="advisor-send-btn"
                        disabled={!advisorInput.trim()}
                      >
                        Send
                      </button>
                    </form>
                  </div>
                )}
              </div>

              {/* Connect Modal */}
              {connectModalNetwork ? (
                <div className="modal-backdrop" onClick={handleCloseConnectModal}>
                  <div className="modal-card" onClick={(e) => e.stopPropagation()}>
                    <div className="modal-header">
                      <h3>Connect to Wi-Fi Network</h3>
                      <button
                        type="button"
                        className="modal-close-btn"
                        onClick={handleCloseConnectModal}
                        disabled={connectLoading}
                      >
                        &#10005;
                      </button>
                    </div>

                    <div className="modal-body">
                      <div className="modal-network-preview">
                        <div className="preview-row">
                          <span className="preview-label">Network (SSID):</span>
                          <strong>{connectModalNetwork.ssid || '<Hidden SSID>'}</strong>
                        </div>
                        <div className="preview-row">
                          <span className="preview-label">BSSID:</span>
                          <span className="mono-val">{connectModalNetwork.bssid || 'Unknown'}</span>
                        </div>
                        <div className="preview-row">
                          <span className="preview-label">Encryption:</span>
                          <span className="badge badge-default">{connectModalNetwork.encryption || 'Open'}</span>
                        </div>
                        <div className="preview-row">
                          <span className="preview-label">Signal:</span>
                          <span>{connectModalNetwork.signal || '--'}</span>
                        </div>
                        <div className="preview-row">
                          <span className="preview-label">ML Classification:</span>
                          <span className={getRecommendationBadgeClass(connectModalNetwork.classification)}>
                            {connectModalNetwork.classification} (Score: {connectModalNetwork.score})
                          </span>
                        </div>
                      </div>

                      {connectStatus ? (
                        <div className={`connect-status-box ${connectStatus.success ? 'success' : 'error'}`}>
                          {connectStatus.success ? '✓ ' : '✗ '}
                          {connectStatus.message}
                        </div>
                      ) : null}

                      <form onSubmit={handleConnectSubmit} className="connect-form">
                        {String(connectModalNetwork.encryption || '').toLowerCase().includes('open') ? (
                          <p className="open-network-notice">
                            ℹ This network does not require a password (Open encryption).
                          </p>
                        ) : (
                          <div className="form-group">
                            <label htmlFor="wifi-password-input">
                              Network Security Key / Password:
                            </label>
                            <div className="password-input-wrap">
                              <input
                                id="wifi-password-input"
                                type={showPassword ? 'text' : 'password'}
                                className="password-input"
                                value={connectPassword}
                                onChange={(e) => setConnectPassword(e.target.value)}
                                placeholder="Enter Wi-Fi password (8-63 chars)"
                                disabled={connectLoading}
                                autoFocus
                              />
                              <button
                                type="button"
                                className="toggle-pwd-btn"
                                onClick={() => setShowPassword(!showPassword)}
                              >
                                {showPassword ? 'Hide' : 'Show'}
                              </button>
                            </div>
                            <span className="form-hint">
                              WPA/WPA2/WPA3 passphrases are typically 8 to 63 characters long.
                            </span>
                          </div>
                        )}

                        <div className="modal-actions">
                          <button
                            type="button"
                            className="scan-button"
                            onClick={handleCloseConnectModal}
                            disabled={connectLoading}
                          >
                            Cancel
                          </button>
                          <button
                            type="submit"
                            className="scan-button primary"
                            disabled={
                              connectLoading ||
                              (!String(connectModalNetwork.encryption || '').toLowerCase().includes('open') &&
                                connectPassword.length < 8)
                            }
                          >
                            {connectLoading ? 'Connecting...' : 'Connect Now'}
                          </button>
                        </div>
                      </form>
                    </div>
                  </div>
                </div>
              ) : null}
            </section>
          ) : activeView === 'Incidents' ? (
            <section className="incidents-view" aria-label="Security Incidents">
              {incidentsError ? <p className="error-banner">{incidentsError}</p> : null}

              {/* Incidents Command Bar */}
              <div className="panel command-bar-panel">
                <div className="command-bar-main">
                  <div>
                    <div className="live-status-pill">
                      <span className="status-dot dot-live" />
                      <span>INCIDENT LOG</span>
                      <span className="mode-badge">AUTO-POLLING 2s</span>
                    </div>
                    <h2>Security Incidents</h2>
                    <p className="panel-subtitle">
                      Intrusion detections and anomalous wireless activity recorded across live inference windows.
                    </p>
                  </div>
                  <div className="command-bar-actions">
                    <button
                      className="scan-button"
                      disabled={incidentsLoading}
                      onClick={() => loadIncidentsData()}
                      type="button"
                    >
                      {incidentsLoading ? 'Refreshing...' : 'Refresh Incidents'}
                    </button>
                    <button
                      className="scan-button"
                      onClick={() => setActiveView('Reports')}
                      type="button"
                    >
                      View Reports
                    </button>
                  </div>
                </div>
              </div>

              {/* 4-Metric KPI Strip */}
              <div className="metric-grid">
                <article className="metric-card metric-card-teal">
                  <p>Total Incidents</p>
                  <strong>{formatValue(totalIncidents)}</strong>
                  <span className="metric-sub">Recorded across all windows</span>
                </article>
                <article className={`metric-card ${newIncidents > 0 ? 'metric-card-amber' : 'metric-card-green'}`}>
                  <p>Unresolved Incidents</p>
                  <strong>{formatValue(newIncidents)}</strong>
                  <span className="metric-sub">{newIncidents > 0 ? 'Awaiting triage' : 'All clear / handled'}</span>
                </article>
                <article className={`metric-card ${highSeverityIncidents > 0 ? 'metric-card-red' : 'metric-card-green'}`}>
                  <p>High Severity Alerts</p>
                  <strong>{formatValue(highSeverityIncidents)}</strong>
                  <span className="metric-sub">{highSeverityIncidents > 0 ? 'Immediate attention' : 'None detected'}</span>
                </article>
                <article className={`metric-card ${avgAttackProb !== '--' ? 'metric-card-cyan' : ''}`}>
                  <p>Mean Attack Probability</p>
                  <strong>{avgAttackProb !== '--' ? `${avgAttackProb}%` : '--'}</strong>
                  <span className="metric-sub">Average across detections</span>
                </article>
              </div>

              {/* Filter and Search Bar */}
              <div className="panel filter-bar-panel">
                <div className="filter-bar-content">
                  <div className="search-box">
                    <input
                      type="text"
                      className="search-input"
                      placeholder="Search by ID, label, severity, status..."
                      value={incidentSearch}
                      onChange={(e) => setIncidentSearch(e.target.value)}
                      aria-label="Search incidents"
                    />
                    {incidentSearch ? (
                      <button
                        type="button"
                        className="search-clear-btn"
                        onClick={() => setIncidentSearch('')}
                        aria-label="Clear search"
                      >
                        ×
                      </button>
                    ) : null}
                  </div>

                  <div className="filter-group">
                    <span className="filter-label">Severity:</span>
                    {['all', 'high', 'medium', 'low'].map((sev) => (
                      <button
                        key={sev}
                        type="button"
                        className={`filter-chip ${incidentSeverityFilter === sev ? 'active' : ''}`}
                        onClick={() => setIncidentSeverityFilter(sev)}
                      >
                        {sev.charAt(0).toUpperCase() + sev.slice(1)}
                      </button>
                    ))}
                  </div>

                  <div className="filter-group">
                    <span className="filter-label">Status:</span>
                    {['all', 'new', 'resolved'].map((stat) => (
                      <button
                        key={stat}
                        type="button"
                        className={`filter-chip ${incidentStatusFilter === stat ? 'active' : ''}`}
                        onClick={() => setIncidentStatusFilter(stat)}
                      >
                        {stat.charAt(0).toUpperCase() + stat.slice(1)}
                      </button>
                    ))}
                  </div>

                  <div className="filter-results-count">
                    Showing <strong>{filteredIncidents.length}</strong> of {totalIncidents} incidents
                  </div>
                </div>
              </div>

              {/* Bounded Scrollable Table Panel */}
              <section className="panel incidents-panel">
                <div className="panel-header">
                  <div>
                    <h2>Incident Register</h2>
                    <p className="panel-subtitle">Select any incident row to inspect complete forensic evidence and telemetry.</p>
                  </div>
                </div>

                {incidentsLoading && incidents.length === 0 ? (
                  <p className="muted-text">Loading incidents...</p>
                ) : filteredIncidents.length > 0 ? (
                  <div className="table-wrap incidents-table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Timestamp</th>
                          <th>Detection Verdict</th>
                          <th>Attack Probability</th>
                          <th>Window Packets</th>
                          <th>Severity</th>
                          <th>Status</th>
                          <th>Forensics</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredIncidents.map((incident, index) => {
                          const isSelected = selectedIncident?.id === incident?.id
                          const probNum = Number(incident?.attack_probability)
                          const probPercent = Number.isFinite(probNum) ? `${(probNum * 100).toFixed(1)}%` : '--'
                          return (
                            <tr
                              key={incident?.id ?? index}
                              className={`incident-row ${isSelected ? 'selected-row' : ''}`}
                              onClick={() => {
                                setSelectedIncident(incident)
                                setIncidentJsonExpanded(false)
                              }}
                            >
                              <td>
                                <strong className="incident-id-badge">
                                  {formatValue(incident.id)}
                                </strong>
                              </td>
                              <td className="timestamp-cell">{formatDateTime(incident.created_at)}</td>
                              <td>
                                <span className="badge badge-detection">
                                  {formatValue(incident.label ?? incident.prediction)}
                                </span>
                              </td>
                              <td>
                                <div className="prob-cell-wrap">
                                  <span>{probPercent}</span>
                                  {Number.isFinite(probNum) ? (
                                    <div className="mini-meter-track">
                                      <div
                                        className="mini-meter-fill"
                                        style={{
                                          width: `${Math.min(100, Math.max(0, probNum * 100))}%`,
                                          backgroundColor: probNum > 0.7 ? '#ef4444' : probNum > 0.4 ? '#f59e0b' : '#14b8a6',
                                        }}
                                      />
                                    </div>
                                  ) : null}
                                </div>
                              </td>
                              <td>{formatValue(incident.total_packets)}</td>
                              <td>
                                <span className={getSeverityBadgeClass(incident.severity)}>
                                  {formatValue(incident.severity)}
                                </span>
                              </td>
                              <td>
                                <span className={getStatusBadgeClass(incident.status)}>
                                  {formatValue(incident.status)}
                                </span>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  className="btn-link"
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    setSelectedIncident(incident)
                                    setIncidentJsonExpanded(false)
                                  }}
                                >
                                  Investigate →
                                </button>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state">
                    <p>{incidents.length === 0 ? 'No Security Incidents Detected' : 'No matching incidents found'}</p>
                    <p>
                      {incidents.length === 0
                        ? 'Incidents created by live ML attack detections will appear here automatically.'
                        : 'Adjust your search query or severity/status filters.'}
                    </p>
                  </div>
                )}
              </section>

            </section>
          ) : activeView === 'Reports' ? (
            <section className="reports-view" aria-label="Security reports">
              {reportsError ? <p className="error-banner">{reportsError}</p> : null}

              {/* Reports Command Bar */}
              <div className="panel command-bar-panel">
                <div className="command-bar-main">
                  <div>
                    <div className="live-status-pill">
                      <span className="status-dot dot-live" />
                      <span>TELEMETRY & AUDIT</span>
                      <span className="mode-badge">INCIDENT ARCHIVE</span>
                    </div>
                    <h2>Security Reports & Analytics</h2>
                    <p className="panel-subtitle">
                      Incident telemetry, threat distributions, and forensic audits generated from live ML intrusion detections.
                    </p>
                  </div>
                  <div className="command-bar-actions">
                    <button
                      className="scan-button"
                      disabled={reportsLoading}
                      onClick={handleRefreshReports}
                      type="button"
                    >
                      {reportsLoading ? 'Refreshing...' : 'Refresh Reports'}
                    </button>
                    <button
                      className="scan-button"
                      disabled={reportsLoading || reportIncidents.length === 0}
                      onClick={handleExportCsv}
                      type="button"
                    >
                      Export CSV
                    </button>
                    <a
                      className="scan-button"
                      href="/api/reports/pdf"
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center' }}
                    >
                      Server PDF
                    </a>
                    <button
                      className="scan-button primary"
                      disabled={reportsLoading}
                      onClick={() => window.print()}
                      type="button"
                    >
                      Print / Save PDF
                    </button>
                  </div>
                </div>
              </div>

              {/* 4-Metric KPI Strip */}
              <div className="metric-grid">
                <article className="metric-card metric-card-teal">
                  <p>Total Incidents</p>
                  <strong>{formatValue(reportTotalIncidents)}</strong>
                  <span className="metric-sub">Recorded across all windows</span>
                </article>
                <article className={`metric-card ${reportHighSeverity > 0 ? 'metric-card-red' : 'metric-card-green'}`}>
                  <p>High Severity</p>
                  <strong>{formatValue(reportHighSeverity)}</strong>
                  <span className="metric-sub">{reportHighSeverity > 0 ? 'Action required' : 'None detected'}</span>
                </article>
                <article className="metric-card metric-card-cyan">
                  <p>Packets in Incidents</p>
                  <strong>{formatValue(reportTotalPackets)}</strong>
                  <span className="metric-sub">Analyzed in attack windows</span>
                </article>
                <article className={`metric-card ${reportAvgAttackProb !== null ? 'metric-card-amber' : ''}`}>
                  <p>Average Attack Probability</p>
                  <strong>{reportAvgAttackProb !== null ? formatProbability(reportAvgAttackProb) : '--'}</strong>
                  <span className="metric-sub">Mean confidence score</span>
                </article>
              </div>

              {/* Threat Distribution Summary Panel */}
              <section className="panel attack-summary-panel">
                <div className="panel-header">
                  <div>
                    <h2>Threat Classification Distribution</h2>
                    <p className="panel-subtitle">Frequency and proportion of detected attack types across recorded windows.</p>
                  </div>
                </div>
                {Object.keys(attackCountsByLabel).length > 0 ? (
                  <div className="report-threat-bar-container">
                    {Object.entries(attackCountsByLabel).map(([label, count]) => {
                      const sharePercent = reportTotalIncidents > 0 ? ((count / reportTotalIncidents) * 100).toFixed(1) : 0
                      return (
                        <div className="report-threat-bar-row" key={label}>
                          <div className="report-threat-bar-label">
                            <span className="badge badge-detection">{label}</span>
                          </div>
                          <div className="report-threat-bar-track">
                            <div
                              className="report-threat-bar-fill"
                              style={{ width: `${Math.min(100, Math.max(4, sharePercent))}%` }}
                            />
                          </div>
                          <div className="report-threat-bar-count">
                            <strong>{count}</strong> ({sharePercent}%)
                          </div>
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <p className="empty-state-muted">No attacks recorded yet. Incidents detected by the ML engine will appear here.</p>
                )}
              </section>

              {/* Incident Audit Ledger Bounded Table */}
              <section className="panel incidents-report-panel">
                <div className="panel-header">
                  <div>
                    <h2>Incident Audit Ledger</h2>
                    <p className="panel-subtitle">Comprehensive historical log of all detected intrusion windows.</p>
                  </div>
                </div>
                {reportsLoading && reportIncidents.length === 0 ? (
                  <p className="muted-text">Loading reports data...</p>
                ) : reportIncidents.length > 0 ? (
                  <div className="table-wrap reports-table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Timestamp</th>
                          <th>Attack Label</th>
                          <th>Attack Probability</th>
                          <th>Window Packets</th>
                          <th>Severity</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {reportIncidents.map((incident, index) => {
                          const probNum = Number(incident?.attack_probability)
                          const probPercent = Number.isFinite(probNum) ? `${(probNum * 100).toFixed(1)}%` : '--'
                          return (
                            <tr key={getValue(incident, ['id']) ?? index}>
                              <td>
                                <strong className="incident-id-badge">
                                  {formatValue(incident.id)}
                                </strong>
                              </td>
                              <td className="timestamp-cell">{formatDateTime(incident.created_at)}</td>
                              <td>
                                <span className="badge badge-detection">
                                  {formatValue(incident.label ?? incident.prediction)}
                                </span>
                              </td>
                              <td>
                                <div className="prob-cell-wrap">
                                  <span>{probPercent}</span>
                                  {Number.isFinite(probNum) ? (
                                    <div className="mini-meter-track">
                                      <div
                                        className="mini-meter-fill"
                                        style={{
                                          width: `${Math.min(100, Math.max(0, probNum * 100))}%`,
                                          backgroundColor: probNum > 0.7 ? '#ef4444' : probNum > 0.4 ? '#f59e0b' : '#14b8a6',
                                        }}
                                      />
                                    </div>
                                  ) : null}
                                </div>
                              </td>
                              <td>{formatValue(incident.total_packets)}</td>
                              <td>
                                <span className={getSeverityBadgeClass(incident.severity)}>
                                  {formatValue(incident.severity)}
                                </span>
                              </td>
                              <td>
                                <span className={getStatusBadgeClass(incident.status)}>
                                  {formatValue(incident.status)}
                                </span>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state">
                    <p>No security incidents recorded yet.</p>
                    <p>Reports will populate when the ML detector identifies an attack during live monitoring or PCAP evaluation.</p>
                  </div>
                )}
              </section>
            </section>
          ) : activeView === 'Settings' ? (
            <section className="settings-view" aria-label="System Settings and Configuration">
              {/* Settings Command Bar */}
              <div className="panel command-bar-panel">
                <div className="command-bar-main">
                  <div>
                    <div className="live-status-pill">
                      <span className="status-dot dot-live" />
                      <span>SYSTEM CONTROL</span>
                      <span className="mode-badge">CONFIGURATION CENTER</span>
                    </div>
                    <h2>Settings & Configuration</h2>
                    <p className="panel-subtitle">
                      Operational parameters, interface telemetry, AWID3 ML engine architecture, and client preferences.
                    </p>
                  </div>
                  <div className="command-bar-actions">
                    <button
                      className="scan-button"
                      disabled={diagnosticsLoading}
                      onClick={handleRunDiagnostics}
                      type="button"
                    >
                      {diagnosticsLoading ? 'Pinging Backend...' : 'Run Health Check'}
                    </button>
                  </div>
                </div>
              </div>

              {/* Settings Tabs Bar */}
              <div className="settings-tabs-bar" role="tablist" aria-label="Settings categories">
                <button
                  type="button"
                  role="tab"
                  aria-selected={settingsTab === 'general'}
                  className={`settings-tab-btn ${settingsTab === 'general' ? 'active' : ''}`}
                  onClick={() => setSettingsTab('general')}
                >
                  ⚙ Preferences (UI)
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={settingsTab === 'telemetry'}
                  className={`settings-tab-btn ${settingsTab === 'telemetry' ? 'active' : ''}`}
                  onClick={() => setSettingsTab('telemetry')}
                >
                  📡 Adapter & Ingestion
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={settingsTab === 'ml'}
                  className={`settings-tab-btn ${settingsTab === 'ml' ? 'active' : ''}`}
                  onClick={() => setSettingsTab('ml')}
                >
                  🧠 AWID3 ML Engine
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={settingsTab === 'recommendations'}
                  className={`settings-tab-btn ${settingsTab === 'recommendations' ? 'active' : ''}`}
                  onClick={() => setSettingsTab('recommendations')}
                >
                  📶 Wi-Fi Recommendation
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={settingsTab === 'diagnostics'}
                  className={`settings-tab-btn ${settingsTab === 'diagnostics' ? 'active' : ''}`}
                  onClick={() => setSettingsTab('diagnostics')}
                >
                  🩺 Diagnostics & Health
                </button>
              </div>

              {/* Tab 1: General UI Preferences */}
              {settingsTab === 'general' ? (
                <div className="settings-content-panel">
                  {settingsSaveMsg ? (
                    <div className="save-success-banner" role="status">
                      <span>✓</span> {settingsSaveMsg}
                    </div>
                  ) : null}

                  <div className="settings-card">
                    <div className="settings-card-header">
                      <h3>SOC Display & Operational Preferences</h3>
                      <span className="badge-client-pref">Client-Side Preferences (localStorage)</span>
                    </div>

                    <div className="settings-grid-2col">
                      <div className="settings-field">
                        <label htmlFor="poll-interval-select">Telemetry Polling Interval</label>
                        <select
                          id="poll-interval-select"
                          className="settings-select"
                          value={uiPrefs.pollInterval ?? 2000}
                          onChange={(e) =>
                            setUiPrefs((prev) => ({ ...prev, pollInterval: Number(e.target.value) }))
                          }
                        >
                          <option value={1000}>1 Second (Intensive / Debug)</option>
                          <option value={2000}>2 Seconds (Recommended SOC Real-Time)</option>
                          <option value={5000}>5 Seconds (Balanced Telemetry)</option>
                          <option value={10000}>10 Seconds (Low Overhead)</option>
                        </select>
                        <span className="settings-field-hint">
                          Governs auto-refresh frequency for packet capture, incident logs, and live monitoring.
                        </span>
                      </div>

                      <div className="settings-field">
                        <label htmlFor="default-view-select">Default Initial Page on Launch</label>
                        <select
                          id="default-view-select"
                          className="settings-select"
                          value={uiPrefs.defaultView ?? 'Dashboard'}
                          onChange={(e) =>
                            setUiPrefs((prev) => ({ ...prev, defaultView: e.target.value }))
                          }
                        >
                          <option value="Dashboard">Dashboard</option>
                          <option value="WiFi Scan">Wi-Fi Scan</option>
                          <option value="Live Monitor">Live Monitor</option>
                          <option value="ML Engine">ML Engine</option>
                          <option value="Network Recommendations">Network Recommendations</option>
                          <option value="Incidents">Security Incidents</option>
                          <option value="Reports">Security Reports</option>
                          <option value="PCAP Analysis">PCAP Analysis</option>
                          <option value="Settings">Settings & Configuration</option>
                        </select>
                        <span className="settings-field-hint">
                          The view displayed immediately when the NetShield dashboard is opened.
                        </span>
                      </div>

                      <div className="settings-field">
                        <label htmlFor="table-density-select">Table Row Density</label>
                        <select
                          id="table-density-select"
                          className="settings-select"
                          value={uiPrefs.tableDensity ?? 'compact'}
                          onChange={(e) =>
                            setUiPrefs((prev) => ({ ...prev, tableDensity: e.target.value }))
                          }
                        >
                          <option value="compact">Compact (SOC Monospace Density)</option>
                          <option value="comfortable">Comfortable (Standard Padding)</option>
                        </select>
                        <span className="settings-field-hint">
                          Row height and spacing across packet tables, network registers, and incident audits.
                        </span>
                      </div>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '10px' }}>
                      <label className="settings-toggle-label">
                        <input
                          type="checkbox"
                          checked={uiPrefs.visualAlerts ?? true}
                          onChange={(e) =>
                            setUiPrefs((prev) => ({ ...prev, visualAlerts: e.target.checked }))
                          }
                        />
                        <span>Visual Alert Highlights (Flash high-severity incident banners in red)</span>
                      </label>

                      <label className="settings-toggle-label">
                        <input
                          type="checkbox"
                          checked={uiPrefs.soundAlerts ?? false}
                          onChange={(e) =>
                            setUiPrefs((prev) => ({ ...prev, soundAlerts: e.target.checked }))
                          }
                        />
                        <span>Audio Notifications (Browser audio chime on new intrusion alert)</span>
                      </label>
                    </div>

                    <div style={{ display: 'flex', gap: '10px', marginTop: '14px' }}>
                      <button
                        type="button"
                        className="scan-button primary"
                        onClick={() => handleSaveUiPrefs(uiPrefs)}
                      >
                        Save Preferences
                      </button>
                      <button
                        type="button"
                        className="scan-button"
                        onClick={() => {
                          const defaults = {
                            pollInterval: 2000,
                            visualAlerts: true,
                            soundAlerts: false,
                            defaultView: 'Dashboard',
                            tableDensity: 'compact',
                          }
                          handleSaveUiPrefs(defaults)
                        }}
                      >
                        Reset Defaults
                      </button>
                    </div>
                  </div>
                </div>
              ) : null}

              {/* Tab 2: Adapter & Ingestion */}
              {settingsTab === 'telemetry' ? (
                <div className="settings-content-panel">
                  <div className="settings-card">
                    <div className="settings-card-header">
                      <h3>Wireless Hardware & Ingestion Stack</h3>
                      <span className="badge-read-only">Read-Only Backend Telemetry</span>
                    </div>

                    <div className="settings-grid-2col">
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Hardware Adapter Status</span>
                        <strong className="settings-telemetry-value">
                          {formatValue(adapterState ?? (interfaces.length > 0 ? 'available' : 'not_detected'))}
                        </strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Detected Wireless Adapters</span>
                        <strong className="settings-telemetry-value">{interfaces.length} Interfaces</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Active Scanner Adapter</span>
                        <strong className="settings-telemetry-value">{selectedInterface || 'None Selected'}</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Active Sniffer Adapter</span>
                        <strong className="settings-telemetry-value">{selectedCaptureInterface || 'None Selected'}</strong>
                      </div>
                    </div>

                    <div className="settings-field" style={{ marginTop: '10px' }}>
                      <label>Detected Physical Wireless Interfaces</label>
                      {interfaces.length > 0 ? (
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>Interface</th>
                                <th>Mode</th>
                                <th>Channel</th>
                                <th>Operational State</th>
                              </tr>
                            </thead>
                            <tbody>
                              {interfaces.map((iface, index) => (
                                <tr key={iface.name ?? index}>
                                  <td>
                                    <strong>{formatValue(iface.name)}</strong>
                                  </td>
                                  <td>
                                    <span className="badge badge-subtle">{formatValue(iface.mode)}</span>
                                  </td>
                                  <td>{formatValue(iface.channel)}</td>
                                  <td>
                                    <span className="badge badge-open">Detected & Ready</span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <div className="empty-state">
                          <p>No Wireless Interfaces Detected</p>
                          <p>
                            Linux wireless interface query returned empty or iw utility is not detected.
                            NetShield is operating in Offline / PCAP Replay mode.
                          </p>
                        </div>
                      )}
                    </div>

                    <div className="settings-field" style={{ marginTop: '10px' }}>
                      <label>Background Daemons & Ingestion Engine</label>
                      <div className="settings-grid-2col">
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Wi-Fi Scanner Daemon</span>
                          <strong className="settings-telemetry-value">
                            netshield-ml-scanner.service ({formatValue(scannerStatus?.state ?? 'idle')})
                          </strong>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Packet Sniffer Daemon</span>
                          <strong className="settings-telemetry-value">
                            netshield-ml-capture.service ({formatValue(captureStatus?.state ?? 'idle')})
                          </strong>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Packet Parsing Engine</span>
                          <strong className="settings-telemetry-value">Scapy / Native 802.11 Raw Frame Ingestion</strong>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Supported Wi-Fi Bands</span>
                          <strong className="settings-telemetry-value">2.4 GHz (802.11b/g/n) • 5 GHz (802.11a/n/ac) • 6 GHz (Wi-Fi 6E)</strong>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}

              {/* Tab 3: AWID3 ML Engine */}
              {settingsTab === 'ml' ? (
                <div className="settings-content-panel">
                  <div className="settings-card">
                    <div className="settings-card-header">
                      <h3>AWID3 Intrusion Detection Architecture</h3>
                      <span className="badge-read-only">Frozen Model Specification</span>
                    </div>

                    <div className="settings-grid-2col">
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Model Pipeline</span>
                        <strong className="settings-telemetry-value">AWID3 Wireless Intrusion Classifier</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Primary Classifier</span>
                        <strong className="settings-telemetry-value">Random Forest Ensemble (AWID3 Optimized)</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Baseline Model</span>
                        <strong className="settings-telemetry-value">XGBoost Gradient Boosted Trees</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Decision Threshold</span>
                        <strong className="settings-telemetry-value">0.50 (Attack Probability ≥ 50%)</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Feature Input Dimension</span>
                        <strong className="settings-telemetry-value">31 Canonical 802.11 Frame Features</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Detection Window Mode</span>
                        <strong className="settings-telemetry-value">Sliding Frame Windows with Real-Time Vectorization</strong>
                      </div>
                    </div>

                    <div className="settings-field" style={{ marginTop: '10px' }}>
                      <label>Canonical 31-Feature Schema (AWID3 Specification)</label>
                      <div className="settings-telemetry-item" style={{ background: '#080d1a', fontSize: '0.8rem', lineHeight: '1.6' }}>
                        <p style={{ margin: 0, color: 'var(--accent)' }}>
                          <strong>Physical & Radio Layer:</strong> radiotap.dbm_antsignal, frame.len, frame.time_delta, frame.time_relative, frame.cap_len
                        </p>
                        <p style={{ margin: '6px 0 0', color: '#38bdf8' }}>
                          <strong>MAC & Control Flags:</strong> wlan.fc.type, wlan.fc.subtype, wlan.fc.ds, wlan.fc.frag, wlan.fc.retry, wlan.fc.pwrmgt, wlan.fc.moredata, wlan.fc.protected, wlan.fc.order
                        </p>
                        <p style={{ margin: '6px 0 0', color: '#a78bfa' }}>
                          <strong>Addressing & Sequence:</strong> wlan.duration, wlan.seq, wlan.frag, wlan.ra, wlan.da, wlan.ta, wlan.sa, wlan.bssid
                        </p>
                        <p style={{ margin: '6px 0 0', color: '#f59e0b' }}>
                          <strong>Management & Frame Details:</strong> wlan.fixed.beacon, wlan.fixed.capabilities, wlan.fixed.listen_ival, wlan.fixed.timestamp, wlan.wep.iv, wlan.wep.key, wlan.wep.icv
                        </p>
                      </div>
                    </div>

                    <div className="settings-field" style={{ marginTop: '10px' }}>
                      <label>Target Threat Categories Detected</label>
                      <div className="settings-grid-2col">
                        <div className="settings-telemetry-item">
                          <strong style={{ color: '#ef4444' }}>Deauthentication Flood</strong>
                          <span className="settings-field-hint">Spoofed 802.11 management deauth frames to force client disconnects.</span>
                        </div>
                        <div className="settings-telemetry-item">
                          <strong style={{ color: '#ef4444' }}>Disassociation Attack</strong>
                          <span className="settings-field-hint">Abusive disassoc frame storm targeting active station associations.</span>
                        </div>
                        <div className="settings-telemetry-item">
                          <strong style={{ color: '#f59e0b' }}>Evil Twin / Rogue AP</strong>
                          <span className="settings-field-hint">Duplicate SSID/BSSID masquerading to intercept client credentials.</span>
                        </div>
                        <div className="settings-telemetry-item">
                          <strong style={{ color: '#f59e0b' }}>KRACK (Key Reinstallation)</strong>
                          <span className="settings-field-hint">4-way handshake replay attacks forcing nonce reuse on WPA2 clients.</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}

              {/* Tab 4: Wi-Fi Recommendation */}
              {settingsTab === 'recommendations' ? (
                <div className="settings-content-panel">
                  <div className="settings-card">
                    <div className="settings-card-header">
                      <h3>Wi-Fi Recommendation Architecture & Weights</h3>
                      <span className="badge-read-only">Frozen Random Forest Specification</span>
                    </div>

                    <div className="settings-grid-2col">
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Ingestion Source</span>
                        <strong className="settings-telemetry-value">backend/data/scan_results/wifi_scan_results.csv</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Seed Networks Policy</span>
                        <strong className="settings-telemetry-value">Disabled (Live scanner output only)</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Classification Model</span>
                        <strong className="settings-telemetry-value">Frozen Random Forest Wi-Fi Classifier</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Scoring Composite Range</span>
                        <strong className="settings-telemetry-value">0–100 Security & Quality Score</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Quality Rating Tiers</span>
                        <strong className="settings-telemetry-value">EXCELLENT (90-100) • GOOD (75-89) • FAIR (50-74) • POOR (&lt;50)</strong>
                      </div>
                      <div className="settings-telemetry-item">
                        <span className="settings-telemetry-label">Confidence Metric</span>
                        <strong className="settings-telemetry-value">Random Forest Class Probability Vector</strong>
                      </div>
                    </div>

                    <div className="settings-field" style={{ marginTop: '10px' }}>
                      <label>12 Evaluated Features (Weights & Rules)</label>
                      <div className="settings-grid-2col">
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Signal Strength (RSSI dBm)</span>
                          <span className="settings-field-hint">Range -100 to -30 dBm; higher power provides higher throughput and SNR.</span>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Frequency Band & Congestion</span>
                          <span className="settings-field-hint">5 GHz and 6 GHz receive higher quality scores due to reduced co-channel interference.</span>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Encryption Protocol</span>
                          <span className="settings-field-hint">WPA3-SAE &gt; WPA2-Enterprise &gt; WPA2-Personal &gt; WEP (Insecure) &gt; Open (Hazard).</span>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">WPS Vulnerability</span>
                          <span className="settings-field-hint">WPS-enabled access points trigger security penalties due to PIN brute-force risks.</span>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Hardware Vendor OUI</span>
                          <span className="settings-field-hint">IEEE OUI lookup verifies authentic enterprise hardware vs rogue spoofed APs.</span>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Beacon Interval & DTIM</span>
                          <span className="settings-field-hint">Standard beacon timing prevents station power consumption and timing drift.</span>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Supported Standards</span>
                          <span className="settings-field-hint">802.11ax (Wi-Fi 6) and 802.11ac receive top performance multipliers.</span>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Hidden SSID Status</span>
                          <span className="settings-field-hint">Flags hidden networks that require probe requests, warning users of tracking risks.</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}

              {/* Tab 5: Diagnostics & Health */}
              {settingsTab === 'diagnostics' ? (
                <div className="settings-content-panel">
                  <div className="settings-card">
                    <div className="settings-card-header">
                      <h3>NetShield-ML-WIDS System Diagnostics & Health</h3>
                      <span className="badge-read-only">Live Diagnostic Test</span>
                    </div>

                    <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                      <button
                        type="button"
                        className="scan-button primary"
                        disabled={diagnosticsLoading}
                        onClick={handleRunDiagnostics}
                      >
                        {diagnosticsLoading ? 'Pinging /api/health...' : 'Execute API Health Ping'}
                      </button>
                      <span className="settings-field-hint">
                        Tests connectivity between Vite client and Flask REST service at http://127.0.0.1:5000/api/health
                      </span>
                    </div>

                    {diagnosticsResult ? (
                      <div className="settings-diagnostics-box" role="region" aria-label="Diagnostic Result">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ color: diagnosticsResult.ok ? '#4ade80' : '#ef4444', fontWeight: 'bold' }}>
                            {diagnosticsResult.ok ? '✓ HEALTH CHECK PASSED' : '✕ HEALTH CHECK FAILED'}
                          </span>
                          <span style={{ color: 'var(--text-muted)' }}>Latency: {diagnosticsResult.latencyMs} ms</span>
                        </div>
                        <div>
                          <strong>Timestamp:</strong> {formatDateTime(diagnosticsResult.timestamp)}
                        </div>
                        {diagnosticsResult.ok ? (
                          <div>
                            <strong>Backend Payload:</strong>
                            <pre style={{ margin: '4px 0 0', color: '#a78bfa' }}>
                              {JSON.stringify(diagnosticsResult.data, null, 2)}
                            </pre>
                          </div>
                        ) : (
                          <div style={{ color: '#f87171' }}>
                            <strong>Error Detail:</strong> {diagnosticsResult.error}
                          </div>
                        )}
                      </div>
                    ) : null}

                    <div className="settings-field" style={{ marginTop: '14px' }}>
                      <label>System Environment & Architecture</label>
                      <div className="settings-grid-2col">
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Software Platform</span>
                          <strong className="settings-telemetry-value">NetShield-ML-WIDS Enterprise SOC Edition</strong>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Version & Build</span>
                          <strong className="settings-telemetry-value">v2.4.0-SOC (Vite + React 18)</strong>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Backend Web Server</span>
                          <strong className="settings-telemetry-value">Flask / Python 3.11 with CORS enabled</strong>
                        </div>
                        <div className="settings-telemetry-item">
                          <span className="settings-telemetry-label">Core Machine Learning Stack</span>
                          <strong className="settings-telemetry-value">Scikit-Learn, XGBoost, Scapy, NumPy</strong>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}
            </section>
          ) : (
            <section className="placeholder-view">
              <p className="eyebrow">{activeView}</p>
              <h2>{activeView}</h2>
              <p>This section is ready for future NetShield functionality.</p>
            </section>
          )}
        </main>

        {/* Viewport-Level Side Drawer for Incident Forensics (React Portal - Globally Available) */}
              {selectedIncident && typeof document !== 'undefined' ? createPortal(
                <div
                  className="incident-drawer-backdrop"
                  onClick={() => {
                    setSelectedIncident(null)
                    setIncidentJsonExpanded(false)
                  }}
                >
                  <div
                    className="incident-drawer"
                    onClick={(e) => e.stopPropagation()}
                    role="dialog"
                    aria-modal="true"
                    aria-label="Incident Details"
                  >
                    <div className="incident-drawer-header">
                      <div className="drawer-title-group">
                        <div className="drawer-pill">
                          <span>INCIDENT FORENSICS</span>
                        </div>
                        <h3>Incident #{formatValue(selectedIncident.id)}</h3>
                      </div>
                      <button
                        type="button"
                        className="modal-close-button"
                        onClick={() => {
                          setSelectedIncident(null)
                          setIncidentJsonExpanded(false)
                        }}
                        aria-label="Close details"
                      >
                        ×
                      </button>
                    </div>

                    <div className="incident-drawer-body">
                      {/* Detection Verdict Banner */}
                      <div className="drawer-verdict-card">
                        <div className="drawer-verdict-header">
                          <span className="badge badge-detection badge-lg">
                            {formatValue(selectedIncident.label ?? selectedIncident.prediction)}
                          </span>
                          <span className={getSeverityBadgeClass(selectedIncident.severity)}>
                            {formatValue(selectedIncident.severity)} Severity
                          </span>
                          <div className="drawer-status-select-wrap">
                            <label htmlFor="drawer-incident-status" className="drawer-status-label">
                              Status:
                            </label>
                            <select
                              id="drawer-incident-status"
                              className="drawer-status-select"
                              value={selectedIncident.status || 'New'}
                              onChange={(e) => handleUpdateIncidentStatus(selectedIncident.id, e.target.value)}
                              aria-label="Incident status selector"
                            >
                              <option value="New">New</option>
                              <option value="Investigating">Investigating</option>
                              <option value="Resolved">Resolved</option>
                            </select>
                          </div>
                        </div>
                        <div className="drawer-prob-bar">
                          <div className="drawer-prob-labels">
                            <span>Attack Probability</span>
                            <strong>
                              {Number.isFinite(Number(selectedIncident.attack_probability))
                                ? `${(Number(selectedIncident.attack_probability) * 100).toFixed(1)}%`
                                : '--'}
                            </strong>
                          </div>
                          <div className="mini-meter-track" style={{ height: '8px' }}>
                            <div
                              className="mini-meter-fill"
                              style={{
                                width: `${Math.min(100, Math.max(0, (Number(selectedIncident.attack_probability) || 0) * 100))}%`,
                                backgroundColor:
                                  Number(selectedIncident.attack_probability) > 0.7
                                    ? '#ef4444'
                                    : Number(selectedIncident.attack_probability) > 0.4
                                      ? '#f59e0b'
                                      : '#14b8a6',
                              }}
                            />
                          </div>
                        </div>
                      </div>

                      {/* Evidence & Metrics Grid */}
                      <div className="drawer-section">
                        <h4>Telemetry & Window Evidence</h4>
                        <div className="drawer-metrics-grid">
                          <div className="drawer-metric-item">
                            <span className="drawer-metric-label">Logged At</span>
                            <strong className="drawer-metric-val">{formatDateTime(selectedIncident.created_at)}</strong>
                          </div>
                          <div className="drawer-metric-item">
                            <span className="drawer-metric-label">Window Start</span>
                            <strong className="drawer-metric-val">{formatDateTime(selectedIncident.window_start)}</strong>
                          </div>
                          <div className="drawer-metric-item">
                            <span className="drawer-metric-label">Window End</span>
                            <strong className="drawer-metric-val">{formatDateTime(selectedIncident.window_end)}</strong>
                          </div>
                          <div className="drawer-metric-item">
                            <span className="drawer-metric-label">Total Packets</span>
                            <strong className="drawer-metric-val">{formatValue(selectedIncident.total_packets)}</strong>
                          </div>
                          <div className="drawer-metric-item">
                            <span className="drawer-metric-label">Features Evaluated</span>
                            <strong className="drawer-metric-val">{formatValue(selectedIncident.feature_count ?? 31)} AWID3</strong>
                          </div>
                          <div className="drawer-metric-item">
                            <span className="drawer-metric-label">Normal Probability</span>
                            <strong className="drawer-metric-val">
                              {Number.isFinite(Number(selectedIncident.normal_probability))
                                ? `${(Number(selectedIncident.normal_probability) * 100).toFixed(1)}%`
                                : '--'}
                            </strong>
                          </div>
                        </div>
                      </div>

                      {/* Raw Forensic Evidence JSON - Collapsed by default */}
                      <div className="drawer-section">
                        <div className="drawer-section-header">
                          <div>
                            <h4>Raw Forensic Artifact</h4>
                            <span className="drawer-json-note">Canonical Store Data</span>
                          </div>
                          <div className="drawer-json-actions">
                            <button
                              type="button"
                              className={`drawer-json-copy-btn ${incidentCopyStatus === 'error' ? 'copy-error' : ''}`}
                              onClick={() => handleCopyIncidentJson(selectedIncident)}
                              title="Copy formatted JSON to clipboard"
                            >
                              {incidentCopyStatus === 'success'
                                ? '✓ Copied'
                                : incidentCopyStatus === 'error'
                                  ? '✕ Copy Failed'
                                  : 'Copy JSON'}
                            </button>
                            <button
                              type="button"
                              className="drawer-json-toggle-btn"
                              onClick={() => setIncidentJsonExpanded(!incidentJsonExpanded)}
                              aria-expanded={incidentJsonExpanded}
                            >
                              {incidentJsonExpanded ? '▲ Collapse JSON' : '▼ Expand JSON'}
                            </button>
                          </div>
                        </div>

                        {incidentJsonExpanded ? (
                          <pre className="drawer-json-viewer">
                            <code>{JSON.stringify(selectedIncident, null, 2)}</code>
                          </pre>
                        ) : (
                          <div
                            className="drawer-json-collapsed-box"
                            onClick={() => setIncidentJsonExpanded(true)}
                            role="button"
                            tabIndex={0}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault()
                                setIncidentJsonExpanded(true)
                              }
                            }}
                          >
                            <span className="drawer-json-collapsed-text">
                              Raw 31-feature forensic JSON artifact is collapsed ({JSON.stringify(selectedIncident).length} bytes). Click to expand.
                            </span>
                            <span className="drawer-json-collapsed-link">Expand JSON</span>
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="incident-drawer-footer">
                      <button
                        type="button"
                        className={`scan-button ${incidentCopyStatus === 'error' ? 'button-error' : ''}`}
                        onClick={() => handleCopyIncidentJson(selectedIncident)}
                      >
                        {incidentCopyStatus === 'success'
                          ? '✓ Copied JSON'
                          : incidentCopyStatus === 'error'
                            ? '✕ Copy Failed'
                            : 'Copy Forensic JSON'}
                      </button>
                      <button
                        type="button"
                        className="scan-button"
                        onClick={() => {
                          setSelectedIncident(null)
                          setIncidentJsonExpanded(false)
                          setActiveView('ML Engine')
                          setMlEngineTab('live')
                        }}
                      >
                        Live ML Engine →
                      </button>
                      <button
                        type="button"
                        className="scan-button primary"
                        onClick={() => {
                          setSelectedIncident(null)
                          setIncidentJsonExpanded(false)
                        }}
                      >
                        Close
                      </button>
                    </div>
                  </div>
                </div>,
                document.body
              ) : null}
      </div>
    </div>
  )
}

export default App
