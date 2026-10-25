import { useEffect, useState } from 'react'
import './App.css'

import {
  getValue,
  normalizeList,
  formatValue,
  formatProbability,
  normalizeScannerStatus,
  normalizeCaptureStatus,
  getInterfaceName,
  getScannerState,
  getCaptureState,
  normalizeCounts,
  generateAdvisorResponse,
} from './utils/helpers'

import { Sidebar } from './components/Sidebar'
import { Header } from './components/Header'
import { IncidentDrawer } from './components/IncidentDrawer'
import { ConnectModal } from './components/ConnectModal'
import { AdvisorDrawer } from './components/AdvisorDrawer'

import { DashboardView } from './views/DashboardView'
import { WifiScanView } from './views/WifiScanView'
import { LiveMonitorView } from './views/LiveMonitorView'
import { MlEngineView } from './views/MlEngineView'
import { PcapAnalysisView } from './views/PcapAnalysisView'
import { RecommendationsView } from './views/RecommendationsView'
import { IncidentsView } from './views/IncidentsView'
import { ReportsView } from './views/ReportsView'
import { SettingsView } from './views/SettingsView'

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

  // Settings state
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

  // ML Evaluation state
  const [mlDatasets, setMlDatasets] = useState([])
  const [selectedDataset, setSelectedDataset] = useState('')
  const [mlTestingLoading, setMlTestingLoading] = useState(false)
  const [mlTestingError, setMlTestingError] = useState('')
  const [mlTestResult, setMlTestResult] = useState(null)
  const [mlTestRuns, setMlTestRuns] = useState([])
  const [mlSchemaInfo, setMlSchemaInfo] = useState(null)

  // Wi-Fi Recommendation state
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

  // Recommendation expandable sections
  const [showRankingExplanation, setShowRankingExplanation] = useState(false)
  const [showRunnerUpComparison, setShowRunnerUpComparison] = useState(false)
  const [showModelBreakdown, setShowModelBreakdown] = useState(false)

  // AI Advisor state
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

  // Dashboard Loader
  useEffect(() => {
    if (activeView !== 'Dashboard') return

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
        if (error.name === 'AbortError') return
      }
    }

    loadDashboardData()
    return () => controller.abort()
  }, [activeView])

  // Wi-Fi Scan Initial Loader
  useEffect(() => {
    if (activeView !== 'WiFi Scan') return

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
        if (error.name === 'AbortError') return
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

  // Live Monitor Initial Loader
  useEffect(() => {
    if (activeView !== 'Live Monitor') return

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
        if (error.name === 'AbortError') return
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

  // Live Monitor Polling
  useEffect(() => {
    if (activeView !== 'Live Monitor') return

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

  // Wi-Fi Scan Polling
  useEffect(() => {
    if (activeView !== 'WiFi Scan') return

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

  // ML Engine Initial Loader
  useEffect(() => {
    if (activeView !== 'ML Engine' && activeView !== 'Dashboard') return

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
        if (error.name === 'AbortError') return
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

  // ML Detection Polling
  useEffect(() => {
    if (activeView !== 'ML Engine' && activeView !== 'Dashboard') return

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

  // Incidents Loader
  const loadIncidentsData = async (signal) => {
    setIncidentsLoading(true)
    setIncidentsError('')

    try {
      const payload = await fetchJson('/incidents', signal ? { signal } : undefined)
      setIncidents(normalizeList(payload, 'incidents'))
    } catch (error) {
      if (error?.name === 'AbortError') return
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
    if (activeView !== 'Incidents' && activeView !== 'Dashboard') return
    const controller = new AbortController()
    loadIncidentsData(controller.signal)
    return () => controller.abort()
  }, [activeView])

  // Incidents Polling
  useEffect(() => {
    if (activeView !== 'Incidents' && activeView !== 'Dashboard') return

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

  // Reports Loader
  const loadReportsData = async (signal) => {
    setReportsLoading(true)
    setReportsError('')

    try {
      const payload = await fetchJson('/incidents', { signal })
      setReportIncidents(normalizeList(payload, 'incidents'))
    } catch (error) {
      if (error.name === 'AbortError') return
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
    if (activeView !== 'Reports') return
    const controller = new AbortController()
    loadReportsData(controller.signal)
    return () => controller.abort()
  }, [activeView])

  // PCAP Data Loader
  const loadPcapData = async (signal) => {
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
    }
  }

  useEffect(() => {
    if (activeView !== 'PCAP Analysis') return
    const controller = new AbortController()
    loadPcapData(controller.signal)
    return () => controller.abort()
  }, [activeView])

  // ML Evaluation Loader
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
    if (activeView !== 'ML Engine') return
    const controller = new AbortController()
    loadMlTestingData(controller.signal)
    return () => controller.abort()
  }, [activeView])

  // Recommendations Loader
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
    if (activeView !== 'Network Recommendations') return
    const controller = new AbortController()
    loadRecommendationsData(controller.signal)
    return () => controller.abort()
  }, [activeView])

  // Handlers
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
      setIncidentCopyStatus('success')
      setTimeout(() => setIncidentCopyStatus(null), 2000)
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

  const handleOpenConnectModal = (network) => {
    setConnectModalNetwork(network)
    setConnectPassword('')
    setShowPassword(false)
    setConnectStatus(null)
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
      const runsRes = await fetchJson('/ml/test/runs')
      setMlTestRuns(runsRes?.runs || [])
    } catch (err) {
      setMlTestingError(err.message || 'Model evaluation failed.')
    } finally {
      setMlTestingLoading(false)
    }
  }

  const handleSaveUiPrefs = (updater) => {
    setUiPrefs((prev) => {
      const next = typeof updater === 'function' ? updater(prev) : updater
      try {
        localStorage.setItem('netshield_ui_prefs', JSON.stringify(next))
        setSettingsSaveMsg('Preferences saved to local storage.')
        setTimeout(() => setSettingsSaveMsg(''), 2500)
      } catch {}
      return next
    })
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

    if (scanFilter === '5ghz') return channel >= 36
    if (scanFilter === '2ghz') return channel > 0 && channel <= 14
    if (scanFilter === 'secured') return enc.includes('WPA') || enc.includes('WEP') || enc.includes('802.1X')
    if (scanFilter === 'open') return enc.includes('OPEN') || enc === '' || enc === 'NONE'

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
    if (!reportIncidents || reportIncidents.length === 0) return

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
      if (val === undefined || val === null) return ''
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
    if (startScanDisabled) return
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
    if (stopScanDisabled) return
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
    if (startCaptureDisabled) return
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
    if (stopCaptureDisabled) return
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
      <Sidebar
        activeView={activeView}
        setActiveView={setActiveView}
        isCaptureRunning={isCaptureRunning}
        newIncidentsCount={newIncidents}
      />

      <div className="workspace">
        <Header
          activeView={activeView}
          setActiveView={setActiveView}
          isCaptureRunning={isCaptureRunning}
          isCaptureStarting={isCaptureStarting}
          isCaptureStopping={isCaptureStopping}
          highSeverityIncidents={highSeverityIncidents}
          visualAlerts={uiPrefs.visualAlerts}
          adapterName={monitoringInterface !== 'Not Selected' ? monitoringInterface : null}
        />

        <main className="main-content">
          {activeView === 'Dashboard' && (
            <DashboardView
              isCaptureRunning={isCaptureRunning}
              monitoringInterface={monitoringInterface}
              dashboardKpis={dashboardKpis}
              setActiveView={setActiveView}
              setMlEngineTab={setMlEngineTab}
              mlLiveStatus={mlLiveStatus}
              incidents={incidents}
              newIncidents={newIncidents}
              setSelectedIncident={setSelectedIncident}
            />
          )}

          {activeView === 'WiFi Scan' && (
            <WifiScanView
              wifiScanError={wifiScanError}
              isScannerRunning={isScannerRunning}
              isScannerStarting={isScannerStarting}
              isScannerStopping={isScannerStopping}
              isScannerActive={isScannerActive}
              scannerStatus={scannerStatus}
              selectableInterfaces={selectableInterfaces}
              selectedInterfaceName={selectedInterfaceName}
              setSelectedInterfaceName={setSelectedInterfaceName}
              selectedInterface={selectedInterface}
              wirelessAdapter={wirelessAdapter}
              scannerProgress={scannerProgress}
              networks={networks}
              filteredScanNetworks={filteredScanNetworks}
              startScanDisabled={startScanDisabled}
              stopScanDisabled={stopScanDisabled}
              handleStartScan={handleStartScan}
              handleStopScan={handleStopScan}
              wifiScanLoading={wifiScanLoading}
              scanSearch={scanSearch}
              setScanSearch={setScanSearch}
              scanFilter={scanFilter}
              setScanFilter={setScanFilter}
              setActiveView={setActiveView}
            />
          )}

          {activeView === 'Live Monitor' && (
            <LiveMonitorView
              liveMonitorError={liveMonitorError}
              isCaptureRunning={isCaptureRunning}
              isCaptureStarting={isCaptureStarting}
              isCaptureStopping={isCaptureStopping}
              isCaptureActive={isCaptureActive}
              captureStatus={captureStatus}
              selectableInterfaces={selectableInterfaces}
              selectedCaptureInterfaceName={selectedCaptureInterfaceName}
              setSelectedCaptureInterfaceName={setSelectedCaptureInterfaceName}
              selectedCaptureInterface={selectedCaptureInterface}
              captureAdapter={captureAdapter}
              captureProgress={captureProgress}
              packets={packets}
              startCaptureDisabled={startCaptureDisabled}
              stopCaptureDisabled={stopCaptureDisabled}
              handleStartCapture={handleStartCapture}
              handleStopCapture={handleStopCapture}
              liveMonitorLoading={liveMonitorLoading}
              packetTypeCounts={packetTypeCounts}
              mlLiveStatus={mlLiveStatus}
              setActiveView={setActiveView}
            />
          )}

          {activeView === 'ML Engine' && (
            <MlEngineView
              mlEngineTab={mlEngineTab}
              setMlEngineTab={setMlEngineTab}
              mlLiveStatus={mlLiveStatus}
              mlDetectionLoading={mlDetectionLoading}
              mlDetectionError={mlDetectionError}
              mlDatasets={mlDatasets}
              selectedDataset={selectedDataset}
              setSelectedDataset={setSelectedDataset}
              mlTestingLoading={mlTestingLoading}
              mlTestingError={mlTestingError}
              handleRunMlTest={handleRunMlTest}
              mlTestResult={mlTestResult}
              mlTestRuns={mlTestRuns}
              mlSchemaInfo={mlSchemaInfo}
              setActiveView={setActiveView}
            />
          )}

          {activeView === 'PCAP Analysis' && (
            <PcapAnalysisView
              pcapSamples={pcapSamples}
              selectedPcapSample={selectedPcapSample}
              setSelectedPcapSample={setSelectedPcapSample}
              selectedPcapFile={selectedPcapFile}
              setSelectedPcapFile={setSelectedPcapFile}
              pcapAnalyzing={pcapAnalyzing}
              pcapError={pcapError}
              pcapResult={pcapResult}
              pcapHistory={pcapHistory}
              pcapFilter={pcapFilter}
              setPcapFilter={setPcapFilter}
              pcapTab={pcapTab}
              setPcapTab={setPcapTab}
              handlePcapAnalyze={handlePcapAnalyze}
              apiBaseUrl={API_BASE_URL}
            />
          )}

          {activeView === 'Network Recommendations' && (
            <RecommendationsView
              recommendationsData={recommendationsData}
              recommendationsLoading={recommendationsLoading}
              recommendationsError={recommendationsError}
              loadRecommendationsData={loadRecommendationsData}
              recommendationFilter={recommendationFilter}
              setRecommendationFilter={setRecommendationFilter}
              recommendationSort={recommendationSort}
              setRecommendationSort={setRecommendationSort}
              filteredRecommendations={filteredRecommendations}
              bestNetwork={bestNetwork}
              recList={recList}
              totalScannedRecs={totalScannedRecs}
              handleOpenConnectModal={handleOpenConnectModal}
              advisorOpen={advisorOpen}
              setAdvisorOpen={setAdvisorOpen}
              showRankingExplanation={showRankingExplanation}
              setShowRankingExplanation={setShowRankingExplanation}
              showRunnerUpComparison={showRunnerUpComparison}
              setShowRunnerUpComparison={setShowRunnerUpComparison}
              showModelBreakdown={showModelBreakdown}
              setShowModelBreakdown={setShowModelBreakdown}
              recommendationModelInfo={recommendationModelInfo}
              setActiveView={setActiveView}
            />
          )}

          {activeView === 'Incidents' && (
            <IncidentsView
              incidents={incidents}
              totalIncidents={totalIncidents}
              newIncidents={newIncidents}
              highSeverityIncidents={highSeverityIncidents}
              avgAttackProb={avgAttackProb}
              incidentsLoading={incidentsLoading}
              incidentsError={incidentsError}
              loadIncidentsData={loadIncidentsData}
              incidentSearch={incidentSearch}
              setIncidentSearch={setIncidentSearch}
              incidentSeverityFilter={incidentSeverityFilter}
              setIncidentSeverityFilter={setIncidentSeverityFilter}
              incidentStatusFilter={incidentStatusFilter}
              setIncidentStatusFilter={setIncidentStatusFilter}
              filteredIncidents={filteredIncidents}
              setSelectedIncident={setSelectedIncident}
              setActiveView={setActiveView}
            />
          )}

          {activeView === 'Reports' && (
            <ReportsView
              reportsError={reportsError}
              reportsLoading={reportsLoading}
              handleRefreshReports={handleRefreshReports}
              handleExportCsv={handleExportCsv}
              reportTotalIncidents={reportTotalIncidents}
              reportHighSeverity={reportHighSeverity}
              reportTotalPackets={reportTotalPackets}
              reportAvgAttackProb={reportAvgAttackProb}
              attackCountsByLabel={attackCountsByLabel}
              reportIncidents={reportIncidents}
              apiBaseUrl={API_BASE_URL}
            />
          )}

          {activeView === 'Settings' && (
            <SettingsView
              settingsTab={settingsTab}
              setSettingsTab={setSettingsTab}
              uiPrefs={uiPrefs}
              setUiPrefs={handleSaveUiPrefs}
              settingsSaveMsg={settingsSaveMsg}
              diagnosticsLoading={diagnosticsLoading}
              diagnosticsResult={diagnosticsResult}
              handleRunDiagnostics={handleRunDiagnostics}
              interfaces={interfaces}
              adapterState={adapterState}
              mlSchemaInfo={mlSchemaInfo}
              recommendationModelInfo={recommendationModelInfo}
              apiBaseUrl={API_BASE_URL}
            />
          )}
        </main>

        {/* Global Overlays & Modals */}
        <IncidentDrawer
          selectedIncident={selectedIncident}
          setSelectedIncident={setSelectedIncident}
          incidentCopyStatus={incidentCopyStatus}
          handleCopyIncidentJson={handleCopyIncidentJson}
          incidentJsonExpanded={incidentJsonExpanded}
          setIncidentJsonExpanded={setIncidentJsonExpanded}
          handleUpdateIncidentStatus={handleUpdateIncidentStatus}
          setActiveView={setActiveView}
          setMlEngineTab={setMlEngineTab}
        />

        <ConnectModal
          connectModalNetwork={connectModalNetwork}
          handleCloseConnectModal={handleCloseConnectModal}
          connectLoading={connectLoading}
          connectStatus={connectStatus}
          handleConnectSubmit={handleConnectSubmit}
          connectPassword={connectPassword}
          setConnectPassword={setConnectPassword}
          showPassword={showPassword}
          setShowPassword={setShowPassword}
        />

        <AdvisorDrawer
          advisorOpen={advisorOpen}
          setAdvisorOpen={setAdvisorOpen}
          advisorMessages={advisorMessages}
          handleSendAdvisorMessage={handleSendAdvisorMessage}
          advisorInput={advisorInput}
          setAdvisorInput={setAdvisorInput}
        />
      </div>
    </div>
  )
}

export default App
