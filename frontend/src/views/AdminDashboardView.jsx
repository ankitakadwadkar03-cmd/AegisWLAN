import React from 'react'
import {
  formatProbability,
  formatDateTime,
  getSeverityBadgeClass,
  getStatusBadgeClass,
  getRecommendationBadgeClass,
} from '../utils/helpers'
import {
  IconDashboard,
  IconWifi,
  IconActivity,
  IconCpu,
  IconFileSearch,
  IconStar,
  IconShieldAlert,
  IconReports,
  IconPlay,
  IconSquare,
  IconChevronRight,
  IconInfo,
  IconBot,
} from '../components/Icons'

export const AdminDashboardView = ({
  networks = [],
  wifiScanLoading = false,
  wifiScanError = null,
  isScannerRunning = false,
  scannerProgress = {},
  _packets = [],
  isCaptureRunning = false,
  captureProgress = {},
  liveMonitorError = null,
  mlLiveStatus = null,
  incidents = [],
  incidentsLoading = false,
  incidentsError = null,
  _totalIncidents,
  newIncidents: _newIncidents,
  highSeverityIncidents: _highSeverityIncidents,
  _recommendationsData = null,
  bestNetwork = null,
  setActiveView,
  handleStartScan,
  handleStopScan,
  handleStartCapture,
  handleStopCapture,
  setSelectedIncident,
  handleOpenWhyDrawer,
  monitoringInterface = null,
  setAdvisorOpen = null,
}) => {
  // 1. Wi-Fi Frequency & Encryption Classification
  const hasNetworksData = Array.isArray(networks) && networks.length > 0
  let band24Count = 0
  let band5Count = 0
  let band6Count = 0
  let bandUnknownCount = 0

  let wpa3Count = 0
  let wpa2Count = 0
  let legacyEncCount = 0
  let openEncCount = 0
  let unknownEncCount = 0

  if (hasNetworksData) {
    networks.forEach((net) => {
      // Frequency classification:
      // - Prefer known frequency values over channel numbers.
      // - Use channel-based fallback ONLY when frequency field is genuinely absent or empty.
      // - If frequency is present but invalid or unsupported, classify as Unclassified Band.
      // - Preserve 6 GHz channel-overlap protection (e.g. 6 GHz Ch 1 at 5955 MHz is never 2.4 GHz).
      const rawFreqField =
        net.frequency !== undefined && net.frequency !== null
          ? net.frequency
          : net.Frequency !== undefined && net.Frequency !== null
            ? net.Frequency
            : null

      const freqStr = rawFreqField != null ? String(rawFreqField).trim() : ''
      const isFreqAbsent = freqStr === ''
      const chanRaw = parseInt(net.channel || net.Channel || 0, 10)

      let detectedBand = 'unknown'

      if (!isFreqAbsent) {
        // Frequency field is present: evaluate frequency value strictly without channel fallback
        let freqNum = NaN
        const freqMatch = freqStr.match(/(\d+(?:\.\d+)?)/)
        if (freqMatch) {
          const parsed = parseFloat(freqMatch[1])
          if (parsed > 0 && parsed < 10) {
            // Provided in GHz (e.g. 2.4, 5.18, 5.95)
            freqNum = Math.round(parsed * 1000)
          } else if (parsed >= 100) {
            // Provided in MHz (e.g. 2412, 5180, 5955)
            freqNum = Math.round(parsed)
          }
        }

        if (!isNaN(freqNum) && freqNum > 0) {
          if (freqNum >= 2400 && freqNum <= 2500) {
            detectedBand = '2.4'
          } else if (freqNum >= 4900 && freqNum <= 5895) {
            detectedBand = '5'
          } else if (freqNum >= 5925 && freqNum <= 7125) {
            detectedBand = '6'
          } else {
            // Frequency is present but outside supported bands -> Unclassified Band
            detectedBand = 'unknown'
          }
        } else {
          // Frequency is present but invalid string -> Unclassified Band
          detectedBand = 'unknown'
        }
      } else {
        // Frequency field is genuinely absent or empty: use channel-based classification
        if (!isNaN(chanRaw) && chanRaw > 0) {
          if (chanRaw >= 1 && chanRaw <= 14) {
            detectedBand = '2.4'
          } else if ((chanRaw >= 32 && chanRaw <= 177) || (chanRaw >= 180 && chanRaw <= 196)) {
            detectedBand = '5'
          }
        }
      }

      // Step 3: Increment frequency band bucket
      if (detectedBand === '2.4') {
        band24Count += 1
      } else if (detectedBand === '5') {
        band5Count += 1
      } else if (detectedBand === '6') {
        band6Count += 1
      } else {
        bandUnknownCount += 1
      }

      // Encryption classification: count confirmed WPA3 and WPA2 separately,
      // distinguish open, legacy/other, and unknown. Never label unknown as secure.
      const rawEnc = String(net.encryption || net.security || net.Encryption || '').trim()
      const encUpper = rawEnc.toUpperCase()

      if (!rawEnc || encUpper === 'UNKNOWN' || encUpper === 'N/A' || encUpper === '?') {
        unknownEncCount += 1
      } else if (
        encUpper === 'OPEN' ||
        encUpper === 'NONE' ||
        encUpper.includes('OPEN') ||
        encUpper === 'UNENCRYPTED'
      ) {
        openEncCount += 1
      } else if (encUpper.includes('WPA3')) {
        wpa3Count += 1
      } else if (encUpper.includes('WPA2')) {
        wpa2Count += 1
      } else if (
        encUpper.includes('WEP') ||
        encUpper.includes('WPA') ||
        encUpper.includes('TKIP') ||
        encUpper.includes('WPS')
      ) {
        legacyEncCount += 1
      } else {
        unknownEncCount += 1
      }
    })
  }

  // 2. Derive AWID3 Live State
  const hasLiveInference =
    mlLiveStatus &&
    mlLiveStatus.status !== 'no_inference' &&
    mlLiveStatus.prediction !== undefined

  // 3. Security Status Accuracy
  // - Distinguish total high-severity incidents from unresolved high-severity incidents.
  // - An unresolved incident has status 'New' or 'Investigating' (case-insensitive).
  // - Any unresolved incident (high, medium, low) qualifies for Guarded state.
  // - High-Severity Alerts status is reserved for unresolved high-severity incidents.
  // - Resolved incidents must NOT cause active High-Severity Alerts or Guarded status.
  // - Keep recorded alert count as the total number of incidents.
  // - Do not use fallback counters to claim a verified security posture when incident data is unavailable.
  const hasIncidentData = Array.isArray(incidents)

  let totalIncidentsCount = 0
  let totalHighSeverityCount = 0
  let unresolvedHighSeverityCount = 0
  let unresolvedNewCount = 0
  let unresolvedIncidentCount = 0

  if (hasIncidentData) {
    totalIncidentsCount = incidents.length
    incidents.forEach((inc) => {
      const statusUpper = String(inc.status || '').trim().toUpperCase()
      const isUnresolved = statusUpper === 'NEW' || statusUpper === 'INVESTIGATING'
      const severityUpper = String(inc.severity || '').trim().toUpperCase()
      const isHigh = severityUpper === 'HIGH' || severityUpper === 'CRITICAL'

      if (isUnresolved) {
        unresolvedIncidentCount += 1
      }

      if (isHigh) {
        totalHighSeverityCount += 1
        if (isUnresolved) {
          unresolvedHighSeverityCount += 1
        }
      }

      if (statusUpper === 'NEW') {
        unresolvedNewCount += 1
      }
    })
  }

  let securityState = {
    key: 'NO_ALERTS',
    badgeText: 'Status: No Recorded Alerts',
    badgeClass: 'badge-status-resolved',
    desc: 'No active intrusion alerts recorded in the database. Active traffic monitoring is required to detect ongoing attacks.',
  }

  // Security-state priority: Loading -> Unknown -> High-Severity Alerts -> Guarded -> No Recorded Alerts
  if (incidentsLoading && (!hasIncidentData || incidents.length === 0)) {
    securityState = {
      key: 'LOADING',
      badgeText: 'Status: Checking Alerts...',
      badgeClass: 'badge-default',
      desc: 'Retrieving security incident history from the local database...',
    }
  } else if (incidentsError || !hasIncidentData) {
    securityState = {
      key: 'UNKNOWN',
      badgeText: 'Status: Unknown (Data Unavailable)',
      badgeClass: 'badge-default',
      desc: incidentsError
        ? `Incident database unavailable: ${incidentsError}`
        : 'Incident records could not be retrieved. Current security status cannot be verified.',
    }
  } else if (unresolvedHighSeverityCount > 0) {
    securityState = {
      key: 'HIGH_ALERTS',
      badgeText: `Status: High-Severity Alerts (${unresolvedHighSeverityCount})`,
      badgeClass: 'badge-severity-high',
      desc: `${unresolvedHighSeverityCount} unresolved high-severity alert${unresolvedHighSeverityCount > 1 ? 's' : ''} require immediate investigation.`,
    }
  } else if (unresolvedIncidentCount > 0) {
    securityState = {
      key: 'GUARDED',
      badgeText: `Status: Guarded (${unresolvedIncidentCount} Unresolved Alert${unresolvedIncidentCount === 1 ? '' : 's'})`,
      badgeClass: 'badge-severity-medium',
      desc: `${unresolvedIncidentCount} unresolved alert${unresolvedIncidentCount === 1 ? '' : 's'} logged (New or Investigating). Review recommended.`,
    }
  } else {
    securityState = {
      key: 'NO_ALERTS',
      badgeText: 'Status: No Recorded Alerts',
      badgeClass: 'badge-status-resolved',
      desc: 'No active intrusion alerts recorded in the database. Active traffic monitoring is required to detect ongoing attacks.',
    }
  }

  return (
    <div className="admin-dashboard-view" aria-label="Admin Security Dashboard">
      {/* Top Threat & Hardware Defense Status Banner */}
      <section className="panel dashboard-hero-banner">
        <div className="hero-banner-main">
          <div className="hero-status-pill-group">
            <span className="hero-brand-tag">
              <IconDashboard size={14} />
              <span>NetShield Security Dashboard</span>
            </span>
            <span className={`badge ${securityState.badgeClass}`}>
              {securityState.badgeText}
            </span>
            <span className="badge badge-default">
              Interface: {monitoringInterface || 'wlan0 (Standby)'}
            </span>
          </div>

          <h2 className="hero-dashboard-title">Wireless Security &amp; Network Health</h2>
          <p className="hero-dashboard-desc">
            Real-time monitoring of nearby Wi-Fi networks, automated threat detection, and connection quality ratings.
          </p>
        </div>

        <div className="hero-banner-quick-actions">
          <div className="hero-action-buttons">
            <button
              type="button"
              className={`btn ${isScannerRunning ? 'btn-secondary' : 'btn-primary'}`}
              onClick={isScannerRunning ? handleStopScan : handleStartScan}
            >
              {isScannerRunning ? <IconSquare size={14} /> : <IconPlay size={14} />}
              <span>{isScannerRunning ? 'Stop Scan' : 'Scan Nearby Networks'}</span>
            </button>

            <button
              type="button"
              className={`btn ${isCaptureRunning ? 'btn-secondary' : 'btn-primary'}`}
              onClick={isCaptureRunning ? handleStopCapture : handleStartCapture}
            >
              {isCaptureRunning ? <IconSquare size={14} /> : <IconActivity size={14} />}
              <span>{isCaptureRunning ? 'Stop Monitor' : 'Start Live Monitor'}</span>
            </button>

            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setAdvisorOpen && setAdvisorOpen(true)}
              title="Open NetShield Security Advisor"
            >
              <IconBot size={14} />
              <span>Ask Security Advisor</span>
            </button>
          </div>
        </div>
      </section>

      {/* 4 Core KPI Telemetry Cards */}
      <div className="dashboard-kpi-grid">
        {/* KPI 1: Nearby Networks */}
        <article className="telemetry-card">
          <div className="telemetry-card-header">
            <span className="telemetry-card-label">NEARBY NETWORKS</span>
            <span className="telemetry-icon-wrap" style={{ color: 'var(--accent)' }}>
              <IconWifi size={18} />
            </span>
          </div>
          <strong className="telemetry-card-val">
            {wifiScanError
              ? 'Unavailable'
              : wifiScanLoading && !networks.length
                ? 'Scanning...'
                : hasNetworksData
                  ? networks.length
                  : Array.isArray(networks)
                    ? 0
                    : 'Unavailable'}
          </strong>
          <span className="telemetry-card-sub">
            {isScannerRunning
              ? `Scanning channel ${scannerProgress?.current_channel || '--'}`
              : hasNetworksData
                ? `${networks.length} networks detected`
                : 'Scanner inactive'}
          </span>
        </article>

        {/* KPI 2: Live Traffic */}
        <article className="telemetry-card">
          <div className="telemetry-card-header">
            <span className="telemetry-card-label">LIVE TRAFFIC</span>
            <span className="telemetry-icon-wrap" style={{ color: 'var(--cyan)' }}>
              <IconActivity size={18} />
            </span>
          </div>
          <strong className="telemetry-card-val" style={{ color: isCaptureRunning ? 'var(--cyan)' : 'inherit' }}>
            {liveMonitorError
              ? 'Unavailable'
              : isCaptureRunning
                ? `${captureProgress?.packet_rate ?? 0} pkt/s`
                : (captureProgress?.packet_count || 0) > 0
                  ? `${captureProgress.packet_count.toLocaleString()} pkts`
                  : 'Inactive'}
          </strong>
          <span className="telemetry-card-sub">
            {isCaptureRunning
              ? `${captureProgress?.packet_count?.toLocaleString() || 0} packets captured`
              : 'Traffic monitor not running'}
          </span>
        </article>

        {/* KPI 3: Threat Detection (ML) */}
        <article className="telemetry-card">
          <div className="telemetry-card-header">
            <span className="telemetry-card-label">THREAT DETECTION (ML)</span>
            <span className="telemetry-icon-wrap" style={{ color: 'var(--accent)' }}>
              <IconCpu size={18} />
            </span>
          </div>
          <strong
            className="telemetry-card-val"
            style={{
              fontSize: hasLiveInference ? '17px' : '15px',
              color: hasLiveInference
                ? mlLiveStatus.prediction === 0
                  ? 'var(--success-text)'
                  : 'var(--danger-text)'
                : 'inherit',
            }}
          >
            {hasLiveInference
              ? mlLiveStatus.prediction === 0
                ? 'Latest Result: Normal'
                : 'Latest Result: Threat Detected'
              : 'Waiting for Traffic Data'}
          </strong>
          <span className="telemetry-card-sub">
            {hasLiveInference
              ? `Latest window${mlLiveStatus.label && mlLiveStatus.prediction !== 0 ? ` (${mlLiveStatus.label})` : ''}: Normal ${formatProbability(mlLiveStatus.normal_probability)} • Threat ${formatProbability(mlLiveStatus.attack_probability)}`
              : 'Evaluates latest analyzed traffic window, not the entire environment'}
          </span>
        </article>

        {/* KPI 4: Recorded Alerts */}
        <article
          className="telemetry-card"
          style={{
            borderTop:
              unresolvedHighSeverityCount > 0
                ? '3px solid var(--danger)'
                : unresolvedIncidentCount > 0
                  ? '3px solid var(--warning)'
                  : '3px solid var(--border)',
          }}
        >
          <div className="telemetry-card-header">
            <span className="telemetry-card-label">RECORDED ALERTS</span>
            <span
              className="telemetry-icon-wrap"
              style={{
                color:
                  unresolvedHighSeverityCount > 0
                    ? 'var(--danger)'
                    : unresolvedIncidentCount > 0
                      ? 'var(--warning)'
                      : 'var(--text-muted)',
              }}
            >
              <IconShieldAlert size={18} />
            </span>
          </div>
          <strong
            className="telemetry-card-val"
            style={{
              color:
                unresolvedHighSeverityCount > 0
                  ? 'var(--danger-text)'
                  : unresolvedIncidentCount > 0
                    ? 'var(--warning-text)'
                    : 'inherit',
            }}
          >
            {incidentsError
              ? 'Unavailable'
              : incidentsLoading && !incidents.length
                ? 'Loading...'
                : hasIncidentData
                  ? totalIncidentsCount
                  : 'Unavailable'}
          </strong>
          <span className="telemetry-card-sub">
            {incidentsLoading && !incidents.length
              ? 'Loading alert history...'
              : incidentsError
                ? 'Alert database unavailable'
                : hasIncidentData
                  ? totalIncidentsCount === 0
                    ? 'No alerts recorded in database'
                    : `${unresolvedHighSeverityCount} unresolved high • ${unresolvedNewCount} new (${totalIncidentsCount} total)`
                  : 'Alert database unavailable'}
          </span>
        </article>
      </div>

      {/* Two Column Command & Analytics Layout */}
      <div className="dashboard-content-grid">
        {/* Left Column: Frequency & Security Breakdown + Tools Matrix */}
        <div className="dashboard-column">
          {/* Frequency & Security Breakdown Card */}
          <section className="panel dashboard-card">
            <div className="panel-header">
              <div>
                <h3 className="section-title">Wi-Fi Frequency &amp; Security Breakdown</h3>
                <p className="panel-subtitle">Distribution across frequency bands and encryption standards</p>
              </div>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => setActiveView('WiFi Scan')}
              >
                Detailed Scan View &rarr;
              </button>
            </div>

            {hasNetworksData ? (
              <div className="spectrum-groups-container">
                {/* Group 1: Frequency Bands */}
                <div className="spectrum-group">
                  <div className="spectrum-group-label">Frequency Bands</div>
                  <div className="spectrum-summary-grid">
                    <div className="spectrum-stat-box">
                      <span className="spectrum-stat-num">{band24Count}</span>
                      <span className="spectrum-stat-title">2.4 GHz Band</span>
                      <span className="spectrum-stat-desc">Standard range (Ch 1–14)</span>
                    </div>

                    <div className="spectrum-stat-box">
                      <span className="spectrum-stat-num">{band5Count}</span>
                      <span className="spectrum-stat-title">5 GHz Band</span>
                      <span className="spectrum-stat-desc">High speed (Ch 32–177)</span>
                    </div>

                    <div className="spectrum-stat-box">
                      <span className="spectrum-stat-num">{band6Count}</span>
                      <span className="spectrum-stat-title">6 GHz Band</span>
                      <span className="spectrum-stat-desc">Wi-Fi 6E / 7</span>
                    </div>

                    <div className="spectrum-stat-box">
                      <span
                        className="spectrum-stat-num"
                        style={{ color: bandUnknownCount > 0 ? 'var(--text-muted)' : 'inherit' }}
                      >
                        {bandUnknownCount}
                      </span>
                      <span className="spectrum-stat-title">Unclassified Band</span>
                      <span className="spectrum-stat-desc">
                        {bandUnknownCount > 0 ? 'Frequency unavailable' : 'All bands identified'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Group 2: Encryption & Security */}
                <div className="spectrum-group">
                  <div className="spectrum-group-label">Encryption &amp; Security</div>
                  <div className="spectrum-summary-grid">
                    <div className="spectrum-stat-box">
                      <span className="spectrum-stat-num" style={{ color: 'var(--success-text)' }}>
                        {wpa3Count}
                      </span>
                      <span className="spectrum-stat-title">WPA3 (Modern)</span>
                      <span className="spectrum-stat-desc">Strongest SAE security</span>
                    </div>

                    <div className="spectrum-stat-box">
                      <span className="spectrum-stat-num">{wpa2Count}</span>
                      <span className="spectrum-stat-title">WPA2 (Standard)</span>
                      <span className="spectrum-stat-desc">Standard AES encryption</span>
                    </div>

                    <div className="spectrum-stat-box">
                      <span
                        className="spectrum-stat-num"
                        style={{ color: openEncCount > 0 ? 'var(--danger-text)' : 'inherit' }}
                      >
                        {openEncCount}
                      </span>
                      <span className="spectrum-stat-title">Open (None)</span>
                      <span className="spectrum-stat-desc">
                        {openEncCount > 0 ? 'Unencrypted / No password' : 'No open networks'}
                      </span>
                    </div>

                    <div className="spectrum-stat-box">
                      <span
                        className="spectrum-stat-num"
                        style={{
                          color:
                            legacyEncCount > 0 || unknownEncCount > 0
                              ? 'var(--warning-text)'
                              : 'inherit',
                        }}
                      >
                        {legacyEncCount + unknownEncCount}
                      </span>
                      <span className="spectrum-stat-title">Legacy / Unknown</span>
                      <span className="spectrum-stat-desc">
                        {legacyEncCount > 0 ? `${legacyEncCount} legacy` : ''}
                        {legacyEncCount > 0 && unknownEncCount > 0 ? ' • ' : ''}
                        {unknownEncCount > 0 ? `${unknownEncCount} unclassified` : ''}
                        {legacyEncCount === 0 && unknownEncCount === 0 ? 'None detected' : ''}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="dashboard-empty-banner">
                <IconInfo size={16} />
                <span>
                  {wifiScanError
                    ? `Network data unavailable: ${wifiScanError}`
                    : 'No networks discovered yet. Run a network scan to view frequency bands and encryption types.'}
                </span>
              </div>
            )}
          </section>

          {/* Quick Tools & Navigation Matrix */}
          <section className="panel dashboard-card">
            <div className="panel-header">
              <div>
                <h3 className="section-title">Tools &amp; Navigation</h3>
                <p className="panel-subtitle">Quick access to network scanning, monitoring, and reports</p>
              </div>
            </div>

            <div className="quick-actions-matrix">
              <button
                type="button"
                className="quick-action-item"
                onClick={() => setActiveView('WiFi Scan')}
              >
                <div className="action-icon-wrap" style={{ color: 'var(--accent)' }}>
                  <IconWifi size={20} />
                </div>
                <div className="action-text-group">
                  <span className="action-title">Network Scanner</span>
                  <span className="action-desc">Scan nearby Wi-Fi networks and view signal details</span>
                </div>
                <IconChevronRight size={16} className="action-arrow" />
              </button>

              <button
                type="button"
                className="quick-action-item"
                onClick={() => setActiveView('Live Monitor')}
              >
                <div className="action-icon-wrap" style={{ color: 'var(--cyan)' }}>
                  <IconActivity size={20} />
                </div>
                <div className="action-text-group">
                  <span className="action-title">Live Traffic Monitor</span>
                  <span className="action-desc">Monitor live Wi-Fi packets and connection traffic</span>
                </div>
                <IconChevronRight size={16} className="action-arrow" />
              </button>

              <button
                type="button"
                className="quick-action-item"
                onClick={() => setActiveView('ML Engine')}
              >
                <div className="action-icon-wrap" style={{ color: 'var(--accent)' }}>
                  <IconCpu size={20} />
                </div>
                <div className="action-text-group">
                  <span className="action-title">Threat Detector</span>
                  <span className="action-desc">Review machine-learning intrusion detection results</span>
                </div>
                <IconChevronRight size={16} className="action-arrow" />
              </button>

              <button
                type="button"
                className="quick-action-item"
                onClick={() => setActiveView('PCAP Analysis')}
              >
                <div className="action-icon-wrap" style={{ color: 'var(--text-muted)' }}>
                  <IconFileSearch size={20} />
                </div>
                <div className="action-text-group">
                  <span className="action-title">Packet File Analysis</span>
                  <span className="action-desc">Upload and inspect saved packet capture (PCAP) files</span>
                </div>
                <IconChevronRight size={16} className="action-arrow" />
              </button>

              <button
                type="button"
                className="quick-action-item"
                onClick={() => setActiveView('Reports')}
              >
                <div className="action-icon-wrap" style={{ color: 'var(--text-muted)' }}>
                  <IconReports size={20} />
                </div>
                <div className="action-text-group">
                  <span className="action-title">Security Reports</span>
                  <span className="action-desc">Export incident summaries in CSV or PDF format</span>
                </div>
                <IconChevronRight size={16} className="action-arrow" />
              </button>
            </div>
          </section>
        </div>

        {/* Right Column: Connection Quality Recommendations & Recent Alerts */}
        <div className="dashboard-column">
          {/* Top Recommended Access Point Snippet */}
          {bestNetwork ? (
            <section className="panel dashboard-card top-rec-snippet-card">
              <div className="panel-header">
                <div>
                  <span className="hero-rank-tag">
                    <IconStar size={13} />
                    <span>#1 RECOMMENDED NETWORK</span>
                  </span>
                  <h3 className="section-title" style={{ marginTop: '6px' }}>
                    {bestNetwork.ssid || '<Hidden SSID>'}
                  </h3>
                  <span className="mono-val" style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                    BSSID: {bestNetwork.bssid} • Vendor: {bestNetwork.vendor || 'Unknown'}
                  </span>
                </div>
                <span className={getRecommendationBadgeClass(bestNetwork.classification)}>
                  {bestNetwork.classification} Quality Tier
                </span>
              </div>

              <div className="top-rec-meta-row">
                <span className="scan-meta-pill">
                  Quality Score: <strong>{bestNetwork.score?.toFixed(1) || '--'}</strong>/100
                </span>
                <span className="scan-meta-pill">
                  Channel: <strong>{bestNetwork.channel || '--'}</strong>
                </span>
                <span className="scan-meta-pill">
                  Security: <strong>{bestNetwork.encryption || 'Open'}</strong>
                </span>
                <span className="scan-meta-pill">
                  Signal: <strong>{bestNetwork.signal || '--'} dBm</strong>
                </span>
              </div>

              <div className="top-rec-action-row">
                {handleOpenWhyDrawer && (
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={() => handleOpenWhyDrawer(bestNetwork)}
                  >
                    <span>Explain Quality Rating</span>
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={() => setActiveView('Network Recommendations')}
                >
                  <span>All Quality Ratings &rarr;</span>
                </button>
              </div>
            </section>
          ) : (
            <section className="panel dashboard-card">
              <div className="panel-header">
                <div>
                  <h3 className="section-title">Wi-Fi Connection Quality</h3>
                  <p className="panel-subtitle">
                    12-factor connection-quality ranking model categorizing networks into EXCELLENT, GOOD, FAIR, and POOR tiers
                  </p>
                </div>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  onClick={() => setActiveView('Network Recommendations')}
                >
                  View Quality Tiers &rarr;
                </button>
              </div>
              <div className="dashboard-empty-banner">
                <IconInfo size={16} />
                <span>
                  No network quality ratings loaded yet. Run a network scan to rank nearby connections by signal strength, security, and channel health.
                </span>
              </div>
            </section>
          )}

          {/* Recent Security Alerts Feed */}
          <section className="panel dashboard-card">
            <div className="panel-header">
              <div>
                <h3 className="section-title">Recent Security Alerts</h3>
                <p className="panel-subtitle">Latest intrusion alerts recorded by the detection engine</p>
              </div>
              <button
                type="button"
                className="btn btn-sm btn-secondary"
                onClick={() => setActiveView('Incidents')}
              >
                All Alerts ({hasIncidentData ? totalIncidentsCount : 0}) &rarr;
              </button>
            </div>

            {incidentsLoading && (!hasIncidentData || incidents.length === 0) ? (
              <div className="dashboard-empty-banner">
                <IconActivity size={16} />
                <span>Loading recorded security alerts...</span>
              </div>
            ) : incidentsError ? (
              <div className="dashboard-empty-banner error">
                <IconShieldAlert size={16} />
                <span>Security alerts unavailable: {incidentsError}. Check backend connection.</span>
              </div>
            ) : incidents.length > 0 ? (
              <div className="dashboard-threats-list">
                {incidents.slice(0, 5).map((inc) => (
                  <div key={inc.id} className="threat-item-row">
                    <div className="threat-info-group">
                      <div className="threat-title-line">
                        <span className={getSeverityBadgeClass(inc.severity)}>
                          {inc.severity}
                        </span>
                        <strong className="threat-label">
                          {inc.label || 'Intrusion Alert'}
                        </strong>
                        <span className="mono-val" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          #{inc.id}
                        </span>
                      </div>
                      <span className="threat-timestamp">
                        {formatDateTime(inc.created_at)} • Threat Prob: {formatProbability(inc.attack_probability)}
                      </span>
                    </div>

                    <div className="threat-actions-group">
                      <span className={getStatusBadgeClass(inc.status)}>
                        {inc.status || 'New'}
                      </span>
                      <button
                        type="button"
                        className="btn btn-sm btn-secondary"
                        onClick={() => setSelectedIncident(inc)}
                        title="Open Incident Details"
                      >
                        Review
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="dashboard-empty-banner clean">
                <IconShieldAlert size={16} style={{ color: 'var(--success-text)' }} />
                <span>No security alerts recorded in the database. Active live capture is required to detect ongoing attacks.</span>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  )
}
