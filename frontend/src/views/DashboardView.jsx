import React from 'react'
import {
  formatValue,
  formatProbability,
  formatDateTime,
  getSeverityBadgeClass,
  getStatusBadgeClass,
} from '../utils/helpers'
import {
  IconWifi,
  IconActivity,
  IconCpu,
  IconFileSearch,
  IconShieldAlert,
} from '../components/Icons'

export const DashboardView = ({
  isCaptureRunning,
  monitoringInterface,
  dashboardKpis,
  setActiveView,
  setMlEngineTab,
  mlLiveStatus,
  incidents,
  newIncidents,
  setSelectedIncident,
}) => {
  // Build a simple threat activity chart from real incidents (up to last 10)
  const recentIncidentsForChart = incidents.slice(0, 10).reverse()
  const hasChartData = recentIncidentsForChart.length > 0

  return (
    <section className="dashboard-view" aria-label="Dashboard overview">
      {/* System Status Hero Banner */}
      <div className="panel dashboard-hero-panel">
        <div className="hero-content-left">
          <div className="hero-status-pill-row">
            <span className={`status-pill ${isCaptureRunning ? 'active' : 'idle'}`}>
              <span className={`status-dot ${isCaptureRunning ? 'active' : ''}`} />
              {isCaptureRunning ? 'Live Capture Streaming' : 'System Ready (Standby)'}
            </span>
            <span className="hero-meta-badge">
              Model: <strong>AWID3 Random Forest (31 Features)</strong>
            </span>
            <span className="hero-meta-badge">
              Adapter: <strong>{monitoringInterface || 'No Adapter'}</strong>
            </span>
          </div>

          <h2 className="hero-title">NetShield Wi-Fi Security Dashboard</h2>
          <p className="hero-description">
            Real-time IEEE 802.11 intrusion detection, passive packet capture, and machine-learning threat classification for wireless networks.
          </p>
        </div>

        <div className="hero-actions-right">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setActiveView('Live Monitor')}
          >
            <IconActivity size={16} />
            <span>{isCaptureRunning ? 'View Live Monitor' : 'Start Capture'}</span>
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setActiveView('WiFi Scan')}
          >
            <IconWifi size={16} />
            <span>Scan Networks</span>
          </button>
        </div>
      </div>

      {/* 4 Primary KPI Metric Cards */}
      <div className="dashboard-kpi-grid">
        {dashboardKpis.map((kpi) => (
          <article className="dashboard-kpi-card" key={kpi.label}>
            <div className="kpi-card-header">
              <span className="dashboard-kpi-label">{kpi.label}</span>
            </div>
            <div className="kpi-card-body">
              <strong
                className="dashboard-kpi-val"
                style={{ color: kpi.valColor || 'var(--text-strong)' }}
              >
                {kpi.value}
              </strong>
              <span className="dashboard-kpi-sub">{kpi.sub}</span>
            </div>
          </article>
        ))}
      </div>

      {/* Quick Action Navigation Bar */}
      <div className="quick-actions-bar">
        <span className="quick-actions-title">Quick Actions</span>
        <div className="quick-actions-grid">
          <button
            type="button"
            className="quick-action-btn"
            onClick={() => setActiveView('WiFi Scan')}
          >
            <span className="quick-action-icon">
              <IconWifi size={16} />
            </span>
            <span>Scan Wi-Fi</span>
          </button>

          <button
            type="button"
            className="quick-action-btn"
            onClick={() => setActiveView('Live Monitor')}
          >
            <span className="quick-action-icon">
              <IconActivity size={16} />
            </span>
            <span>Live Monitor</span>
            {isCaptureRunning ? <span className="live-pulse-dot" /> : null}
          </button>

          <button
            type="button"
            className="quick-action-btn"
            onClick={() => {
              setActiveView('ML Engine')
              setMlEngineTab('live')
            }}
          >
            <span className="quick-action-icon">
              <IconCpu size={16} />
            </span>
            <span>ML Engine</span>
          </button>

          <button
            type="button"
            className="quick-action-btn"
            onClick={() => setActiveView('PCAP Analysis')}
          >
            <span className="quick-action-icon">
              <IconFileSearch size={16} />
            </span>
            <span>PCAP Analysis</span>
          </button>

          <button
            type="button"
            className="quick-action-btn"
            onClick={() => setActiveView('Incidents')}
          >
            <span className="quick-action-icon">
              <IconShieldAlert size={16} />
            </span>
            <span>Security Incidents</span>
            {newIncidents > 0 ? (
              <span className="badge badge-severity-high" style={{ padding: '2px 6px', fontSize: '11px' }}>
                {newIncidents}
              </span>
            ) : null}
          </button>
        </div>
      </div>

      {/* Threat Activity Chart Section (if incidents exist) */}
      {hasChartData && (
        <section className="panel threat-chart-panel">
          <div className="panel-header">
            <div>
              <h3>Recent Incident Attack Probability Timeline</h3>
              <p className="panel-subtitle">
                ML confidence distribution across the latest {recentIncidentsForChart.length} recorded intrusion events.
              </p>
            </div>
          </div>

          <div className="threat-chart-wrap">
            <div className="threat-bars-container">
              {recentIncidentsForChart.map((inc, idx) => {
                const prob = Number(inc.attack_probability) || 0
                const pct = Math.min(100, Math.max(10, prob * 100))
                const isHigh = prob > 0.7
                const isMed = prob > 0.4 && prob <= 0.7

                return (
                  <div
                    key={inc.id ?? idx}
                    className="threat-bar-col"
                    onClick={() => setSelectedIncident(inc)}
                    title={`Incident #${inc.id}: ${inc.label || 'Attack'} (${(prob * 100).toFixed(1)}%) - Click to inspect`}
                  >
                    <span className="threat-bar-pct">{(prob * 100).toFixed(0)}%</span>
                    <div className="threat-bar-track">
                      <div
                        className="threat-bar-fill"
                        style={{
                          height: `${pct}%`,
                          backgroundColor: isHigh ? '#ef4444' : isMed ? '#f59e0b' : '#14b8a6',
                        }}
                      />
                    </div>
                    <span className="threat-bar-id">#{inc.id}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </section>
      )}

      {/* 2-Column Operational Grid */}
      <div className="dashboard-two-col">
        {/* Column 1: Live Threat Detection */}
        <section className="panel live-detection-panel">
          <div className="panel-header">
            <div>
              <h3>Live Threat Telemetry</h3>
              <p className="panel-subtitle">Current 5-second streaming window analyzed by AWID3.</p>
            </div>
            <span className={isCaptureRunning ? 'badge badge-status-new' : 'badge badge-default'}>
              {isCaptureRunning ? 'Ingest Active' : 'Idle'}
            </span>
          </div>

          {mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined ? (
            <div className="detection-active-box">
              <div className="detection-verdict-row">
                <span className="detection-verdict-label">Latest Window Classification</span>
                <span
                  className={
                    mlLiveStatus.prediction === 0 ? 'badge badge-status-resolved' : 'badge badge-severity-high'
                  }
                >
                  {mlLiveStatus.prediction === 0 ? 'Normal Traffic' : (mlLiveStatus.label ?? 'Attack Detected')}
                </span>
              </div>

              {/* Meter 1: Attack Probability */}
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
                      backgroundColor: mlLiveStatus.attack_probability > 0.5 ? '#ef4444' : '#14b8a6',
                    }}
                  />
                </div>
              </div>

              {/* Meter 2: Normal Probability */}
              <div className="prob-meter-row" style={{ marginTop: '10px' }}>
                <div className="prob-meter-label">
                  <span>Normal Probability</span>
                  <strong>{formatProbability(mlLiveStatus.normal_probability)}</strong>
                </div>
                <div className="prob-meter-bar">
                  <div
                    className="prob-meter-fill"
                    style={{
                      width: `${Math.min(100, Math.max(0, (mlLiveStatus.normal_probability || 0) * 100))}%`,
                      backgroundColor: '#10b981',
                    }}
                  />
                </div>
              </div>

              <div className="window-telemetry-grid">
                <div className="window-telemetry-item">
                  <span className="telemetry-label">Frames in Window</span>
                  <strong className="telemetry-val">{formatValue(mlLiveStatus.total_packets)}</strong>
                </div>
                <div className="window-telemetry-item">
                  <span className="telemetry-label">Window Span</span>
                  <strong className="telemetry-val">
                    {mlLiveStatus.window_start ?? '--'}s - {mlLiveStatus.window_end ?? '--'}s
                  </strong>
                </div>
                <div className="window-telemetry-item">
                  <span className="telemetry-label">Monitored Interface</span>
                  <strong className="telemetry-val">{formatValue(monitoringInterface)}</strong>
                </div>
              </div>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-icon">
                <IconActivity size={28} />
              </div>
              <p className="empty-state-title">Awaiting Live Ingestion</p>
              <p className="empty-state-text">
                Start Live Capture to stream 802.11 wireless frames into the 5-second Random Forest inference pipeline.
              </p>
              <div className="empty-state-actions">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => setActiveView('Live Monitor')}
                >
                  Open Live Monitor &rarr;
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => {
                    setActiveView('ML Engine')
                    setMlEngineTab('live')
                  }}
                >
                  Inspect ML Engine
                </button>
              </div>
            </div>
          )}
        </section>

        {/* Column 2: Recent Security Events */}
        <section className="panel recent-events-panel">
          <div className="panel-header">
            <div>
              <h3>Recent Security Incidents</h3>
              <p className="panel-subtitle">Recorded anomalous activity and intrusion alerts.</p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="badge badge-default">{incidents.length} Logged</span>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setActiveView('Incidents')}
              >
                View All &rarr;
              </button>
            </div>
          </div>

          {incidents.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Time</th>
                    <th>Attack Label</th>
                    <th>Probability</th>
                    <th>Packets</th>
                    <th>Severity</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.slice(0, 5).map((incident, idx) => (
                    <tr
                      key={incident.id ?? idx}
                      className="clickable-row"
                      onClick={() => setSelectedIncident(incident)}
                      title="Click to view full forensics drawer"
                    >
                      <td className="mono-val">#{incident.id}</td>
                      <td style={{ fontSize: '12px' }}>{formatDateTime(incident.created_at)}</td>
                      <td>
                        <span className="badge badge-detection">
                          {formatValue(incident.label ?? incident.prediction)}
                        </span>
                      </td>
                      <td className="mono-val">{formatProbability(incident.attack_probability)}</td>
                      <td className="mono-val">{formatValue(incident.total_packets)}</td>
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
            <div className="empty-state">
              <div className="empty-state-icon">
                <IconShieldAlert size={28} />
              </div>
              <p className="empty-state-title">No Security Incidents Logged</p>
              <p className="empty-state-text">
                When anomalous 802.11 attack patterns (such as Deauthentication or Disassociation bursts) are detected, incidents are logged here with forensic evidence.
              </p>
            </div>
          )}
        </section>
      </div>
    </section>
  )
}
