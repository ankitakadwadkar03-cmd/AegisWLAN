import React from 'react'
import { createPortal } from 'react-dom'
import {
  formatValue,
  formatDateTime,
  getSeverityBadgeClass,
} from '../utils/helpers'
import { IconX, IconCopy, IconCheck } from './Icons'

export const IncidentDrawer = ({
  selectedIncident,
  setSelectedIncident,
  incidentCopyStatus,
  handleCopyIncidentJson,
  incidentJsonExpanded,
  setIncidentJsonExpanded,
  handleUpdateIncidentStatus,
  setActiveView,
  setMlEngineTab,
}) => {
  if (!selectedIncident || typeof document === 'undefined') {
    return null
  }

  const attackProb = Number(selectedIncident.attack_probability)
  const normProb = Number(selectedIncident.normal_probability)

  return createPortal(
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
            <span className="drawer-pill">INCIDENT FORENSICS</span>
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
            <IconX size={18} />
          </button>
        </div>

        <div className="incident-drawer-body">
          {/* Verdict Card */}
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
                  {Number.isFinite(attackProb) ? `${(attackProb * 100).toFixed(1)}%` : '--'}
                </strong>
              </div>
              <div className="mini-meter-track">
                <div
                  className="mini-meter-fill"
                  style={{
                    width: `${Math.min(100, Math.max(0, (attackProb || 0) * 100))}%`,
                    backgroundColor:
                      attackProb > 0.7 ? 'var(--danger)' : attackProb > 0.4 ? 'var(--warning)' : 'var(--success)',
                  }}
                />
              </div>
            </div>
          </div>

          {/* Evidence Grid */}
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
                  {Number.isFinite(normProb) ? `${(normProb * 100).toFixed(1)}%` : '--'}
                </strong>
              </div>
            </div>
          </div>

          {/* Raw Forensic Evidence */}
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
                  {incidentCopyStatus === 'success' ? (
                    <>
                      <IconCheck size={14} /> Copied
                    </>
                  ) : (
                    <>
                      <IconCopy size={14} /> Copy JSON
                    </>
                  )}
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
            className="btn btn-secondary"
            onClick={() => handleCopyIncidentJson(selectedIncident)}
          >
            {incidentCopyStatus === 'success' ? '✓ Copied' : 'Copy Forensic JSON'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => {
              setSelectedIncident(null)
              setIncidentJsonExpanded(false)
              setActiveView('ML Engine')
              setMlEngineTab('live')
            }}
          >
            Inspect ML Engine &rarr;
          </button>
          <button
            type="button"
            className="btn btn-primary"
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
  )
}
