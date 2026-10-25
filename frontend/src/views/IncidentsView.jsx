import React from 'react'
import {
  formatValue,
  formatProbability,
  formatDateTime,
  getSeverityBadgeClass,
  getStatusBadgeClass,
} from '../utils/helpers'
import {
  IconShieldAlert,
  IconSearch,
  IconRefresh,
  IconReports,
} from '../components/Icons'

export const IncidentsView = ({
  incidents,
  totalIncidents,
  newIncidents,
  highSeverityIncidents,
  avgAttackProb,
  incidentsLoading,
  incidentsError,
  loadIncidentsData,
  incidentSearch,
  setIncidentSearch,
  incidentSeverityFilter,
  setIncidentSeverityFilter,
  incidentStatusFilter,
  setIncidentStatusFilter,
  filteredIncidents,
  setSelectedIncident,
  setActiveView,
}) => {
  return (
    <section className="incidents-view" aria-label="Security Incidents Register">
      {incidentsError && <p className="error-banner">{incidentsError}</p>}

      {/* Control & Header Panel */}
      <div className="panel scan-control-panel">
        <div className="control-bar-row">
          <div className="control-bar-info">
            <div className="control-title-group">
              <h2 className="section-title">Security Incidents Register</h2>
              <span className="badge badge-default">AWID3 Intrusion Log</span>
            </div>
            <p className="panel-subtitle">
              Verified anomalies and 802.11 attack bursts classified by the Random Forest engine across live capture and PCAP analysis.
            </p>
          </div>

          <div className="control-bar-actions">
            <button
              className="btn btn-secondary"
              disabled={incidentsLoading}
              onClick={() => loadIncidentsData()}
              type="button"
            >
              <IconRefresh size={14} />
              <span>{incidentsLoading ? 'Refreshing...' : 'Refresh'}</span>
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => setActiveView('Reports')}
              type="button"
            >
              <IconReports size={14} />
              <span>View Reports &rarr;</span>
            </button>
          </div>
        </div>

        {/* 4 Metric KPI Cards */}
        <div className="telemetry-strip-grid" style={{ marginTop: '16px' }}>
          <article className="telemetry-card">
            <span className="telemetry-card-label">Total Incidents</span>
            <strong className="telemetry-card-val">{formatValue(totalIncidents)}</strong>
            <span className="telemetry-card-sub">Recorded across windows</span>
          </article>

          <article
            className="telemetry-card"
            style={{
              borderTop: newIncidents > 0 ? '3px solid #f59e0b' : '3px solid #10b981',
            }}
          >
            <span className="telemetry-card-label">Unresolved Alerts</span>
            <strong
              className="telemetry-card-val"
              style={{ color: newIncidents > 0 ? '#fbbf24' : '#34d399' }}
            >
              {formatValue(newIncidents)}
            </strong>
            <span className="telemetry-card-sub">
              {newIncidents > 0 ? 'Awaiting SOC triage' : 'All clear'}
            </span>
          </article>

          <article
            className="telemetry-card"
            style={{
              borderTop: highSeverityIncidents > 0 ? '3px solid #ef4444' : '3px solid #10b981',
            }}
          >
            <span className="telemetry-card-label">High Severity</span>
            <strong
              className="telemetry-card-val"
              style={{ color: highSeverityIncidents > 0 ? '#f87171' : '#34d399' }}
            >
              {formatValue(highSeverityIncidents)}
            </strong>
            <span className="telemetry-card-sub">
              {highSeverityIncidents > 0 ? 'Immediate attention' : 'None detected'}
            </span>
          </article>

          <article className="telemetry-card">
            <span className="telemetry-card-label">Mean Attack Prob</span>
            <strong className="telemetry-card-val" style={{ color: 'var(--accent-text)' }}>
              {avgAttackProb !== '--' ? `${avgAttackProb}%` : '--'}
            </strong>
            <span className="telemetry-card-sub">Average across detections</span>
          </article>
        </div>

        {/* Search & Filter Toolbar */}
        <div className="scan-toolbar" style={{ marginTop: '16px' }}>
          <div className="search-box">
            <IconSearch size={16} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder="Search by ID, attack label, severity, or status..."
              value={incidentSearch}
              onChange={(e) => setIncidentSearch(e.target.value)}
              aria-label="Search incidents"
            />
            {incidentSearch && (
              <button
                type="button"
                className="search-clear-btn"
                onClick={() => setIncidentSearch('')}
                aria-label="Clear search"
              >
                &times;
              </button>
            )}
          </div>

          <div className="filter-chips">
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

          <div className="filter-chips">
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

          <span className="filter-results-count">
            Showing <strong>{filteredIncidents.length}</strong> of {totalIncidents} incidents
          </span>
        </div>
      </div>

      {/* Incidents Table Panel */}
      <div className="panel incidents-panel" style={{ marginTop: '16px' }}>
        <div className="panel-header">
          <div>
            <h3>Incident Forensic Log</h3>
            <p className="panel-subtitle">Click any row to open the complete 31-feature forensic evidence drawer.</p>
          </div>
        </div>

        {incidentsLoading && incidents.length === 0 ? (
          <div className="empty-state">
            <p className="empty-state-title">Loading Incidents...</p>
          </div>
        ) : filteredIncidents.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Timestamp</th>
                  <th>Detection Verdict</th>
                  <th>Attack Probability</th>
                  <th>Window Frames</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredIncidents.map((incident, index) => (
                  <tr
                    key={incident.id ?? index}
                    className="clickable-row"
                    onClick={() => setSelectedIncident(incident)}
                    title="Click to view full forensic evidence drawer"
                  >
                    <td className="mono-val" style={{ fontWeight: 600 }}>
                      #{incident.id}
                    </td>
                    <td>
                      <span className="mono-val" style={{ fontSize: '12px' }}>
                        {formatDateTime(incident.created_at)}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-detection">
                        {formatValue(incident.label ?? incident.prediction)}
                      </span>
                    </td>
                    <td>
                      <span
                        className="mono-val"
                        style={{
                          color:
                            incident.attack_probability > 0.7
                              ? '#f87171'
                              : incident.attack_probability > 0.4
                                ? '#fbbf24'
                                : 'var(--text-strong)',
                        }}
                      >
                        {formatProbability(incident.attack_probability)}
                      </span>
                    </td>
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
                    <td>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedIncident(incident)
                        }}
                      >
                        Forensics
                      </button>
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
            <p className="empty-state-title">No Incidents Recorded</p>
            <p className="empty-state-text">
              The AWID3 intrusion detection engine has not logged any anomalies. When attack patterns like Deauth/Disassoc bursts occur, they will be archived here.
            </p>
          </div>
        )}
      </div>
    </section>
  )
}
