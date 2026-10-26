import React from 'react'
import {
  formatValue,
  formatProbability,
  formatDateTime,
  getSeverityBadgeClass,
  getStatusBadgeClass,
} from '../utils/helpers'
import {
  IconReports,
  IconDownload,
  IconRefresh,
} from '../components/Icons'

export const ReportsView = ({
  reportsError,
  reportsLoading,
  handleRefreshReports,
  handleExportCsv,
  reportTotalIncidents,
  reportHighSeverity,
  reportTotalPackets,
  reportAvgAttackProb,
  attackCountsByLabel,
  reportIncidents,
  apiBaseUrl,
}) => {
  return (
    <section className="reports-view" aria-label="Security reports and analytics">
      {reportsError && <p className="error-banner">{reportsError}</p>}

      {/* Control & Header Panel */}
      <div className="panel scan-control-panel">
        <div className="control-bar-row">
          <div className="control-bar-info">
            <div className="control-title-group">
              <h2 className="section-title">Security Reports &amp; Incident Analytics</h2>
              <span className="badge badge-default">Telemetry Archive</span>
            </div>
            <p className="panel-subtitle">
              Comprehensive intrusion audits, threat frequency distributions, and forensic reports generated from live AWID3 detections.
            </p>
          </div>

          <div className="control-bar-actions">
            <button
              className="btn btn-secondary"
              disabled={reportsLoading}
              onClick={handleRefreshReports}
              type="button"
            >
              <IconRefresh size={14} />
              <span>Refresh</span>
            </button>
            <button
              className="btn btn-secondary"
              disabled={reportsLoading || reportIncidents.length === 0}
              onClick={handleExportCsv}
              type="button"
            >
              <IconDownload size={14} />
              <span>Export CSV</span>
            </button>
            <a
              className="btn btn-secondary"
              href={`${apiBaseUrl}/reports/pdf`}
              target="_blank"
              rel="noopener noreferrer"
            >
              <IconDownload size={14} />
              <span>Backend PDF</span>
            </a>
            <button
              className="btn btn-primary"
              disabled={reportsLoading}
              onClick={() => window.print()}
              type="button"
            >
              <span>Print / Save PDF</span>
            </button>
          </div>
        </div>

        {/* 4 Metric KPI Cards */}
        <div className="telemetry-strip-grid" style={{ marginTop: '16px' }}>
          <article className="telemetry-card">
            <span className="telemetry-card-label">Total Incidents</span>
            <strong className="telemetry-card-val">{formatValue(reportTotalIncidents)}</strong>
            <span className="telemetry-card-sub">Recorded detections</span>
          </article>

          <article
            className="telemetry-card"
            style={{
              borderTop: reportHighSeverity > 0 ? '3px solid var(--danger)' : '3px solid var(--success)',
            }}
          >
            <span className="telemetry-card-label">High Severity</span>
            <strong
              className="telemetry-card-val"
              style={{ color: reportHighSeverity > 0 ? 'var(--danger-text)' : 'var(--success-text)' }}
            >
              {formatValue(reportHighSeverity)}
            </strong>
            <span className="telemetry-card-sub">Critical intrusion events</span>
          </article>

          <article className="telemetry-card">
            <span className="telemetry-card-label">Packets in Incidents</span>
            <strong className="telemetry-card-val">{formatValue(reportTotalPackets)}</strong>
            <span className="telemetry-card-sub">Evaluated frames</span>
          </article>

          <article className="telemetry-card">
            <span className="telemetry-card-label">Average Attack Probability</span>
            <strong className="telemetry-card-val" style={{ color: 'var(--accent-text)' }}>
              {reportAvgAttackProb !== null ? formatProbability(reportAvgAttackProb) : '--'}
            </strong>
            <span className="telemetry-card-sub">Mean ML confidence</span>
          </article>
        </div>
      </div>

      {/* Threat Classification Distribution Panel */}
      <div className="panel threat-dist-panel" style={{ marginTop: '16px' }}>
        <div className="panel-header">
          <div>
            <h3>Threat Classification Distribution</h3>
            <p className="panel-subtitle">Frequency and proportion of detected attack types across recorded windows.</p>
          </div>
        </div>

        {Object.keys(attackCountsByLabel).length > 0 ? (
          <div className="threat-dist-bars-list">
            {Object.entries(attackCountsByLabel).map(([label, count]) => {
              const sharePercent =
                reportTotalIncidents > 0
                  ? ((count / reportTotalIncidents) * 100).toFixed(1)
                  : 0

              return (
                <div className="threat-dist-row" key={label}>
                  <div className="threat-dist-label-wrap">
                    <span className="badge badge-detection">{label}</span>
                  </div>
                  <div className="threat-dist-track">
                    <div
                      className="threat-dist-fill"
                      style={{ width: `${Math.min(100, Math.max(5, sharePercent))}%` }}
                    />
                  </div>
                  <div className="threat-dist-stat">
                    <strong>{count}</strong> ({sharePercent}%)
                  </div>
                </div>
              )
            })}
          </div>
        ) : (
          <div className="empty-state">
            <p className="empty-state-title">No Attacks Recorded Yet</p>
            <p className="empty-state-text">Incidents detected by the ML engine will be summarized here.</p>
          </div>
        )}
      </div>

      {/* Historical Incidents Archive Table */}
      <div className="panel report-table-panel" style={{ marginTop: '16px' }}>
        <div className="panel-header">
          <div>
            <h3>Historical Incident Records</h3>
            <p className="panel-subtitle">All intrusion events included in the generated audit report.</p>
          </div>
          <span className="badge badge-default">{reportIncidents.length} Records</span>
        </div>

        {reportIncidents.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Timestamp</th>
                  <th>Detection Label</th>
                  <th>Attack Probability</th>
                  <th>Window Frames</th>
                  <th>Severity</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {reportIncidents.map((incident, idx) => (
                  <tr key={incident.id ?? idx}>
                    <td className="mono-val" style={{ fontWeight: 600 }}>#{incident.id}</td>
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
              <IconReports size={28} />
            </div>
            <p className="empty-state-title">No Incident Records in Report</p>
            <p className="empty-state-text">
              Run live monitoring or PCAP analysis to generate security event data for export.
            </p>
          </div>
        )}
      </div>
    </section>
  )
}
