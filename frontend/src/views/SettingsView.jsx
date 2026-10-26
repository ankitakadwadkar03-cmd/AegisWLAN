import React from 'react'
import {
  formatDateTime,
  formatValue,
} from '../utils/helpers'
import {
  IconActivity,
  IconCheck,
} from '../components/Icons'

export const SettingsView = ({
  settingsTab,
  setSettingsTab,
  uiPrefs,
  setUiPrefs,
  settingsSaveMsg,
  diagnosticsLoading,
  diagnosticsResult,
  handleRunDiagnostics,
  interfaces,
  adapterState,
  mlSchemaInfo,
  recommendationModelInfo,
  apiBaseUrl,
}) => {
  return (
    <section className="settings-view" aria-label="System Settings and Configuration">
      {/* Control & Header Panel */}
      <div className="panel scan-control-panel">
        <div className="control-bar-row">
          <div className="control-bar-info">
            <div className="control-title-group">
              <h2 className="section-title">Settings &amp; Configuration Center</h2>
              <span className="badge badge-default">System Management</span>
            </div>
            <p className="panel-subtitle">
              Configure user preferences, wireless ingestion, machine learning models, and system health checks.
            </p>
          </div>

          <div className="control-bar-actions">
            <button
              className="btn btn-primary"
              disabled={diagnosticsLoading}
              onClick={handleRunDiagnostics}
              type="button"
            >
              <IconActivity size={14} />
              <span>{diagnosticsLoading ? 'Testing API...' : 'Run Health Check'}</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="soc-tab-bar" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={settingsTab === 'general'}
            className={`soc-tab-btn ${settingsTab === 'general' ? 'active' : ''}`}
            onClick={() => setSettingsTab('general')}
          >
            General Preferences
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={settingsTab === 'telemetry'}
            className={`soc-tab-btn ${settingsTab === 'telemetry' ? 'active' : ''}`}
            onClick={() => setSettingsTab('telemetry')}
          >
            Wireless Adapter &amp; Ingestion
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={settingsTab === 'ml'}
            className={`soc-tab-btn ${settingsTab === 'ml' ? 'active' : ''}`}
            onClick={() => setSettingsTab('ml')}
          >
            AWID3 ML Engine
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={settingsTab === 'recommendations'}
            className={`soc-tab-btn ${settingsTab === 'recommendations' ? 'active' : ''}`}
            onClick={() => setSettingsTab('recommendations')}
          >
            Wi-Fi Recommendation Model
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={settingsTab === 'diagnostics'}
            className={`soc-tab-btn ${settingsTab === 'diagnostics' ? 'active' : ''}`}
            onClick={() => setSettingsTab('diagnostics')}
          >
            Diagnostics &amp; Health
          </button>
        </div>
      </div>

      {/* TAB 1: GENERAL PREFERENCES */}
      {settingsTab === 'general' && (
        <div className="settings-content-panel" style={{ marginTop: '16px' }}>
          {settingsSaveMsg && (
            <div className="save-success-banner" role="status">
              <IconCheck size={16} /> <span>{settingsSaveMsg}</span>
            </div>
          )}

          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>User Interface Preferences</h3>
                <p className="panel-subtitle">Preferences persisted in browser local storage.</p>
              </div>
            </div>

            <div className="settings-fields-grid">
              <div className="form-group">
                <label htmlFor="poll-interval-select">Telemetry Polling Interval</label>
                <select
                  id="poll-interval-select"
                  className="settings-select"
                  value={uiPrefs.pollInterval ?? 2000}
                  onChange={(e) =>
                    setUiPrefs((prev) => ({ ...prev, pollInterval: Number(e.target.value) }))
                  }
                >
                  <option value={1000}>1 Second (High Frequency / Debug)</option>
                  <option value={2000}>2 Seconds (Recommended Real-Time)</option>
                  <option value={5000}>5 Seconds (Balanced Telemetry)</option>
                  <option value={10000}>10 Seconds (Low Overhead)</option>
                </select>
                <span className="form-hint">
                  Auto-refresh frequency for packet capture, incident logs, and live monitoring.
                </span>
              </div>

              <div className="form-group">
                <label htmlFor="default-view-select">Default View on Launch</label>
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
                  <option value="PCAP Analysis">PCAP Analysis</option>
                  <option value="Network Recommendations">Network Recommendations</option>
                  <option value="Incidents">Security Incidents</option>
                  <option value="Reports">Reports</option>
                  <option value="Settings">Settings</option>
                </select>
                <span className="form-hint">
                  The initial page opened when launching NetShield.
                </span>
              </div>

              <div className="form-group">
                <label htmlFor="table-density-select">Table Density</label>
                <select
                  id="table-density-select"
                  className="settings-select"
                  value={uiPrefs.tableDensity ?? 'compact'}
                  onChange={(e) =>
                    setUiPrefs((prev) => ({ ...prev, tableDensity: e.target.value }))
                  }
                >
                  <option value="compact">Compact (High Information Density)</option>
                  <option value="comfortable">Comfortable (Standard Padding)</option>
                </select>
                <span className="form-hint">
                  Row height and spacing across packet tables and logs.
                </span>
              </div>
            </div>

            <div className="settings-toggles-list" style={{ marginTop: '16px' }}>
              <label className="settings-toggle-row">
                <input
                  type="checkbox"
                  checked={uiPrefs.visualAlerts ?? true}
                  onChange={(e) =>
                    setUiPrefs((prev) => ({ ...prev, visualAlerts: e.target.checked }))
                  }
                />
                <div>
                  <strong>Show Visual Alert Badges in Top Header</strong>
                  <p className="form-hint">Displays prominent high-severity incident counters in the workspace bar.</p>
                </div>
              </label>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: WIRELESS ADAPTER & INGESTION */}
      {settingsTab === 'telemetry' && (
        <div className="settings-content-panel" style={{ marginTop: '16px' }}>
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Wireless Adapter Status &amp; Ingestion Subsystem</h3>
                <p className="panel-subtitle">Detected network interfaces and packet sniffer parameters.</p>
              </div>
            </div>

            <div className="spec-grid">
              <div className="spec-card">
                <span className="spec-label">Adapter Subsystem State</span>
                <strong className="spec-val">{formatValue(adapterState || 'Initialized')}</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Available Interfaces</span>
                <strong className="spec-val">{interfaces?.length || 0} Interfaces</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Capture Mechanism</span>
                <strong className="spec-val">Scapy / Native Socket Ingestion</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Buffer Capacity</span>
                <strong className="spec-val">100 Frames (Rolling Ring Buffer)</strong>
              </div>
            </div>

            {interfaces && interfaces.length > 0 && (
              <div className="table-wrap" style={{ marginTop: '16px' }}>
                <table>
                  <thead>
                    <tr>
                      <th>Interface Name</th>
                      <th>Operational Mode</th>
                      <th>MAC Address</th>
                      <th>IP Address</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {interfaces.map((iface, idx) => (
                      <tr key={idx}>
                        <td className="mono-val"><strong>{iface.name || iface.interface}</strong></td>
                        <td>{iface.mode || 'managed'}</td>
                        <td className="mono-val">{iface.mac || iface.hardware_address || '--'}</td>
                        <td className="mono-val">{iface.ip || iface.ip_address || '--'}</td>
                        <td>
                          <span className="badge badge-status-resolved">Active</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: AWID3 ML ENGINE */}
      {settingsTab === 'ml' && (
        <div className="settings-content-panel" style={{ marginTop: '16px' }}>
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>AWID3 Machine Learning Classifier Specifications</h3>
                <p className="panel-subtitle">Underlying intrusion detection model architecture and hyper-parameters.</p>
              </div>
            </div>

            <div className="spec-grid">
              <div className="spec-card">
                <span className="spec-label">Model File</span>
                <strong className="spec-val mono-val">{mlSchemaInfo?.model_name || 'random_forest_awid3_v3_expanded.joblib'}</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Canonical Feature Schema</span>
                <strong className="spec-val" style={{ color: 'var(--accent-text)' }}>
                  {mlSchemaInfo?.feature_count ?? 31} Features
                </strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Algorithm</span>
                <strong className="spec-val">Random Forest Classifier (Scikit-Learn)</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Classification Mode</span>
                <strong className="spec-val">Binary (0: Normal, 1: Attack)</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Inference Window Duration</span>
                <strong className="spec-val">5.0 Seconds Tumbling</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Decision Threshold</span>
                <strong className="spec-val">0.50 (Probability of Attack)</strong>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: WI-FI RECOMMENDATION MODEL */}
      {settingsTab === 'recommendations' && (
        <div className="settings-content-panel" style={{ marginTop: '16px' }}>
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Wi-Fi Network Recommendation Engine</h3>
                <p className="panel-subtitle">Quality-of-Service and connection scoring model details.</p>
              </div>
            </div>

            <div className="spec-grid">
              <div className="spec-card">
                <span className="spec-label">Model File</span>
                <strong className="spec-val mono-val">{recommendationModelInfo?.model_name || 'wifi_network_recommendation.joblib'}</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Feature Vector Count</span>
                <strong className="spec-val" style={{ color: 'var(--accent-rose-text)' }}>12 Features</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Target Quality Classes</span>
                <strong className="spec-val">EXCELLENT, GOOD, FAIR, POOR</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Score Scaling</span>
                <strong className="spec-val">0 to 100 Normalized Scale</strong>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: DIAGNOSTICS & HEALTH */}
      {settingsTab === 'diagnostics' && (
        <div className="settings-content-panel" style={{ marginTop: '16px' }}>
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Backend Health Ping &amp; Diagnostic Check</h3>
                <p className="panel-subtitle">Ping the Flask REST API at {apiBaseUrl}/health.</p>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <button
                type="button"
                className="btn btn-primary"
                disabled={diagnosticsLoading}
                onClick={handleRunDiagnostics}
              >
                <IconActivity size={14} />
                <span>{diagnosticsLoading ? 'Pinging /api/health...' : 'Execute Health Ping'}</span>
              </button>
            </div>

            {diagnosticsResult && (
              <div className="diagnostics-result-box" style={{ marginTop: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: diagnosticsResult.ok ? 'var(--success-text)' : 'var(--danger-text)', fontWeight: 700 }}>
                    {diagnosticsResult.ok ? '✓ BACKEND SERVICE HEALTHY' : '✕ HEALTH CHECK FAILED'}
                  </span>
                  <span style={{ color: 'var(--text-muted)' }}>Latency: {diagnosticsResult.latencyMs} ms</span>
                </div>
                <div style={{ marginTop: '8px' }}>
                  <strong>Timestamp:</strong> {formatDateTime(diagnosticsResult.timestamp)}
                </div>
                {diagnosticsResult.ok ? (
                  <div style={{ marginTop: '8px' }}>
                    <strong>Server Payload:</strong>
                    <pre className="mono-val code-block" style={{ marginTop: '4px' }}>
                      {JSON.stringify(diagnosticsResult.data, null, 2)}
                    </pre>
                  </div>
                ) : (
                  <div style={{ color: 'var(--danger-text)', marginTop: '8px' }}>
                    <strong>Error:</strong> {diagnosticsResult.error}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  )
}
