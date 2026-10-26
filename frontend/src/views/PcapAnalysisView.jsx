import React from 'react'
import {
  formatValue,
  formatProbability,
  formatFileSize,
  formatDateTime,
  getCategoryBadgeClass,
} from '../utils/helpers'
import {
  IconFileSearch,
  IconPlay,
  IconDownload,
} from '../components/Icons'

export const PcapAnalysisView = ({
  pcapSamples,
  selectedPcapSample,
  setSelectedPcapSample,
  selectedPcapFile,
  setSelectedPcapFile,
  pcapAnalyzing,
  pcapError,
  pcapResult,
  pcapHistory,
  pcapFilter,
  setPcapFilter,
  pcapTab,
  setPcapTab,
  handlePcapAnalyze,
  apiBaseUrl,
}) => {
  // Filter windows based on pcapFilter
  const allWindows = pcapResult?.windows || pcapResult?.window_results || []
  const filteredWindows = allWindows.filter((w) => {
    if (pcapFilter === 'attacks') {
      return (
        w.prediction === 1 ||
        w.is_attack ||
        String(w.label || '').toLowerCase().includes('attack') ||
        (w.attack_probability && w.attack_probability > 0.5)
      )
    }
    if (pcapFilter === 'normal') {
      return (
        w.prediction === 0 ||
        (!w.is_attack && (w.attack_probability || 0) <= 0.5)
      )
    }
    return true
  })

  // Category counts from result
  const threatCategories = pcapResult?.threat_breakdown || pcapResult?.summary?.threat_categories || {}

  return (
    <section className="pcap-analysis-view" aria-label="Offline PCAP packet analysis">
      {pcapError && <p className="error-banner">{pcapError}</p>}

      {/* Workflow Step 1: Upload / Choose File & Run */}
      <div className="panel scan-control-panel">
        <div className="control-bar-row">
          <div className="control-bar-info">
            <div className="control-title-group">
              <h2 className="section-title">Offline PCAP / PCAPNG ML Analysis</h2>
              <span className="badge badge-default">
                {pcapAnalyzing ? 'Analyzing...' : pcapResult ? 'Analysis Complete' : 'Ready'}
              </span>
            </div>
            <p className="panel-subtitle">
              Upload captured wireless traffic (.pcap, .pcapng) or select a bundled dataset to run 31-feature AWID3 threat detection across 5-second tumbling windows.
            </p>
          </div>

          {pcapResult?.id && (
            <div className="control-bar-actions">
              <a
                className="btn btn-secondary"
                href={`${apiBaseUrl}/pcap/download/${pcapResult.id}/csv`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <IconDownload size={14} />
                <span>Export Windows CSV</span>
              </a>
            </div>
          )}
        </div>

        {/* Upload Form */}
        <form className="pcap-upload-form" onSubmit={handlePcapAnalyze}>
          <div className="pcap-inputs-row">
            {/* Custom file upload */}
            <label className="pcap-file-box">
              <span className="pcap-input-label">Upload PCAP / PCAPNG:</span>
              <input
                type="file"
                accept=".pcap,.pcapng,.cap"
                onChange={(e) => {
                  const file = e.target.files?.[0]
                  setSelectedPcapFile(file || null)
                  if (file) setSelectedPcapSample('')
                }}
                disabled={pcapAnalyzing}
                className="file-input-hidden"
              />
              <span className="file-name-display">
                {selectedPcapFile ? (
                  <strong>{selectedPcapFile.name} ({formatFileSize(selectedPcapFile.size)})</strong>
                ) : (
                  'Choose local .pcap or .pcapng file...'
                )}
              </span>
            </label>

            <span className="pcap-or-divider">OR</span>

            {/* Bundled sample dropdown */}
            <div className="pcap-sample-box">
              <span className="pcap-input-label">Select Bundled Sample:</span>
              <select
                disabled={pcapAnalyzing || !!selectedPcapFile}
                onChange={(e) => {
                  setSelectedPcapSample(e.target.value)
                  setSelectedPcapFile(null)
                }}
                value={selectedPcapFile ? '' : selectedPcapSample}
                className="pcap-sample-select"
              >
                <option value="">-- Choose bundled capture --</option>
                {pcapSamples.map((s) => (
                  <option key={s.filename} value={s.filename}>
                    {s.filename} ({formatFileSize(s.file_size_bytes)})
                  </option>
                ))}
              </select>
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={pcapAnalyzing || (!selectedPcapFile && !selectedPcapSample)}
            >
              <IconPlay size={14} />
              <span>{pcapAnalyzing ? 'Analyzing 31 Features...' : 'Start Analysis'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Workflow Step 2 & 3: Results Summary Strip */}
      {pcapResult ? (
        <>
          <div className="telemetry-strip-grid" style={{ marginTop: '16px' }}>
            <article className="telemetry-card">
              <span className="telemetry-card-label">Total Frames</span>
              <strong className="telemetry-card-val">
                {formatValue(pcapResult.total_packets ?? pcapResult.summary?.total_packets)}
              </strong>
              <span className="telemetry-card-sub">In captured file</span>
            </article>

            <article className="telemetry-card">
              <span className="telemetry-card-label">5s Windows Analyzed</span>
              <strong className="telemetry-card-val">
                {formatValue(pcapResult.total_windows ?? pcapResult.summary?.analyzed_windows)}
              </strong>
              <span className="telemetry-card-sub">Time windows</span>
            </article>

            <article
              className="telemetry-card"
              style={{
                borderTop:
                  (pcapResult.attack_windows ?? pcapResult.summary?.attack_windows) > 0
                    ? '3px solid var(--danger)'
                    : '3px solid var(--success)',
              }}
            >
              <span className="telemetry-card-label">Attack Windows</span>
              <strong
                className="telemetry-card-val"
                style={{
                  color:
                    (pcapResult.attack_windows ?? pcapResult.summary?.attack_windows) > 0
                      ? 'var(--danger-text)'
                      : 'var(--success-text)',
                }}
              >
                {formatValue(pcapResult.attack_windows ?? pcapResult.summary?.attack_windows ?? 0)}
              </strong>
              <span className="telemetry-card-sub">
                {formatValue(pcapResult.attack_percentage ?? pcapResult.summary?.attack_percentage ?? 0)}% of total
              </span>
            </article>

            <article className="telemetry-card">
              <span className="telemetry-card-label">Dominant Threat</span>
              <strong className="telemetry-card-val" style={{ fontSize: '15px' }}>
                {formatValue(pcapResult.dominant_category ?? pcapResult.summary?.dominant_category ?? 'Normal Traffic')}
              </strong>
              <span className="telemetry-card-sub">Highest burst signature</span>
            </article>
          </div>

          {/* Results Tabs: Timeline vs Threat Breakdown vs History */}
          <div className="soc-tab-bar" style={{ marginTop: '16px' }}>
            <button
              className={`soc-tab-btn ${pcapTab === 'timeline' ? 'active' : ''}`}
              onClick={() => setPcapTab('timeline')}
              type="button"
            >
              Classification Timeline ({allWindows.length} Windows)
            </button>
            <button
              className={`soc-tab-btn ${pcapTab === 'threats' ? 'active' : ''}`}
              onClick={() => setPcapTab('threats')}
              type="button"
            >
              Threat Breakdown
            </button>
            <button
              className={`soc-tab-btn ${pcapTab === 'history' ? 'active' : ''}`}
              onClick={() => setPcapTab('history')}
              type="button"
            >
              Past Analyses Archive ({pcapHistory.length})
            </button>
          </div>

          {/* TAB: TIMELINE TABLE */}
          {pcapTab === 'timeline' && (
            <div className="panel pcap-timeline-panel">
              <div className="panel-header">
                <div>
                  <h3>Time-Window Inference Breakdown</h3>
                  <p className="panel-subtitle">
                    Each 5-second window evaluated against the 31-feature Random Forest model.
                  </p>
                </div>

                <div className="filter-chips">
                  <button
                    type="button"
                    className={`filter-chip ${pcapFilter === 'all' ? 'active' : ''}`}
                    onClick={() => setPcapFilter('all')}
                  >
                    All ({allWindows.length})
                  </button>
                  <button
                    type="button"
                    className={`filter-chip ${pcapFilter === 'attacks' ? 'active' : ''}`}
                    onClick={() => setPcapFilter('attacks')}
                  >
                    Attacks Only
                  </button>
                  <button
                    type="button"
                    className={`filter-chip ${pcapFilter === 'normal' ? 'active' : ''}`}
                    onClick={() => setPcapFilter('normal')}
                  >
                    Normal Only
                  </button>
                </div>
              </div>

              {filteredWindows.length > 0 ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Window</th>
                        <th>Time Span</th>
                        <th>Frames</th>
                        <th>ML Verdict</th>
                        <th>Attack Prob</th>
                        <th>Threat Category</th>
                        <th>Top Contributing Feature</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredWindows.map((win, idx) => {
                        const isAtk =
                          win.prediction === 1 ||
                          win.is_attack ||
                          (win.attack_probability && win.attack_probability > 0.5)

                        return (
                          <tr key={win.window_index ?? idx}>
                            <td className="mono-val">#{win.window_index ?? idx + 1}</td>
                            <td>
                              <span className="mono-val" style={{ fontSize: '12px' }}>
                                {win.window_start ?? '--'}s - {win.window_end ?? '--'}s
                              </span>
                            </td>
                            <td className="mono-val">{formatValue(win.packet_count ?? win.total_packets)}</td>
                            <td>
                              <span className={`badge ${isAtk ? 'badge-severity-high' : 'badge-status-resolved'}`}>
                                {isAtk ? 'Attack' : 'Normal'}
                              </span>
                            </td>
                            <td>
                              <span
                                className="mono-val"
                                style={{ color: isAtk ? 'var(--danger-text)' : 'var(--text-strong)' }}
                              >
                                {formatProbability(win.attack_probability)}
                              </span>
                            </td>
                            <td>
                              <span className={getCategoryBadgeClass(win.attack_category || win.label)}>
                                {win.attack_category || win.label || (isAtk ? 'Attack Burst' : 'Normal')}
                              </span>
                            </td>
                            <td className="mono-val" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                              {win.top_contributing_feature || 'None'}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty-state">
                  <p className="empty-state-title">No Windows Match Current Filter</p>
                  <p className="empty-state-text">Switch filter to "All" to inspect every 5-second slice.</p>
                </div>
              )}
            </div>
          )}

          {/* TAB: THREATS BREAKDOWN */}
          {pcapTab === 'threats' && (
            <div className="panel pcap-threats-panel">
              <div className="panel-header">
                <div>
                  <h3>Threat Classification Distribution in Capture</h3>
                  <p className="panel-subtitle">Distribution of observed attack types across evaluated time slices.</p>
                </div>
              </div>

              {Object.keys(threatCategories).length > 0 ? (
                <div className="threat-categories-list">
                  {Object.entries(threatCategories).map(([cat, count]) => (
                    <div className="threat-category-row" key={cat}>
                      <div className="threat-cat-meta">
                        <span className={getCategoryBadgeClass(cat)}>{cat}</span>
                        <strong className="threat-cat-count">{count} Windows</strong>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <p className="empty-state-title">No Threats Detected in Capture</p>
                  <p className="empty-state-text">All evaluated windows conform to baseline 802.11 wireless behavior.</p>
                </div>
              )}
            </div>
          )}

          {/* TAB: HISTORY ARCHIVE */}
          {pcapTab === 'history' && (
            <div className="panel pcap-history-panel">
              <div className="panel-header">
                <div>
                  <h3>Past PCAP Analyses History</h3>
                  <p className="panel-subtitle">Previously executed offline capture analyses.</p>
                </div>
              </div>

              {pcapHistory.length > 0 ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Filename</th>
                        <th>Created</th>
                        <th>Total Packets</th>
                        <th>Attack Windows</th>
                        <th>Verdict</th>
                        <th>Export</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pcapHistory.map((item) => (
                        <tr key={item.id}>
                          <td className="mono-val">#{item.id}</td>
                          <td><strong>{item.filename || 'capture.pcap'}</strong></td>
                          <td>{formatDateTime(item.created_at)}</td>
                          <td className="mono-val">{formatValue(item.total_packets)}</td>
                          <td className="mono-val">{formatValue(item.attack_windows ?? 0)}</td>
                          <td>
                            <span className={`badge ${item.attack_windows > 0 ? 'badge-severity-high' : 'badge-status-resolved'}`}>
                              {item.attack_windows > 0 ? 'Attacks Detected' : 'Clean / Normal'}
                            </span>
                          </td>
                          <td>
                            <a
                              className="btn btn-secondary btn-sm"
                              href={`${apiBaseUrl}/pcap/download/${item.id}/csv`}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              Download CSV
                            </a>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="empty-state">
                  <p className="empty-state-title">No Past Analyses Stored</p>
                </div>
              )}
            </div>
          )}
        </>
      ) : (
        <div className="panel empty-state" style={{ marginTop: '16px' }}>
          <div className="empty-state-icon">
            <IconFileSearch size={32} />
          </div>
          <p className="empty-state-title">Ready for PCAP Packet Analysis</p>
          <p className="empty-state-text">
            Upload an 802.11 capture file or select a bundled sample above, then click &ldquo;Start Analysis&rdquo; to begin offline 31-feature ML evaluation.
          </p>
        </div>
      )}
    </section>
  )
}
