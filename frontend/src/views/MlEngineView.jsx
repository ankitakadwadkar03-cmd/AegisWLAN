import React, { useState } from 'react'
import {
  formatValue,
  formatProbability,
  getValue,
} from '../utils/helpers'
import {
  IconCpu,
  IconPlay,
  IconActivity,
  IconWifi,
  IconAlertTriangle,
  IconFileSearch,
  IconChevronDown,
  IconChevronRight,
  IconInfo,
} from '../components/Icons'

export const MlEngineView = ({
  mlEngineTab,
  setMlEngineTab,
  mlLiveStatus,
  _mlDetectionLoading,
  mlDetectionError,
  mlDatasets = [],
  selectedDataset,
  setSelectedDataset,
  mlTestingLoading,
  mlTestingError,
  handleRunMlTest,
  mlTestResult,
  mlSchemaInfo,
  setActiveView,
  networks = [],
}) => {
  const [selectedNetworkDetails, setSelectedNetworkDetails] = useState(null)
  const [showExtractedFeatures, setShowExtractedFeatures] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')

  const features = mlSchemaInfo?.features || []

  // Check if genuine 31-feature inference is available
  const hasLiveInference =
    mlLiveStatus &&
    mlLiveStatus.status !== 'no_inference' &&
    mlLiveStatus.prediction !== undefined

  // Filter networks if search query exists
  const filteredNetworks = networks.filter((net) => {
    if (!searchQuery.trim()) return true
    const q = searchQuery.toLowerCase().trim()
    const ssid = String(getValue(net, ['ssid', 'SSID']) || '').toLowerCase()
    const bssid = String(getValue(net, ['bssid', 'BSSID']) || '').toLowerCase()
    return ssid.includes(q) || bssid.includes(q)
  })

  return (
    <div className="ml-engine-container" aria-label="AWID3 Machine Learning Intrusion Detector">
      {/* Error Banners */}
      {mlEngineTab === 'live' && mlDetectionError && (
        <div className="error-banner-box">
          <IconAlertTriangle size={16} />
          <span>{mlDetectionError}</span>
        </div>
      )}
      {mlEngineTab === 'evaluation' && mlTestingError && (
        <div className="error-banner-box">
          <IconAlertTriangle size={16} />
          <span>{mlTestingError}</span>
        </div>
      )}

      {/* Control & Tab Header */}
      <div className="panel ml-control-panel">
        <div className="control-bar-row">
          <div className="control-bar-info">
            <div className="control-title-group">
              <h2 className="section-title">AWID3 Intrusion Detection Engine</h2>
              <span className="badge badge-subsystem-awid3">
                <IconCpu size={12} /> Random Forest (31 Features)
              </span>
              <span
                className={`badge ${
                  hasLiveInference
                    ? mlLiveStatus.prediction === 0
                      ? 'badge-status-resolved'
                      : 'badge-severity-high'
                    : 'badge-default'
                }`}
              >
                {hasLiveInference
                  ? mlLiveStatus.prediction === 0
                    ? 'Live Verdict: Normal'
                    : `Live Verdict: ${mlLiveStatus.label ?? 'Attack'}`
                  : 'Live Ingest: Awaiting 5s Frame Window'}
              </span>
            </div>
            <p className="panel-subtitle">
              Analyzes raw IEEE 802.11 management, control, and data frame temporal bursts using the canonical 31-feature AWID3 classification schema.
            </p>
          </div>

          <div className="control-bar-actions">
            <button
              className="btn btn-secondary"
              onClick={() => setActiveView('Live Monitor')}
              type="button"
            >
              <IconActivity size={14} />
              <span>Live Monitor Stream &rarr;</span>
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => setActiveView('PCAP Analysis')}
              type="button"
            >
              <IconFileSearch size={14} />
              <span>PCAP File Analysis &rarr;</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="ml-tab-bar" role="tablist">
          <button
            className={`ml-tab-button ${mlEngineTab === 'live' ? 'active' : ''}`}
            onClick={() => setMlEngineTab('live')}
            type="button"
            role="tab"
            aria-selected={mlEngineTab === 'live'}
          >
            Wi-Fi Scan &amp; Threat Detection
          </button>
          <button
            className={`ml-tab-button ${mlEngineTab === 'evaluation' ? 'active' : ''}`}
            onClick={() => setMlEngineTab('evaluation')}
            type="button"
            role="tab"
            aria-selected={mlEngineTab === 'evaluation'}
          >
            Offline Dataset Evaluation ({mlDatasets?.length || 0})
          </button>
          <button
            className={`ml-tab-button ${mlEngineTab === 'schema' ? 'active' : ''}`}
            onClick={() => setMlEngineTab('schema')}
            type="button"
            role="tab"
            aria-selected={mlEngineTab === 'schema'}
          >
            31 Canonical Feature Schema
          </button>
        </div>
      </div>

      {/* =========================================================================
         TAB 1: LIVE SCAN & THREAT INFERENCE (STATES A, B, C, D)
         ========================================================================= */}
      {mlEngineTab === 'live' && (
        <div className="ml-tab-body">
          {/* STATE D: GENUINE 31-FEATURE INFERENCE CARD (When Live Packet Window Analyzed) */}
          {hasLiveInference && (
            <div className="panel genuine-inference-panel">
              <div className="panel-header">
                <div className="control-title-group">
                  <h3 className="section-title">Live 31-Feature Frame Window Verdict</h3>
                  <span
                    className={`badge ${
                      mlLiveStatus.prediction === 0 ? 'badge-status-resolved' : 'badge-severity-high'
                    }`}
                  >
                    {mlLiveStatus.prediction === 0 ? 'NORMAL TRAFFIC' : 'ATTACK DETECTED'}
                  </span>
                </div>
                <span className="mono-val" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Window: 5.0s Tumbling Slice
                </span>
              </div>

              <div className="telemetry-strip-grid" style={{ marginTop: '10px' }}>
                <article className="telemetry-card">
                  <span className="telemetry-card-label">Predicted Class</span>
                  <strong
                    className="telemetry-card-val"
                    style={{
                      color:
                        mlLiveStatus.prediction === 1 ? 'var(--danger-text)' : 'var(--success-text)',
                    }}
                  >
                    {mlLiveStatus.prediction === 0 ? 'NORMAL' : 'ATTACK'}
                  </strong>
                  <span className="telemetry-card-sub">
                    {mlLiveStatus.label || (mlLiveStatus.prediction === 0 ? 'Normal 802.11 Traffic' : 'Suspicious Burst')}
                  </span>
                </article>

                <article className="telemetry-card">
                  <span className="telemetry-card-label">Attack Probability</span>
                  <strong
                    className="telemetry-card-val"
                    style={{
                      color:
                        mlLiveStatus.attack_probability > 0.5 ? 'var(--danger-text)' : 'var(--success-text)',
                    }}
                  >
                    {formatProbability(mlLiveStatus.attack_probability)}
                  </strong>
                  <span className="telemetry-card-sub">Random Forest Softmax</span>
                </article>

                <article className="telemetry-card">
                  <span className="telemetry-card-label">Frames Evaluated</span>
                  <strong className="telemetry-card-val">
                    {formatValue(mlLiveStatus.frame_count ?? mlLiveStatus.packet_count ?? '--')}
                  </strong>
                  <span className="telemetry-card-sub">Ingested in window</span>
                </article>

                <article className="telemetry-card">
                  <span className="telemetry-card-label">Timestamp</span>
                  <strong className="telemetry-card-val" style={{ fontSize: '13px' }}>
                    {formatValue(mlLiveStatus.timestamp ?? 'Real-time Stream')}
                  </strong>
                  <span className="telemetry-card-sub">Latest batch inference</span>
                </article>
              </div>

              {/* Evidence Explanation */}
              <div className="inference-evidence-box">
                <p>
                  <strong>Model Verdict Explanation:</strong>{' '}
                  {mlLiveStatus.prediction === 1
                    ? 'The AWID3 Random Forest classifier identified abnormal temporal frame distributions, elevated retry ratios, or excessive deauthentication bursts exceeding typical wireless baseline thresholds.'
                    : 'The frame sequence and temporal burst metrics extracted from the current 5-second capture window conform to legitimate IEEE 802.11 wireless network operation.'}
                </p>
              </div>

              {/* Expandable Extracted Features */}
              <div className="expandable-features-wrap">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => setShowExtractedFeatures(!showExtractedFeatures)}
                >
                  {showExtractedFeatures ? <IconChevronDown size={14} /> : <IconChevronRight size={14} />}
                  <span>{showExtractedFeatures ? 'Hide Extracted 31 Features' : 'View Extracted 31 Features'}</span>
                </button>

                {showExtractedFeatures && (
                  <div className="features-preview-box">
                    <p className="features-box-intro">
                      Canonical 31 AWID3 input vector features feeding the Random Forest decision tree forest:
                    </p>
                    <div className="feature-schema-grid">
                      {features.map((feat, idx) => {
                        const featValue = mlLiveStatus.features?.[feat] ?? mlLiveStatus.feature_values?.[idx]
                        return (
                          <div className="schema-chip" key={feat}>
                            <span className="chip-idx">#{idx + 1}</span>
                            <span className="chip-name">{feat}:</span>
                            <strong className="chip-val">
                              {featValue !== undefined ? formatValue(featValue) : 'Extracted'}
                            </strong>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* =========================================================================
             STATE A: NO WI-FI SCAN RESULTS (Compact Informational Cards)
             ========================================================================= */}
          {networks.length === 0 ? (
            <div className="panel state-a-panel">
              <div className="state-a-intro">
                <div className="state-a-icon-circle">
                  <IconWifi size={24} />
                </div>
                <div>
                  <h3 className="section-title">No Wi-Fi Scan Data Available Yet</h3>
                  <p className="panel-subtitle">
                    Scan nearby wireless networks to populate access points and evaluate network parameters.
                  </p>
                </div>
              </div>

              {/* 4 Compact Informational Cards as specified in Prompt */}
              <div className="telemetry-strip-grid" style={{ marginTop: '14px' }}>
                <article className="telemetry-card">
                  <span className="telemetry-card-label">Subsystem Purpose</span>
                  <strong className="telemetry-card-val" style={{ fontSize: '15px' }}>
                    Detect Attacks
                  </strong>
                  <span className="telemetry-card-sub">Identifies anomalies from 802.11 packet bursts</span>
                </article>

                <article className="telemetry-card">
                  <span className="telemetry-card-label">Frozen Classifier</span>
                  <strong className="telemetry-card-val" style={{ fontSize: '15px' }}>
                    AWID3 Random Forest
                  </strong>
                  <span className="telemetry-card-sub">Canonical binary threat detector</span>
                </article>

                <article className="telemetry-card">
                  <span className="telemetry-card-label">Feature Schema</span>
                  <strong className="telemetry-card-val" style={{ fontSize: '15px' }}>
                    31 Canonical Features
                  </strong>
                  <span className="telemetry-card-sub">Frame timing, retries &amp; burst ratios</span>
                </article>

                <article className="telemetry-card">
                  <span className="telemetry-card-label">Subsystem Status</span>
                  <strong className="telemetry-card-val" style={{ fontSize: '15px', color: 'var(--text-muted)' }}>
                    Waiting for Data
                  </strong>
                  <span className="telemetry-card-sub">Run Wi-Fi scan or packet capture</span>
                </article>
              </div>

              <div className="state-a-cta">
                <button
                  className="btn btn-primary"
                  onClick={() => setActiveView('WiFi Scan')}
                  type="button"
                >
                  <IconWifi size={14} />
                  <span>Go to Wi-Fi Scan</span>
                </button>
              </div>
            </div>
          ) : (
            /* =========================================================================
               STATE B & C: NETWORKS DISCOVERED & STATUS EXPLANATION
               ========================================================================= */
            <div className="panel state-b-panel">
              <div className="panel-header">
                <div>
                  <h3 className="section-title">
                    Discovered Wireless Access Points ({filteredNetworks.length})
                  </h3>
                  <p className="panel-subtitle">
                    Real-time access points detected by the spectrum scanner. Select an access point to view analysis requirements.
                  </p>
                </div>

                <div className="search-box" style={{ maxWidth: '280px' }}>
                  <input
                    type="text"
                    className="search-input"
                    placeholder="Filter by SSID or BSSID..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                </div>
              </div>

              {/* Network Table */}
              <div className="table-wrap" style={{ marginTop: '10px' }}>
                <table>
                  <thead>
                    <tr>
                      <th>SSID &amp; Access Point</th>
                      <th>BSSID (MAC)</th>
                      <th>Signal</th>
                      <th>Channel</th>
                      <th>AWID3 Analysis Status</th>
                      <th style={{ textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredNetworks.map((net, idx) => {
                      const ssid = getValue(net, ['ssid', 'SSID']) || '<Hidden SSID>'
                      const bssid = getValue(net, ['bssid', 'BSSID']) || 'Unknown'
                      const sig = getValue(net, ['signal', 'Signal']) || '--'
                      const ch = getValue(net, ['channel', 'Channel']) || '--'
                      const isSelected = selectedNetworkDetails?.bssid === bssid

                      return (
                        <tr
                          key={bssid || idx}
                          style={{
                            background: isSelected ? 'var(--accent-light)' : 'transparent',
                          }}
                        >
                          <td>
                            <strong>{ssid}</strong>
                          </td>
                          <td>
                            <span className="mono-val" style={{ fontSize: '12px' }}>
                              {bssid}
                            </span>
                          </td>
                          <td>
                            <span className="mono-val">{sig}</span>
                          </td>
                          <td>
                            <span className="mono-val">Ch {ch}</span>
                          </td>
                          {/* STATE C: Truthful Status without synthetic vectors */}
                          <td>
                            <span className="badge badge-default">
                              Network discovered — waiting for packet data
                            </span>
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={() =>
                                setSelectedNetworkDetails(isSelected ? null : { ssid, bssid, sig, ch, ...net })
                              }
                            >
                              <IconInfo size={13} />
                              <span>{isSelected ? 'Close' : 'Inspect'}</span>
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>

              {/* STATE C: Selected Network Inspection Card */}
              {selectedNetworkDetails && (
                <div className="selected-network-card">
                  <div className="selected-card-header">
                    <h4 className="selected-card-title">
                      Network Details &amp; Model Requirements: {selectedNetworkDetails.ssid}
                    </h4>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => setSelectedNetworkDetails(null)}
                    >
                      &times;
                    </button>
                  </div>

                  <div className="selected-card-body">
                    <div className="selected-meta-strip">
                      <span><strong>BSSID:</strong> {selectedNetworkDetails.bssid}</span>
                      <span><strong>Channel:</strong> {selectedNetworkDetails.ch}</span>
                      <span><strong>Signal:</strong> {selectedNetworkDetails.sig}</span>
                      <span><strong>Security:</strong> {getValue(selectedNetworkDetails, ['encryption', 'security']) || 'WPA2'}</span>
                    </div>

                    <div className="state-c-explanation-box">
                      <p>
                        <strong>Why is intrusion analysis waiting for packet data?</strong>
                        <br />
                        The AWID3 intrusion detection model operates on 31 canonical frame-header and temporal burst metrics (such as deauth frame ratios, retry distributions, and sequence delta gaps). Ordinary beacon scan results only provide physical RF properties. To ensure mathematical accuracy and adhere to the project's safeguards, <strong>synthetic features are never fabricated</strong>.
                      </p>
                      <div className="state-c-action-buttons">
                        <button
                          type="button"
                          className="btn btn-primary btn-sm"
                          onClick={() => setActiveView('Live Monitor')}
                        >
                          <IconActivity size={13} />
                          <span>Start Live Packet Capture</span>
                        </button>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => setActiveView('PCAP Analysis')}
                        >
                          <IconFileSearch size={13} />
                          <span>Analyze Pre-recorded PCAP</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
         TAB 2: OFFLINE DATASET EVALUATION
         ========================================================================= */}
      {mlEngineTab === 'evaluation' && (
        <div className="ml-tab-body">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3 className="section-title">Offline Benchmark Dataset Evaluation</h3>
                <p className="panel-subtitle">
                  Benchmark the frozen 31-feature Random Forest model against verified AWID3 evaluation CSV datasets.
                </p>
              </div>

              <div className="control-bar-actions">
                <select
                  className="dataset-select"
                  value={selectedDataset}
                  onChange={(e) => setSelectedDataset(e.target.value)}
                  disabled={mlTestingLoading}
                >
                  <option value="">-- Choose Evaluation Dataset --</option>
                  {mlDatasets.map((ds) => {
                    const dsName = ds.filename || ds.name
                    const isValid = ds.is_valid !== false && ds.is_valid_schema !== false
                    return (
                      <option key={dsName} value={dsName} disabled={!isValid}>
                        {dsName} ({ds.sample_count || ds.rows || '?'} samples)
                        {!isValid ? ` [Invalid: ${ds.schema_status || 'Incompatible'}]` : ''}
                      </option>
                    )
                  })}
                </select>

                <button
                  className="btn btn-primary"
                  disabled={
                    mlTestingLoading ||
                    !selectedDataset ||
                    mlDatasets.find((d) => (d.filename || d.name) === selectedDataset)?.is_valid === false ||
                    mlDatasets.find((d) => (d.filename || d.name) === selectedDataset)?.is_valid_schema === false
                  }
                  onClick={handleRunMlTest}
                  type="button"
                >
                  <IconPlay size={14} />
                  <span>{mlTestingLoading ? 'Evaluating...' : 'Run Benchmark Test'}</span>
                </button>
              </div>
            </div>

            {mlTestResult && (
              <div className="test-results-wrap" style={{ marginTop: '16px' }}>
                <div className="telemetry-strip-grid">
                  <article className="telemetry-card">
                    <span className="telemetry-card-label">Accuracy</span>
                    <strong className="telemetry-card-val" style={{ color: 'var(--success-text)' }}>
                      {mlTestResult.metrics?.accuracy !== undefined
                        ? `${Number(mlTestResult.metrics.accuracy).toFixed(2)}%`
                        : mlTestResult.accuracy !== undefined
                        ? `${Number(mlTestResult.accuracy <= 1 ? mlTestResult.accuracy * 100 : mlTestResult.accuracy).toFixed(2)}%`
                        : '--'}
                    </strong>
                    <span className="telemetry-card-sub">Correct classifications</span>
                  </article>

                  <article className="telemetry-card">
                    <span className="telemetry-card-label">Precision</span>
                    <strong className="telemetry-card-val">
                      {mlTestResult.metrics?.precision !== undefined
                        ? `${Number(mlTestResult.metrics.precision).toFixed(2)}%`
                        : mlTestResult.precision !== undefined
                        ? `${Number(mlTestResult.precision <= 1 ? mlTestResult.precision * 100 : mlTestResult.precision).toFixed(2)}%`
                        : '--'}
                    </strong>
                    <span className="telemetry-card-sub">Attack precision</span>
                  </article>

                  <article className="telemetry-card">
                    <span className="telemetry-card-label">Recall</span>
                    <strong className="telemetry-card-val">
                      {mlTestResult.metrics?.recall !== undefined
                        ? `${Number(mlTestResult.metrics.recall).toFixed(2)}%`
                        : mlTestResult.recall !== undefined
                        ? `${Number(mlTestResult.recall <= 1 ? mlTestResult.recall * 100 : mlTestResult.recall).toFixed(2)}%`
                        : '--'}
                    </strong>
                    <span className="telemetry-card-sub">Attack sensitivity</span>
                  </article>

                  <article className="telemetry-card">
                    <span className="telemetry-card-label">F1 Score</span>
                    <strong className="telemetry-card-val">
                      {mlTestResult.metrics?.f1_score !== undefined
                        ? `${Number(mlTestResult.metrics.f1_score).toFixed(2)}%`
                        : mlTestResult.f1_score !== undefined
                        ? `${Number(mlTestResult.f1_score <= 1 ? mlTestResult.f1_score * 100 : mlTestResult.f1_score).toFixed(2)}%`
                        : '--'}
                    </strong>
                    <span className="telemetry-card-sub">Harmonic mean</span>
                  </article>
                </div>

                {mlTestResult.confusion_matrix && (
                  <div className="confusion-matrix-box" style={{ marginTop: '16px' }}>
                    <h4 className="section-title" style={{ fontSize: '14px', marginBottom: '8px' }}>
                      Confusion Matrix
                    </h4>
                    <div className="confusion-matrix-grid">
                      <div className="cm-cell positive">
                        <span className="cm-cell-label">True Normal (TN)</span>
                        <strong className="cm-cell-val">
                          {formatValue(
                            mlTestResult.confusion_matrix.true_negatives ??
                            mlTestResult.confusion_matrix.true_negative ??
                            mlTestResult.confusion_matrix.tn
                          )}
                        </strong>
                      </div>
                      <div className="cm-cell negative">
                        <span className="cm-cell-label">False Attack (FP)</span>
                        <strong className="cm-cell-val">
                          {formatValue(
                            mlTestResult.confusion_matrix.false_positives ??
                            mlTestResult.confusion_matrix.false_positive ??
                            mlTestResult.confusion_matrix.fp
                          )}
                        </strong>
                      </div>
                      <div className="cm-cell negative">
                        <span className="cm-cell-label">Missed Attack (FN)</span>
                        <strong className="cm-cell-val">
                          {formatValue(
                            mlTestResult.confusion_matrix.false_negatives ??
                            mlTestResult.confusion_matrix.false_negative ??
                            mlTestResult.confusion_matrix.fn
                          )}
                        </strong>
                      </div>
                      <div className="cm-cell positive">
                        <span className="cm-cell-label">True Attack (TP)</span>
                        <strong className="cm-cell-val">
                          {formatValue(
                            mlTestResult.confusion_matrix.true_positives ??
                            mlTestResult.confusion_matrix.true_positive ??
                            mlTestResult.confusion_matrix.tp
                          )}
                        </strong>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* =========================================================================
         TAB 3: 31 CANONICAL FEATURE SCHEMA
         ========================================================================= */}
      {mlEngineTab === 'schema' && (
        <div className="ml-tab-body">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3 className="section-title">Canonical 31-Feature AWID3 Vector Schema</h3>
                <p className="panel-subtitle">
                  Fixed input vector order expected by <code>random_forest_awid3_v3_expanded.joblib</code>.
                </p>
              </div>
              <span className="badge badge-default">31 Features Frozen</span>
            </div>

            <div className="feature-schema-grid" style={{ marginTop: '12px' }}>
              {features.map((feat, idx) => (
                <div className="schema-chip" key={feat}>
                  <span className="chip-idx">#{idx + 1}</span>
                  <span className="chip-name">{feat}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
