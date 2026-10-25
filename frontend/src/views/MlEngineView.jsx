import React, { useState } from 'react'
import {
  formatValue,
  formatProbability,
  formatDateTime,
} from '../utils/helpers'
import {
  IconCpu,
  IconPlay,
  IconActivity,
} from '../components/Icons'

export const MlEngineView = ({
  mlEngineTab,
  setMlEngineTab,
  mlLiveStatus,
  mlDetectionLoading,
  mlDetectionError,
  mlDatasets,
  selectedDataset,
  setSelectedDataset,
  mlTestingLoading,
  mlTestingError,
  handleRunMlTest,
  mlTestResult,
  mlTestRuns,
  mlSchemaInfo,
  setActiveView,
}) => {
  const [showAdvancedSchema, setShowAdvancedSchema] = useState(false)

  // Categorize 31 canonical features if available
  const features = mlSchemaInfo?.features || []

  return (
    <section className="ml-engine-view" aria-label="AWID3 Machine Learning Engine">
      {mlEngineTab === 'live' && mlDetectionError && (
        <p className="error-banner">{mlDetectionError}</p>
      )}
      {mlEngineTab === 'evaluation' && mlTestingError && (
        <p className="error-banner">{mlTestingError}</p>
      )}

      {/* Control & Header Panel */}
      <div className="panel scan-control-panel">
        <div className="control-bar-row">
          <div className="control-bar-info">
            <div className="control-title-group">
              <h2 className="section-title">AWID3 ML Intrusion Detection Engine</h2>
              <span
                className={`badge ${
                  mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined
                    ? mlLiveStatus.prediction === 0
                      ? 'badge-status-resolved'
                      : 'badge-severity-high'
                    : 'badge-default'
                }`}
              >
                {mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined
                  ? mlLiveStatus.prediction === 0
                    ? 'Normal Traffic'
                    : (mlLiveStatus.label ?? 'Attack Detected')
                  : 'Awaiting 5s Window'}
              </span>
            </div>

            <div className="meta-pills-row">
              <span className="scan-meta-pill">
                Model: <strong>{mlSchemaInfo?.model_name || 'random_forest_awid3_v3_expanded'}</strong>
              </span>
              <span className="scan-meta-pill">
                Architecture: <strong>Random Forest (Binary: Normal vs Attack)</strong>
              </span>
              <span className="scan-meta-pill">
                Schema: <strong>{mlSchemaInfo?.feature_count ?? 31} Canonical Features</strong>
              </span>
              <span className="scan-meta-pill">
                Inference Window: <strong>5.0 seconds</strong>
              </span>
            </div>
          </div>

          <div className="control-bar-actions">
            <button
              className="btn btn-secondary"
              onClick={() => setActiveView('Live Monitor')}
              type="button"
            >
              <IconActivity size={14} />
              <span>Live Monitor</span>
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => setActiveView('PCAP Analysis')}
              type="button"
            >
              <span>PCAP Offline Analysis &rarr;</span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="soc-tab-bar" role="tablist">
          <button
            className={`soc-tab-btn ${mlEngineTab === 'live' ? 'active' : ''}`}
            onClick={() => setMlEngineTab('live')}
            type="button"
            role="tab"
            aria-selected={mlEngineTab === 'live'}
          >
            Live Threat Inference
          </button>
          <button
            className={`soc-tab-btn ${mlEngineTab === 'evaluation' ? 'active' : ''}`}
            onClick={() => setMlEngineTab('evaluation')}
            type="button"
            role="tab"
            aria-selected={mlEngineTab === 'evaluation'}
          >
            Offline Dataset Evaluation ({mlDatasets?.length || 0})
          </button>
          <button
            className={`soc-tab-btn ${mlEngineTab === 'schema' ? 'active' : ''}`}
            onClick={() => setMlEngineTab('schema')}
            type="button"
            role="tab"
            aria-selected={mlEngineTab === 'schema'}
          >
            Model &amp; Feature Schema (31 Features)
          </button>
        </div>
      </div>

      {/* TAB 1: LIVE INFERENCE */}
      {mlEngineTab === 'live' && (
        <div className="ml-tab-content">
          {/* Important Information Front and Center */}
          <div className="telemetry-strip-grid">
            <article className="telemetry-card">
              <span className="telemetry-card-label">Inference Status</span>
              <strong className="telemetry-card-val">
                {mlLiveStatus && mlLiveStatus.status !== 'no_inference' ? 'Evaluating' : 'Standby'}
              </strong>
              <span className="telemetry-card-sub">5s Sliding Window</span>
            </article>

            <article
              className="telemetry-card"
              style={{
                borderTop:
                  mlLiveStatus?.prediction === 1
                    ? '3px solid #ef4444'
                    : mlLiveStatus?.prediction === 0
                      ? '3px solid #10b981'
                      : 'none',
              }}
            >
              <span className="telemetry-card-label">Predicted Class</span>
              <strong
                className="telemetry-card-val"
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
                      : 'None')}
              </strong>
              <span className="telemetry-card-sub">Random Forest Verdict</span>
            </article>

            <article className="telemetry-card">
              <span className="telemetry-card-label">Attack Probability</span>
              <strong
                className="telemetry-card-val"
                style={{
                  color: mlLiveStatus?.attack_probability > 0.5 ? '#f87171' : 'var(--accent-text)',
                }}
              >
                {formatProbability(mlLiveStatus?.attack_probability)}
              </strong>
              <span className="telemetry-card-sub">Anomaly Confidence</span>
            </article>

            <article className="telemetry-card">
              <span className="telemetry-card-label">Packets in Window</span>
              <strong className="telemetry-card-val">
                {formatValue(mlLiveStatus?.total_packets)}
              </strong>
              <span className="telemetry-card-sub">Frames processed</span>
            </article>
          </div>

          {/* Live Inference Details Panel */}
          <div className="panel ml-inference-panel">
            <div className="panel-header">
              <div>
                <h3>Latest 5-Second Window Inference Telemetry</h3>
                <p className="panel-subtitle">
                  Features computed across IEEE 802.11 management, control, and data frames.
                </p>
              </div>
              {mlDetectionLoading && <span className="badge badge-default">Analyzing...</span>}
            </div>

            {mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined ? (
              <div className="detection-active-box">
                {/* Probability Meters */}
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

                <div className="prob-meter-row" style={{ marginTop: '12px' }}>
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

                <div className="window-telemetry-grid" style={{ marginTop: '16px' }}>
                  <div className="window-telemetry-item">
                    <span className="telemetry-label">Window Start (Timestamp)</span>
                    <strong className="telemetry-val">{mlLiveStatus.window_start ?? '--'}s</strong>
                  </div>
                  <div className="window-telemetry-item">
                    <span className="telemetry-label">Window End (Timestamp)</span>
                    <strong className="telemetry-val">{mlLiveStatus.window_end ?? '--'}s</strong>
                  </div>
                  <div className="window-telemetry-item">
                    <span className="telemetry-label">Total Window Frames</span>
                    <strong className="telemetry-val">{formatValue(mlLiveStatus.total_packets)}</strong>
                  </div>
                  <div className="window-telemetry-item">
                    <span className="telemetry-label">Features Extracted</span>
                    <strong className="telemetry-val">{mlLiveStatus.feature_count ?? 31} AWID3 Features</strong>
                  </div>
                </div>
              </div>
            ) : (
              <div className="empty-state">
                <div className="empty-state-icon">
                  <IconCpu size={28} />
                </div>
                <p className="empty-state-title">Awaiting Live Capture Traffic</p>
                <p className="empty-state-text">
                  To view live inference predictions, start packet capture on the Live Monitor page. The model automatically evaluates 5-second tumbling windows.
                </p>
                <div className="empty-state-actions">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => setActiveView('Live Monitor')}
                  >
                    Go to Live Monitor &rarr;
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => setMlEngineTab('evaluation')}
                  >
                    Try Offline Dataset Evaluation
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: OFFLINE DATASET EVALUATION */}
      {mlEngineTab === 'evaluation' && (
        <div className="ml-tab-content">
          <div className="panel dataset-eval-panel">
            <div className="panel-header">
              <div>
                <h3>Offline AWID3 Dataset Evaluation Benchmark</h3>
                <p className="panel-subtitle">
                  Validate the Random Forest classifier against ground-truth labeled benchmark CSV datasets.
                </p>
              </div>
            </div>

            <div className="eval-select-row">
              <label className="eval-label">
                <span>Select Evaluation Dataset:</span>
                <select
                  value={selectedDataset}
                  onChange={(e) => setSelectedDataset(e.target.value)}
                  disabled={mlTestingLoading}
                  className="eval-select"
                >
                  <option value="">-- Choose a test dataset --</option>
                  {mlDatasets.map((ds) => (
                    <option key={ds.filename || ds.name} value={ds.filename || ds.name}>
                      {ds.name || ds.filename} ({ds.sample_count ? `${ds.sample_count} samples` : ds.size_bytes ? `${Math.round(ds.size_bytes / 1024)} KB` : 'Ready'})
                    </option>
                  ))}
                </select>
              </label>

              <button
                type="button"
                className="btn btn-primary"
                disabled={mlTestingLoading || !selectedDataset}
                onClick={handleRunMlTest}
              >
                <IconPlay size={14} />
                <span>{mlTestingLoading ? 'Running Evaluation...' : 'Run Benchmark Evaluation'}</span>
              </button>
            </div>

            {/* Evaluation Results (if available) */}
            {mlTestResult ? (
              <div className="eval-results-container" style={{ marginTop: '20px' }}>
                <div className="telemetry-strip-grid">
                  <article className="telemetry-card">
                    <span className="telemetry-card-label">Model Accuracy</span>
                    <strong className="telemetry-card-val" style={{ color: '#34d399' }}>
                      {mlTestResult.accuracy !== undefined ? `${(mlTestResult.accuracy * 100).toFixed(2)}%` : '--'}
                    </strong>
                    <span className="telemetry-card-sub">Overall Correct</span>
                  </article>

                  <article className="telemetry-card">
                    <span className="telemetry-card-label">Precision</span>
                    <strong className="telemetry-card-val">
                      {mlTestResult.precision !== undefined ? `${(mlTestResult.precision * 100).toFixed(2)}%` : '--'}
                    </strong>
                    <span className="telemetry-card-sub">Positive Predictive Value</span>
                  </article>

                  <article className="telemetry-card">
                    <span className="telemetry-card-label">Recall / Sensitivity</span>
                    <strong className="telemetry-card-val">
                      {mlTestResult.recall !== undefined ? `${(mlTestResult.recall * 100).toFixed(2)}%` : '--'}
                    </strong>
                    <span className="telemetry-card-sub">True Positive Rate</span>
                  </article>

                  <article className="telemetry-card">
                    <span className="telemetry-card-label">F1-Score</span>
                    <strong className="telemetry-card-val" style={{ color: 'var(--accent-text)' }}>
                      {mlTestResult.f1_score !== undefined ? `${(mlTestResult.f1_score * 100).toFixed(2)}%` : '--'}
                    </strong>
                    <span className="telemetry-card-sub">Harmonic Mean</span>
                  </article>
                </div>

                {/* Confusion Matrix */}
                {mlTestResult.confusion_matrix && (
                  <div className="panel matrix-panel" style={{ marginTop: '16px' }}>
                    <h4>Confusion Matrix Breakdown</h4>
                    <div className="matrix-grid">
                      <div className="matrix-cell">
                        <span className="matrix-label">True Negative (Normal correctly identified)</span>
                        <strong className="matrix-val">{mlTestResult.confusion_matrix.tn ?? mlTestResult.confusion_matrix[0]?.[0] ?? '--'}</strong>
                      </div>
                      <div className="matrix-cell">
                        <span className="matrix-label">False Positive (Normal classified as Attack)</span>
                        <strong className="matrix-val error-text">{mlTestResult.confusion_matrix.fp ?? mlTestResult.confusion_matrix[0]?.[1] ?? '--'}</strong>
                      </div>
                      <div className="matrix-cell">
                        <span className="matrix-label">False Negative (Attack missed)</span>
                        <strong className="matrix-val error-text">{mlTestResult.confusion_matrix.fn ?? mlTestResult.confusion_matrix[1]?.[0] ?? '--'}</strong>
                      </div>
                      <div className="matrix-cell">
                        <span className="matrix-label">True Positive (Attack correctly detected)</span>
                        <strong className="matrix-val success-text">{mlTestResult.confusion_matrix.tp ?? mlTestResult.confusion_matrix[1]?.[1] ?? '--'}</strong>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="empty-state" style={{ marginTop: '20px' }}>
                <p className="empty-state-title">Select a Dataset and Click Run</p>
                <p className="empty-state-text">
                  The system will run batch classification on the selected test dataset and generate accuracy, precision, recall, and confusion matrix reports.
                </p>
              </div>
            )}
          </div>

          {/* Historical Runs */}
          {mlTestRuns && mlTestRuns.length > 0 && (
            <div className="panel history-panel" style={{ marginTop: '16px' }}>
              <div className="panel-header">
                <div>
                  <h3>Evaluation Run History</h3>
                  <p className="panel-subtitle">Past offline benchmark evaluations saved in database.</p>
                </div>
              </div>

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Run ID</th>
                      <th>Timestamp</th>
                      <th>Dataset</th>
                      <th>Samples</th>
                      <th>Accuracy</th>
                      <th>F1-Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mlTestRuns.map((run) => (
                      <tr key={run.id}>
                        <td className="mono-val">#{run.id}</td>
                        <td>{formatDateTime(run.created_at)}</td>
                        <td>{run.dataset_name || run.dataset_path || 'Test Set'}</td>
                        <td className="mono-val">{formatValue(run.total_samples)}</td>
                        <td className="mono-val success-text">
                          {run.accuracy !== undefined ? `${(run.accuracy * 100).toFixed(1)}%` : '--'}
                        </td>
                        <td className="mono-val">
                          {run.f1_score !== undefined ? `${(run.f1_score * 100).toFixed(1)}%` : '--'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: MODEL & 31-FEATURE SCHEMA SPECIFICATION */}
      {mlEngineTab === 'schema' && (
        <div className="ml-tab-content">
          <div className="panel schema-overview-panel">
            <div className="panel-header">
              <div>
                <h3>AWID3 Intrusion Detection Model Specification</h3>
                <p className="panel-subtitle">
                  Technical specifications of the Random Forest model and canonical feature schema.
                </p>
              </div>
            </div>

            <div className="spec-grid">
              <div className="spec-card">
                <span className="spec-label">Model File</span>
                <strong className="spec-val mono-val">{mlSchemaInfo?.model_name || 'random_forest_awid3_v3_expanded.joblib'}</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Classification Mode</span>
                <strong className="spec-val">Binary (0: Normal Traffic, 1: Attack)</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Canonical Feature Count</span>
                <strong className="spec-val" style={{ color: 'var(--accent-text)' }}>
                  {mlSchemaInfo?.feature_count ?? 31} Features
                </strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Algorithm Architecture</span>
                <strong className="spec-val">Random Forest Ensemble (Decision Trees)</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Feature Order Enforcement</span>
                <strong className="spec-val success-text">Strict Schema Index Validation</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Target Field</span>
                <strong className="spec-val mono-val">{mlSchemaInfo?.target_column || 'Label'}</strong>
              </div>
            </div>

            {/* Collapsible 31 Canonical Features Details Section */}
            <div className="collapsible-section" style={{ marginTop: '20px' }}>
              <div
                className="collapsible-header"
                onClick={() => setShowAdvancedSchema(!showAdvancedSchema)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    setShowAdvancedSchema(!showAdvancedSchema)
                  }
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span className="collapsible-toggle-icon">{showAdvancedSchema ? '▼' : '►'}</span>
                  <h4>Inspect 31 Canonical AWID3 Feature Definitions</h4>
                </div>
                <span className="badge badge-default">
                  {showAdvancedSchema ? 'Collapse Schema' : 'Expand Schema'}
                </span>
              </div>

              {showAdvancedSchema && (
                <div className="collapsible-body" style={{ marginTop: '12px' }}>
                  <p className="schema-intro-text">
                    The AWID3 intrusion detection pipeline transforms raw 802.11 frames into 31 time-window statistics capturing packet burst dynamics, inter-arrival times, sequence fluctuations, and frame subtype counts:
                  </p>

                  <div className="feature-tags-grid">
                    {features.length > 0 ? (
                      features.map((feat, idx) => (
                        <div className="feature-item-card" key={feat}>
                          <span className="feature-idx mono-val">#{idx + 1}</span>
                          <span className="feature-name mono-val">{feat}</span>
                        </div>
                      ))
                    ) : (
                      <div className="empty-state-muted">
                        Loading feature definitions from /api/ml/test/schema...
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
