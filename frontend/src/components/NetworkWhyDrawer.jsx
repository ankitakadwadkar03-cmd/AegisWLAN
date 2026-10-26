import React from 'react'
import {
  formatConfidence,
  getRecommendationBadgeClass,
} from '../utils/helpers'
import {
  IconX,
  IconCheck,
  IconAlertTriangle,
  IconStar,
  IconCpu,
  IconWifi,
  IconShieldAlert,
} from './Icons'

export const NetworkWhyDrawer = ({
  network,
  onClose,
  onConnect,
}) => {
  if (!network) return null

  const features = network.features || {}
  const positiveFactors = network.positive_factors || []
  const negativeFactors = network.negative_factors || []
  const hasFactors = positiveFactors.length > 0 || negativeFactors.length > 0

  return (
    <div className="drawer-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-label="Why this network explanation">
      <div className="drawer-panel why-network-drawer" onClick={(e) => e.stopPropagation()}>
        {/* Drawer Header */}
        <div className="drawer-header">
          <div className="drawer-title-group">
            <div className="drawer-badge-row">
              <span className="badge badge-rec-model">
                <IconCpu size={12} /> Wi-Fi Recommendation Model (12 Features)
              </span>
              <span className={getRecommendationBadgeClass(network.classification)}>
                {network.classification} Tier
              </span>
            </div>
            <h3 className="drawer-title">Why This Network? — Decision Breakdown</h3>
            <p className="drawer-subtitle">
              Transparent, evidence-based explainability for <strong>{network.ssid || '<Hidden Network>'}</strong>
            </p>
          </div>
          <button
            type="button"
            className="drawer-close-btn"
            onClick={onClose}
            aria-label="Close drawer"
          >
            <IconX size={18} />
          </button>
        </div>

        {/* Drawer Content */}
        <div className="drawer-body">
          {/* Section 1: ML Model Output */}
          <div className="drawer-section">
            <h4 className="drawer-section-title">
              <IconStar size={15} /> 1. Machine Learning Model Output
            </h4>
            <div className="why-metrics-grid">
              <div className="why-metric-card">
                <span className="why-metric-label">Predicted Quality Tier</span>
                <strong className="why-metric-val" style={{ color: 'var(--accent-text)' }}>
                  {network.classification || 'UNSPECIFIED'}
                </strong>
                <span className="why-metric-hint">Random Forest Classifier (4 Tiers)</span>
              </div>
              <div className="why-metric-card">
                <span className="why-metric-label">Composite ML Score</span>
                <strong className="why-metric-val">
                  {typeof network.score === 'number' ? network.score.toFixed(1) : network.score || '--'}
                  <span className="why-metric-sub"> / 100</span>
                </strong>
                <span className="why-metric-hint">Weighted QoS Index</span>
              </div>
              <div className="why-metric-card">
                <span className="why-metric-label">Prediction Confidence</span>
                <strong className="why-metric-val">
                  {formatConfidence(network.confidence_pct)}
                </strong>
                <span className="why-metric-hint">Model Softmax Probability</span>
              </div>
              <div className="why-metric-card">
                <span className="why-metric-label">Rank Assignment</span>
                <strong className="why-metric-val" style={{ color: network.rank === 1 ? 'var(--status-warning-text)' : 'var(--text-primary)' }}>
                  #{network.rank || '1'}
                </strong>
                <span className="why-metric-hint">Among Visible Spectrum APs</span>
              </div>
            </div>

            {network.recommendation_reason && (
              <div className="why-summary-quote">
                <strong>Model Recommendation Summary:</strong>
                <p>{network.recommendation_reason}</p>
              </div>
            )}
          </div>

          {/* Section 2: Evidence & Factor Contributions */}
          <div className="drawer-section">
            <h4 className="drawer-section-title">
              <IconCheck size={15} /> 2. Model Feature Contributions &amp; Evidence
            </h4>
            <p className="drawer-section-desc">
              Extracted from physical Wi-Fi beacon telemetry and channel state.
            </p>

            {hasFactors ? (
              <div className="factors-split-container">
                {positiveFactors.length > 0 && (
                  <div className="factors-column positive-col">
                    <span className="factors-col-header">
                      <IconCheck size={14} /> Positive Selection Strengths ({positiveFactors.length})
                    </span>
                    <ul className="factors-list">
                      {positiveFactors.map((factor, idx) => (
                        <li key={idx} className="factor-item positive">
                          <span className="factor-bullet">✓</span>
                          <span>{factor}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {negativeFactors.length > 0 && (
                  <div className="factors-column negative-col">
                    <span className="factors-col-header">
                      <IconAlertTriangle size={14} /> Negative / Degraded Factors ({negativeFactors.length})
                    </span>
                    <ul className="factors-list">
                      {negativeFactors.map((factor, idx) => (
                        <li key={idx} className="factor-item negative">
                          <span className="factor-bullet">⚠</span>
                          <span>{factor}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <div className="empty-factors-notice">
                <p>No anomalous positive or negative factor deviations detected for this network.</p>
              </div>
            )}
          </div>

          {/* Section 3: Extracted 12-Feature Canonical Inputs */}
          <div className="drawer-section">
            <h4 className="drawer-section-title">
              <IconWifi size={15} /> 3. 12-Feature Canonical Model Inputs
            </h4>
            <div className="table-wrap drawer-table-wrap">
              <table className="drawer-table">
                <thead>
                  <tr>
                    <th>Feature Name</th>
                    <th>Observed Value</th>
                    <th>Model Impact / Description</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="mono-val">signal_strength_dbm</td>
                    <td><strong style={{ color: 'var(--accent-text)' }}>{features.signal_strength_dbm ?? network.signal ?? '--'} dBm</strong></td>
                    <td>Raw Received Signal Strength Indicator (RSSI)</td>
                  </tr>
                  <tr>
                    <td className="mono-val">signal_quality_pct</td>
                    <td><strong>{features.signal_quality_pct !== undefined ? `${features.signal_quality_pct}%` : '--'}</strong></td>
                    <td>Normalized 0-100% link budget quality</td>
                  </tr>
                  <tr>
                    <td className="mono-val">channel_number</td>
                    <td>Ch {features.channel_number ?? network.channel ?? '--'}</td>
                    <td>Operating 802.11 center channel frequency</td>
                  </tr>
                  <tr>
                    <td className="mono-val">band_is_5ghz</td>
                    <td>{features.band_is_5ghz === 1 ? '1 (5 GHz Band)' : '0 (2.4 GHz Band)'}</td>
                    <td>High-frequency 5 GHz spectrum indicator</td>
                  </tr>
                  <tr>
                    <td className="mono-val">security_level_rank</td>
                    <td>
                      <span className="badge badge-default">
                        Rank {features.security_level_rank ?? '3'} ({network.security || network.encryption || 'WPA2'})
                      </span>
                    </td>
                    <td>Cryptographic security score (WPA3=4, WPA2=3, WEP=1, Open=0)</td>
                  </tr>
                  <tr>
                    <td className="mono-val">is_open_network</td>
                    <td>{features.is_open_network === 1 ? '1 (Open / Unencrypted)' : '0 (Secured)'}</td>
                    <td>Penalty flag for unauthenticated captive/public access points</td>
                  </tr>
                  <tr>
                    <td className="mono-val">is_hidden_ssid</td>
                    <td>{features.is_hidden_ssid === 1 ? '1 (Hidden)' : '0 (Broadcast)'}</td>
                    <td>SSID beacon broadcast concealment flag</td>
                  </tr>
                  <tr>
                    <td className="mono-val">channel_congestion_count</td>
                    <td><strong>{features.channel_congestion_count ?? 0} competing APs</strong></td>
                    <td>Airtime contention on this frequency channel</td>
                  </tr>
                  <tr>
                    <td className="mono-val">co_channel_interference_risk</td>
                    <td>{features.co_channel_interference_risk !== undefined ? features.co_channel_interference_risk.toFixed(2) : '--'}</td>
                    <td>Calculated adjacent / co-channel interference probability</td>
                  </tr>
                  <tr>
                    <td className="mono-val">nearby_ap_density</td>
                    <td>{features.nearby_ap_density ?? '--'} APs</td>
                    <td>Total density of access points in current RF sweep</td>
                  </tr>
                  <tr>
                    <td className="mono-val">has_known_vendor</td>
                    <td>{features.has_known_vendor === 1 ? `1 (${network.vendor || 'Verified'})` : '0 (Unknown)'}</td>
                    <td>OUI hardware vendor registry validation</td>
                  </tr>
                  <tr>
                    <td className="mono-val">estimated_snr_proxy</td>
                    <td>{features.estimated_snr_proxy !== undefined ? `${features.estimated_snr_proxy.toFixed(1)} dB` : '--'}</td>
                    <td>Estimated Signal-to-Noise Ratio proxy calculation</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 4: Architecture Boundary Confirmation */}
          <div className="drawer-alert-box info">
            <IconShieldAlert size={16} />
            <div>
              <strong>Subsystem Boundary Note:</strong>
              <p>
                This ranking is generated exclusively by the dedicated 12-feature Wi-Fi Recommendation ML model (<code>wifi_network_recommendation.joblib</code>). It is completely separate from the AWID3 31-feature Intrusion Detection model. A quality tier of POOR indicates low signal or channel congestion, NOT a malicious cyberattack.
              </p>
            </div>
          </div>
        </div>

        {/* Drawer Footer Actions */}
        <div className="drawer-footer">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onClose}
          >
            Close
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              onClose()
              if (onConnect) onConnect(network)
            }}
          >
            <span>Connect to This Network &rarr;</span>
          </button>
        </div>
      </div>
    </div>
  )
}
