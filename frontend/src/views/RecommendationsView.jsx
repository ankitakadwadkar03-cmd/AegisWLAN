import React from 'react'
import {
  formatConfidence,
  getRecommendationBadgeClass,
} from '../utils/helpers'
import {
  IconStar,
  IconWifi,
  IconBot,
  IconCheck,
} from '../components/Icons'

export const RecommendationsView = ({
  _recommendationsData,
  recommendationsLoading,
  recommendationsError,
  loadRecommendationsData,
  recommendationFilter,
  setRecommendationFilter,
  recommendationSort,
  setRecommendationSort,
  filteredRecommendations,
  bestNetwork,
  recList,
  totalScannedRecs,
  handleOpenConnectModal,
  advisorOpen,
  setAdvisorOpen,
  _showRankingExplanation,
  _setShowRankingExplanation,
  _showRunnerUpComparison,
  _setShowRunnerUpComparison,
  showModelBreakdown,
  setShowModelBreakdown,
  recommendationModelInfo,
  setActiveView,
}) => {
  return (
    <section className="recommendations-view" aria-label="Wi-Fi network recommendations">
      {recommendationsError && <p className="error-banner">{recommendationsError}</p>}

      {/* Control & Header Panel */}
      <div className="panel scan-control-panel">
        <div className="control-bar-row">
          <div className="control-bar-info">
            <div className="control-title-group">
              <h2 className="section-title">Smart Wi-Fi QoS &amp; Network Recommendation</h2>
              <span className="badge badge-rec-excellent">Random Forest QoS Model</span>
            </div>
            <p className="panel-subtitle">
              Scan-level QoS and wireless connection scoring evaluated by a dedicated 12-feature machine learning model (distinct from AWID3 intrusion detection).
            </p>
          </div>

          <div className="control-bar-actions">
            <button
              className="btn btn-primary"
              disabled={recommendationsLoading}
              onClick={() => loadRecommendationsData()}
              type="button"
            >
              <IconStar size={14} />
              <span>{recommendationsLoading ? 'Evaluating Networks...' : 'Refresh Rankings'}</span>
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => setActiveView('WiFi Scan')}
              type="button"
            >
              <IconWifi size={14} />
              <span>Wi-Fi Scan</span>
            </button>
            <button
              className={`btn btn-secondary ${advisorOpen ? 'btn-active' : ''}`}
              onClick={() => setAdvisorOpen(!advisorOpen)}
              type="button"
              title="Open AI Wi-Fi Assistant"
            >
              <IconBot size={14} />
              <span>AI Advisor</span>
            </button>
          </div>
        </div>

        {/* 5-Stage Pipeline Progress Strip */}
        <div className="pipeline-steps-bar">
          <div className="pipeline-step-item">
            <span className="step-num">1</span>
            <span className="step-label">Spectrum Scan Ingest</span>
          </div>
          <span className="step-arrow">&rarr;</span>
          <div className="pipeline-step-item">
            <span className="step-num">2</span>
            <span className="step-label">12-Feature Extraction</span>
          </div>
          <span className="step-arrow">&rarr;</span>
          <div className="pipeline-step-item">
            <span className="step-num">3</span>
            <span className="step-label">Random Forest Inference</span>
          </div>
          <span className="step-arrow">&rarr;</span>
          <div className="pipeline-step-item">
            <span className="step-num">4</span>
            <span className="step-label">4-Tier Classification</span>
          </div>
          <span className="step-arrow">&rarr;</span>
          <div className="pipeline-step-item">
            <span className="step-num">5</span>
            <span className="step-label">Ranked Recommendation</span>
          </div>
        </div>
      </div>

      {/* Hero Card: #1 Best Recommended Network */}
      {bestNetwork ? (
        <div className="panel best-rec-hero-card">
          <div className="hero-rec-header">
            <div className="hero-badge-group">
              <span className="hero-top-badge">
                <IconStar size={14} /> #1 TOP RECOMMENDED NETWORK
              </span>
              <span className={getRecommendationBadgeClass(bestNetwork.classification)}>
                {bestNetwork.classification} Quality Tier
              </span>
            </div>

            <div className="hero-score-badge">
              <div className="score-val-wrap">
                <span className="score-label">ML Score:</span>
                <strong className="score-val">{bestNetwork.score?.toFixed(1) || '--'}</strong>
                <span className="score-max">/ 100</span>
              </div>
              <span className="score-conf">
                Confidence: {formatConfidence(bestNetwork.confidence_pct)}
              </span>
            </div>
          </div>

          <div className="hero-rec-body">
            <div className="hero-rec-details">
              <div className="hero-network-id">
                <h3 className="hero-ssid">{bestNetwork.ssid || '<Hidden SSID>'}</h3>
                <div className="hero-meta-row">
                  <span className="mono-val hero-bssid">{bestNetwork.bssid || 'BSSID Unknown'}</span>
                  {bestNetwork.vendor && bestNetwork.vendor !== 'Unknown Vendor' && (
                    <span className="net-vendor-chip">{bestNetwork.vendor}</span>
                  )}
                </div>
              </div>

              {bestNetwork.recommendation_reason && (
                <p className="hero-rec-summary">
                  {bestNetwork.recommendation_reason}
                </p>
              )}

              <div className="hero-stats-grid">
                <div className="hero-stat-item">
                  <span className="stat-label">Signal Level</span>
                  <strong className="stat-val" style={{ color: '#2dd4bf' }}>{bestNetwork.signal}</strong>
                </div>
                <div className="hero-stat-item">
                  <span className="stat-label">Frequency Band</span>
                  <strong className="stat-val">{bestNetwork.band}</strong>
                </div>
                <div className="hero-stat-item">
                  <span className="stat-label">Operating Channel</span>
                  <strong className="stat-val">Ch {bestNetwork.channel || '?'}</strong>
                </div>
                <div className="hero-stat-item">
                  <span className="stat-label">Security Protocol</span>
                  <strong className="stat-val">{bestNetwork.security}</strong>
                </div>
                <div className="hero-stat-item">
                  <span className="stat-label">Channel Congestion</span>
                  <strong className="stat-val">
                    {bestNetwork.features?.channel_congestion_count !== undefined
                      ? `${bestNetwork.features.channel_congestion_count} APs`
                      : 'Low Interference'}
                  </strong>
                </div>
              </div>

              {/* Explainability Strengths & Selection Factors */}
              {bestNetwork.positive_factors && bestNetwork.positive_factors.length > 0 && (
                <div className="factors-row">
                  <span className="factors-label">Strengths &amp; Selection Factors:</span>
                  <div className="factors-chips">
                    {bestNetwork.positive_factors.map((f, i) => (
                      <span key={i} className="factor-chip positive">
                        <IconCheck size={12} />
                        <span>{f}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="hero-rec-action-side">
              <button
                type="button"
                className="btn btn-primary btn-large"
                onClick={() => handleOpenConnectModal(bestNetwork)}
              >
                <span>Connect to Network &rarr;</span>
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {/* Filter and Sort Toolbar */}
      <div className="panel filter-bar-panel" style={{ marginTop: '16px' }}>
        <div className="filter-bar-content">
          <div className="filter-group">
            <span className="filter-label">Filter:</span>
            <button
              type="button"
              className={`filter-chip ${recommendationFilter === 'all' ? 'active' : ''}`}
              onClick={() => setRecommendationFilter('all')}
            >
              All ({recList.length})
            </button>
            <button
              type="button"
              className={`filter-chip ${recommendationFilter === 'recommended' ? 'active' : ''}`}
              onClick={() => setRecommendationFilter('recommended')}
            >
              Recommended (Tier &ge; GOOD)
            </button>
            <button
              type="button"
              className={`filter-chip ${recommendationFilter === '5ghz' ? 'active' : ''}`}
              onClick={() => setRecommendationFilter('5ghz')}
            >
              5 GHz Band
            </button>
            <button
              type="button"
              className={`filter-chip ${recommendationFilter === 'secure' ? 'active' : ''}`}
              onClick={() => setRecommendationFilter('secure')}
            >
              Secured Only
            </button>
          </div>

          <div className="filter-group">
            <span className="filter-label">Sort By:</span>
            <select
              value={recommendationSort}
              onChange={(e) => setRecommendationSort(e.target.value)}
              className="settings-select"
              style={{ width: 'auto', padding: '4px 10px', fontSize: '13px' }}
            >
              <option value="score">ML Recommendation Score (High &rarr; Low)</option>
              <option value="signal">Signal Strength (dBm)</option>
              <option value="security">Security Protocol</option>
              <option value="channel">Channel Number</option>
            </select>
          </div>

          <span className="filter-results-count">
            Showing <strong>{filteredRecommendations.length}</strong> of {totalScannedRecs} networks
          </span>
        </div>
      </div>

      {/* Ranked Networks List */}
      <div className="panel ranked-networks-panel" style={{ marginTop: '16px' }}>
        <div className="panel-header">
          <div>
            <h3>Complete Ranked Network Register</h3>
            <p className="panel-subtitle">Evaluated on 12 IEEE 802.11 QoS, throughput, and encryption metrics.</p>
          </div>
        </div>

        {recommendationsLoading && recList.length === 0 ? (
          <div className="empty-state">
            <p className="empty-state-title">Evaluating Wi-Fi Networks with ML QoS Model...</p>
          </div>
        ) : filteredRecommendations.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rank &amp; SSID</th>
                  <th>Quality Tier</th>
                  <th>Score / 100</th>
                  <th>Signal</th>
                  <th>Band &amp; Channel</th>
                  <th>Security</th>
                  <th>Key Strength</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecommendations.map((net, idx) => {
                  const rank = net.rank ?? idx + 1
                  const isTop = rank === 1

                  return (
                    <tr key={net.bssid || idx} className={isTop ? 'highlight-row' : ''}>
                      <td>
                        <div className="ranked-net-name">
                          <span className={`rank-badge ${isTop ? 'rank-1' : ''}`}>#{rank}</span>
                          <div>
                            <strong>{net.ssid || '<Hidden SSID>'}</strong>
                            <span className="mono-val ranked-bssid-sub">{net.bssid || 'Unknown BSSID'}</span>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className={getRecommendationBadgeClass(net.classification)}>
                          {net.classification}
                        </span>
                      </td>
                      <td>
                        <strong className="mono-val" style={{ color: 'var(--accent-text)' }}>
                          {net.score !== undefined ? net.score.toFixed(1) : '--'}
                        </strong>
                      </td>
                      <td>
                        <span className="mono-val">{net.signal}</span>
                      </td>
                      <td>
                        <span className="mono-val">{net.band} (Ch {net.channel})</span>
                      </td>
                      <td>
                        <span className={`badge ${String(net.security).toLowerCase().includes('open') ? 'badge-severity-high' : 'badge-default'}`}>
                          {net.security}
                        </span>
                      </td>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        {net.positive_factors?.[0] || net.recommendation_reason || 'Adequate signal & WPA'}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleOpenConnectModal(net)}
                        >
                          Connect
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <p className="empty-state-title">No Networks Found</p>
            <p className="empty-state-text">
              Run a Wi-Fi scan in the "Wi-Fi Scan" page to discover wireless networks and compute recommendations.
            </p>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => setActiveView('WiFi Scan')}
              style={{ marginTop: '12px' }}
            >
              Open Wi-Fi Scan &rarr;
            </button>
          </div>
        )}
      </div>

      {/* Model Specifications Collapsible Panel */}
      <div className="panel" style={{ marginTop: '16px' }}>
        <div
          className="collapsible-header"
          onClick={() => setShowModelBreakdown(!showModelBreakdown)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              setShowModelBreakdown(!showModelBreakdown)
            }
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>{showModelBreakdown ? '▼' : '►'}</span>
            <h4>Recommendation Model Details (12 Features)</h4>
          </div>
          <span className="badge badge-default">
            {showModelBreakdown ? 'Collapse' : 'Expand'}
          </span>
        </div>

        {showModelBreakdown && (
          <div className="collapsible-body" style={{ marginTop: '12px' }}>
            <p className="schema-intro-text">
              The recommendation engine uses a Random Forest classifier trained on 12 distinct signal, congestion, security, and protocol metrics to rank Wi-Fi networks into EXCELLENT, GOOD, FAIR, and POOR tiers:
            </p>
            <div className="spec-grid" style={{ marginTop: '12px' }}>
              <div className="spec-card">
                <span className="spec-label">Model Name</span>
                <strong className="spec-val mono-val">{recommendationModelInfo?.model_name || 'wifi_network_recommendation.joblib'}</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Quality Tiers</span>
                <strong className="spec-val">EXCELLENT, GOOD, FAIR, POOR</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Feature Count</span>
                <strong className="spec-val">12 IEEE 802.11 Metrics</strong>
              </div>
              <div className="spec-card">
                <span className="spec-label">Key Deciding Factors</span>
                <strong className="spec-val">RSSI, 5 GHz Band, Channel Overlap, WPA3/WPA2</strong>
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
