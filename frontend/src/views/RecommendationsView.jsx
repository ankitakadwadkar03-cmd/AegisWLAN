import React from 'react'
import {
  formatConfidence,
  getRecommendationBadgeClass,
} from '../utils/helpers'
import {
  IconStar,
  IconWifi,
  IconCheck,
  IconAlertTriangle,
  IconInfo,
  IconLock,
  IconUnlock,
  IconCpu,
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
  filteredRecommendations = [],
  bestNetwork,
  recList = [],
  handleOpenConnectModal,
  handleOpenWhyDrawer,
  _recommendationModelInfo,
  setActiveView,
}) => {
  return (
    <div className="recommendations-container" aria-label="Wi-Fi QoS Network Recommendations">
      {recommendationsError && (
        <div className="error-banner-box">
          <IconAlertTriangle size={16} />
          <span>{recommendationsError}</span>
        </div>
      )}

      {/* Control & Header Panel */}
      <div className="panel rec-control-panel">
        <div className="control-bar-row">
          <div className="control-bar-info">
            <div className="control-title-group">
              <h2 className="section-title">Wi-Fi Connection Recommendations</h2>
              <span className="badge badge-subsystem-rec">
                <IconCpu size={12} /> Wi-Fi Quality Model (12 Features)
              </span>
              <span className="badge badge-default">
                {recList.length} Networks Evaluated
              </span>
            </div>
            <p className="panel-subtitle">
              Intelligent ranking and 4-tier quality prediction (EXCELLENT, GOOD, FAIR, POOR) based on signal strength, channel congestion, and security standards.
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
              <span>{recommendationsLoading ? 'Evaluating...' : 'Refresh Rankings'}</span>
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => setActiveView('WiFi Scan')}
              type="button"
            >
              <IconWifi size={14} />
              <span>Go to Wi-Fi Scan &rarr;</span>
            </button>
          </div>
        </div>
      </div>

      {/* HIGHLIGHTED CARD: #1 TOP RECOMMENDED NETWORK */}
      {bestNetwork ? (
        <section className="panel best-network-hero-card" aria-label="Top Recommended Network">
          <div className="hero-card-accent-bar" />
          <div className="hero-card-content">
            <div className="hero-card-top">
              <div className="hero-rank-tag">
                <IconStar size={14} />
                <span>#1 TOP RECOMMENDED ACCESS POINT</span>
              </div>
              <div className="hero-tier-tag-group">
                <span className={getRecommendationBadgeClass(bestNetwork.classification)}>
                  {bestNetwork.classification} Quality Tier
                </span>
                <span className="hero-score-badge">
                  Score: <strong>{bestNetwork.score?.toFixed(1) || '--'}</strong> / 100
                </span>
                <span className="hero-conf-badge">
                  Confidence: {formatConfidence(bestNetwork.confidence_pct)}
                </span>
              </div>
            </div>

            <div className="hero-network-title-row">
              <div className="hero-title-details">
                <h3 className="hero-network-ssid">{bestNetwork.ssid || '<Hidden SSID>'}</h3>
                <div className="hero-identity-meta">
                  <span className="mono-val hero-bssid-text">{bestNetwork.bssid || 'BSSID Unknown'}</span>
                  {bestNetwork.vendor && bestNetwork.vendor !== 'Unknown Vendor' && (
                    <span className="vendor-pill">{bestNetwork.vendor}</span>
                  )}
                  <span className="security-pill">
                    {bestNetwork.security?.toLowerCase().includes('open') ? (
                      <IconUnlock size={12} />
                    ) : (
                      <IconLock size={12} />
                    )}
                    {bestNetwork.security || 'WPA2-PSK'}
                  </span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="hero-cta-buttons">
                <button
                  type="button"
                  className="btn btn-primary btn-cta"
                  onClick={() => handleOpenConnectModal(bestNetwork)}
                >
                  <IconWifi size={15} />
                  <span>Connect to Network</span>
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-cta-secondary"
                  onClick={() => handleOpenWhyDrawer(bestNetwork)}
                >
                  <IconInfo size={15} />
                  <span>Why This Network?</span>
                </button>
              </div>
            </div>

            {bestNetwork.recommendation_reason && (
              <p className="hero-network-reason">
                {bestNetwork.recommendation_reason}
              </p>
            )}

            {/* Quick Metrics */}
            <div className="hero-metrics-grid">
              <div className="hero-metric-tile">
                <span className="hero-metric-label">Signal Level</span>
                <strong className="hero-metric-val" style={{ color: 'var(--success-text)' }}>
                  {bestNetwork.signal || '--'}
                </strong>
              </div>

              <div className="hero-metric-tile">
                <span className="hero-metric-label">Frequency Band</span>
                <strong className="hero-metric-val">
                  {bestNetwork.band || (bestNetwork.features?.band_is_5ghz ? '5 GHz' : '2.4 GHz')}
                </strong>
              </div>

              <div className="hero-metric-tile">
                <span className="hero-metric-label">Operating Channel</span>
                <strong className="hero-metric-val">Ch {bestNetwork.channel || '?'}</strong>
              </div>

              <div className="hero-metric-tile">
                <span className="hero-metric-label">Channel Saturation</span>
                <strong className="hero-metric-val">
                  {bestNetwork.features?.channel_congestion_count !== undefined
                    ? `${bestNetwork.features.channel_congestion_count} APs`
                    : 'Low Contention'}
                </strong>
              </div>
            </div>

            {/* Strengths List */}
            {bestNetwork.positive_factors && bestNetwork.positive_factors.length > 0 && (
              <div className="hero-factors-row" style={{ marginTop: '10px' }}>
                <span className="hero-factors-title" style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>
                  Key Strengths:
                </span>
                <div className="factors-chip-list" style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
                  {bestNetwork.positive_factors.map((factor, idx) => (
                    <span key={idx} className="badge badge-status-resolved" style={{ fontSize: '11px' }}>
                      <IconCheck size={11} />
                      <span>{factor}</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>
      ) : null}

      {/* FILTER & SORT CONTROLS */}
      {recList.length > 0 && (
        <div className="panel" style={{ padding: '12px 18px' }}>
          <div className="scan-filter-toolbar" style={{ border: 'none', padding: 0 }}>
            <div className="filter-chips">
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', marginRight: '4px' }}>
                Filter:
              </span>
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
                className={`filter-chip ${recommendationFilter === '2ghz' ? 'active' : ''}`}
                onClick={() => setRecommendationFilter('2ghz')}
              >
                2.4 GHz Band
              </button>
            </div>

            <div className="sort-select-group" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <label htmlFor="rec-sort-select" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Sort:
              </label>
              <select
                id="rec-sort-select"
                className="adapter-select"
                value={recommendationSort}
                onChange={(e) => setRecommendationSort(e.target.value)}
              >
                <option value="score">ML Quality Score</option>
                <option value="signal">Signal Strength</option>
                <option value="congestion">Channel Congestion</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* RANKED NETWORKS REGISTER */}
      <div className="panel ranked-register-panel">
        <div className="panel-header">
          <div>
            <h3 className="section-title">Ranked Access Point Register</h3>
            <p className="panel-subtitle">
              All evaluated access points ordered by 12-feature machine learning quality score.
            </p>
          </div>
          {recList.length > 0 && (
            <span className="badge badge-default">
              {filteredRecommendations.length} of {recList.length} Access Points
            </span>
          )}
        </div>

        {recommendationsLoading && recList.length === 0 ? (
          <div className="empty-state">
            <p className="muted-text">Evaluating network quality rankings...</p>
          </div>
        ) : recList.length === 0 ? (
          /* Empty state with Go to Wi-Fi Scan */
          <div className="empty-state" style={{ padding: '32px 16px', textAlign: 'center' }}>
            <div style={{ display: 'inline-flex', padding: '12px', borderRadius: '50%', background: 'var(--nav-selected)', color: 'var(--accent)', marginBottom: '10px' }}>
              <IconWifi size={28} />
            </div>
            <p style={{ fontWeight: 600, color: 'var(--text-strong)', margin: '0 0 6px' }}>
              No Evaluated Networks Available
            </p>
            <p className="muted-text" style={{ margin: '0 0 16px', fontSize: '13px' }}>
              Scan nearby Wi-Fi networks first so the machine learning model can evaluate link quality.
            </p>
            <button
              className="btn btn-primary"
              onClick={() => setActiveView('WiFi Scan')}
              type="button"
            >
              <IconWifi size={14} />
              <span>Go to Wi-Fi Scan</span>
            </button>
          </div>
        ) : filteredRecommendations.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: '60px' }}>Rank</th>
                  <th>SSID &amp; Access Point</th>
                  <th>Band &amp; Channel</th>
                  <th>Signal</th>
                  <th>Security</th>
                  <th>Quality Tier</th>
                  <th>Quality Score</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecommendations.map((net, index) => {
                  const rank = net.rank || index + 1
                  const isTopRank = rank === 1
                  const isOpen = String(net.security || '').toLowerCase().includes('open')
                  const sigRaw = net.signal || '--'
                  const sigNum = parseInt(String(sigRaw).replace(/[^0-9-]/g, ''), 10)

                  return (
                    <tr key={net.bssid || index}>
                      <td>
                        <span
                          className="mono-val"
                          style={{
                            fontWeight: 700,
                            color: isTopRank ? 'var(--accent)' : 'inherit',
                          }}
                        >
                          #{rank}
                        </span>
                      </td>

                      <td>
                        <div className="net-ssid-cell">
                          <strong>{net.ssid || '<Hidden SSID>'}</strong>
                          <span className="net-bssid-sub">{net.bssid || 'Unknown BSSID'}</span>
                          {net.vendor && net.vendor !== 'Unknown Vendor' && (
                            <span className="net-vendor-chip">{net.vendor}</span>
                          )}
                        </div>
                      </td>

                      <td>
                        <span className="mono-val">Ch {net.channel || '?'}</span>
                        <span className="band-sub">
                          {net.band || (net.features?.band_is_5ghz ? '5 GHz' : '2.4 GHz')}
                        </span>
                      </td>

                      <td>
                        <span
                          className="mono-val"
                          style={{
                            color:
                              sigNum >= -65
                                ? 'var(--success-text)'
                                : sigNum >= -75
                                  ? 'var(--accent-cyan-text)'
                                  : sigNum >= -85
                                    ? 'var(--warning-text)'
                                    : 'var(--danger-text)',
                            fontWeight: 600,
                          }}
                        >
                          {sigRaw}
                        </span>
                      </td>

                      <td>
                        <span className={`badge ${isOpen ? 'badge-severity-high' : 'badge-status-resolved'}`}>
                          {net.security || 'WPA2'}
                        </span>
                      </td>

                      <td>
                        <span className={getRecommendationBadgeClass(net.classification)}>
                          {net.classification}
                        </span>
                      </td>

                      <td>
                        <span className="mono-val" style={{ fontWeight: 700 }}>
                          {net.score?.toFixed(1) || '--'}
                        </span>
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}> / 100</span>
                      </td>

                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '6px', alignItems: 'center' }}>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleOpenWhyDrawer(net)}
                            title="Inspect why this network received this rank"
                          >
                            <IconInfo size={12} />
                            <span>Why?</span>
                          </button>

                          <button
                            type="button"
                            className="btn btn-primary btn-sm"
                            onClick={() => handleOpenConnectModal(net)}
                          >
                            <IconWifi size={12} />
                            <span>Connect</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state" style={{ padding: '24px', textAlign: 'center' }}>
            <p style={{ fontWeight: 600, color: 'var(--text-strong)', margin: '0 0 6px' }}>
              No networks match &ldquo;{recommendationFilter}&rdquo;
            </p>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setRecommendationFilter('all')}
              type="button"
            >
              Reset Filter
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
