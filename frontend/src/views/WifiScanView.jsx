import React from 'react'
import {
  formatValue,
  getValue,
  getInterfaceName,
} from '../utils/helpers'
import {
  IconWifi,
  IconPlay,
  IconSquare,
  IconSearch,
  IconLock,
  IconUnlock,
} from '../components/Icons'

export const WifiScanView = ({
  wifiScanError,
  isScannerRunning,
  isScannerStarting,
  isScannerStopping,
  isScannerActive,
  scannerStatus,
  selectableInterfaces,
  selectedInterfaceName,
  setSelectedInterfaceName,
  selectedInterface,
  wirelessAdapter,
  scannerProgress,
  networks,
  filteredScanNetworks,
  startScanDisabled,
  stopScanDisabled,
  handleStartScan,
  handleStopScan,
  wifiScanLoading,
  scanSearch,
  setScanSearch,
  scanFilter,
  setScanFilter,
  setActiveView,
}) => {
  const channelCount = networks.length

  return (
    <section className="wifi-scan-view" aria-label="Wi-Fi spectrum scan">
      {wifiScanError && <p className="error-banner">{wifiScanError}</p>}

      {/* Control & Telemetry Panel */}
      <div className="panel scan-control-panel">
        <div className="control-bar-row">
          <div className="control-bar-info">
            <div className="control-title-group">
              <h2 className="section-title">Wi-Fi Spectrum Scanner</h2>
              <span
                className={`badge ${
                  isScannerRunning
                    ? 'badge-status-resolved'
                    : isScannerStarting || isScannerStopping
                      ? 'badge-severity-medium'
                      : 'badge-default'
                }`}
              >
                {formatValue(
                  getValue(scannerStatus, ['state', 'scanner_state', 'status']) ||
                    (isScannerRunning ? 'Scanning' : 'Idle')
                )}
              </span>
            </div>

            <div className="meta-pills-row">
              {selectableInterfaces.length > 1 ? (
                <label className="adapter-select-label">
                  <span>Interface:</span>
                  <select
                    disabled={isScannerActive}
                    onChange={(e) => setSelectedInterfaceName(e.target.value)}
                    value={selectedInterfaceName}
                    className="adapter-select"
                  >
                    {selectableInterfaces.map((adapter) => {
                      const name = getInterfaceName(adapter)
                      return (
                        <option key={name} value={name}>
                          {name}
                        </option>
                      )
                    })}
                  </select>
                </label>
              ) : (
                <span className="scan-meta-pill">
                  Interface: <strong>{selectedInterface || 'None Detected'}</strong>
                </span>
              )}

              {wirelessAdapter && (
                <span className="scan-meta-pill">
                  Mode: <strong>{formatValue(getValue(wirelessAdapter, ['mode']))}</strong>
                </span>
              )}

              <span className="scan-meta-pill">
                Discovered:{' '}
                <strong style={{ color: 'var(--accent-text)' }}>
                  {formatValue(getValue(scannerProgress, ['session_network_count']) || channelCount)} APs
                </strong>
              </span>

              {isScannerRunning && (
                <span className="scan-meta-pill">
                  Sweep: <strong>#{formatValue(getValue(scannerProgress, ['sweep_number']) || 1)}</strong> (Ch{' '}
                  {formatValue(getValue(scannerProgress, ['current_channel']) || '--')})
                </span>
              )}
            </div>
          </div>

          <div className="control-bar-actions">
            <button
              className="btn btn-primary"
              disabled={startScanDisabled}
              onClick={handleStartScan}
              type="button"
            >
              <IconPlay size={14} />
              <span>{isScannerStarting ? 'Starting...' : isScannerRunning ? 'Scanning...' : 'Start Scan'}</span>
            </button>
            <button
              className="btn btn-secondary"
              disabled={stopScanDisabled}
              onClick={handleStopScan}
              type="button"
            >
              <IconSquare size={14} />
              <span>{isScannerStopping ? 'Stopping...' : 'Stop Scan'}</span>
            </button>
          </div>
        </div>

        {/* Warning if no wireless adapter is present */}
        {!wirelessAdapter && !wifiScanLoading && (
          <div className="empty-state-notice">
            <p>
              <strong>Notice:</strong> No compatible wireless adapter was detected on this operating system. Active channel sweeping requires a compatible Wi-Fi interface (e.g., in Linux / Kali). Any previously cached networks are listed below.
            </p>
          </div>
        )}

        {/* Search & Filter Toolbar */}
        <div className="scan-toolbar">
          <div className="search-box">
            <IconSearch size={16} className="search-icon" />
            <input
              aria-label="Filter networks by SSID, BSSID, or Vendor"
              className="search-input"
              onChange={(e) => setScanSearch(e.target.value)}
              placeholder="Search by SSID, BSSID, vendor, or security..."
              type="text"
              value={scanSearch}
            />
          </div>

          <div className="filter-chips">
            <button
              className={`filter-chip ${scanFilter === 'all' ? 'active' : ''}`}
              onClick={() => setScanFilter('all')}
              type="button"
            >
              All ({networks.length})
            </button>
            <button
              className={`filter-chip ${scanFilter === '5ghz' ? 'active' : ''}`}
              onClick={() => setScanFilter('5ghz')}
              type="button"
            >
              5 GHz ({networks.filter((n) => Number(getValue(n, ['channel', 'Channel'])) >= 36).length})
            </button>
            <button
              className={`filter-chip ${scanFilter === '2ghz' ? 'active' : ''}`}
              onClick={() => setScanFilter('2ghz')}
              type="button"
            >
              2.4 GHz ({networks.filter((n) => {
                const ch = Number(getValue(n, ['channel', 'Channel'])) || 0
                return ch > 0 && ch <= 14
              }).length})
            </button>
            <button
              className={`filter-chip ${scanFilter === 'secured' ? 'active' : ''}`}
              onClick={() => setScanFilter('secured')}
              type="button"
            >
              Secured ({networks.filter((n) => {
                const enc = String(getValue(n, ['encryption', 'security']) || '').toUpperCase()
                return enc.includes('WPA') || enc.includes('WEP') || enc.includes('802.1X')
              }).length})
            </button>
            <button
              className={`filter-chip ${scanFilter === 'open' ? 'active' : ''}`}
              onClick={() => setScanFilter('open')}
              type="button"
            >
              Open ({networks.filter((n) => {
                const enc = String(getValue(n, ['encryption', 'security']) || '').toUpperCase()
                return enc.includes('OPEN') || enc === '' || enc === 'NONE'
              }).length})
            </button>
          </div>
        </div>
      </div>

      {/* Networks Table */}
      <div className="panel networks-panel">
        <div className="panel-header">
          <div>
            <h3>Discovered Wireless Access Points</h3>
            <p className="panel-subtitle">
              Showing {filteredScanNetworks.length} of {networks.length} networks matching current criteria.
            </p>
          </div>
          {networks.length > 0 && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setActiveView('Network Recommendations')}
            >
              Analyze with ML QoS &rarr;
            </button>
          )}
        </div>

        {wifiScanLoading && networks.length === 0 ? (
          <div className="empty-state">
            <p className="empty-state-title">Loading Scanned Networks...</p>
          </div>
        ) : networks.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>SSID &amp; Access Point</th>
                  <th>Band &amp; Channel</th>
                  <th>Signal Strength</th>
                  <th>Security / Encryption</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScanNetworks.length > 0 ? (
                  filteredScanNetworks.map((network, index) => {
                    const bssid = formatValue(getValue(network, ['bssid', 'BSSID']))
                    const ssid = formatValue(getValue(network, ['ssid', 'SSID']))
                    const vendor = getValue(network, ['vendor', 'Vendor'])
                    const ch = Number(getValue(network, ['channel', 'Channel'])) || 0
                    const band = ch >= 36 ? '5 GHz' : ch > 0 ? '2.4 GHz' : 'Auto'
                    const sigRaw = formatValue(getValue(network, ['signal', 'Signal']))
                    const sigNum = parseInt(String(sigRaw || '').replace(/[^0-9-]/g, ''), 10)
                    const enc = formatValue(getValue(network, ['encryption', 'security']))
                    const isOpen = String(enc || '').toUpperCase().includes('OPEN') || enc === 'None' || !enc

                    // Signal percentage for visual meter (-100 dBm is 0%, -40 dBm is 100%)
                    const sigPct = Math.min(100, Math.max(0, ((sigNum + 100) / 60) * 100))

                    return (
                      <tr key={bssid || index}>
                        <td>
                          <div className="net-ssid-cell">
                            <strong>{ssid || '<Hidden SSID>'}</strong>
                            <span className="mono-val net-bssid-sub">{bssid || 'Unknown BSSID'}</span>
                            {vendor && vendor !== 'Unknown Vendor' && vendor !== 'Unknown' && (
                              <span className="net-vendor-chip">{vendor}</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="band-cell">
                            <span className="mono-val">Ch {ch || '?'}</span>
                            <span className="band-sub">{band}</span>
                          </div>
                        </td>
                        <td>
                          <div className="signal-cell">
                            <span
                              className="mono-val"
                              style={{
                                color:
                                  sigNum >= -65
                                    ? '#2dd4bf'
                                    : sigNum >= -75
                                      ? '#38bdf8'
                                      : sigNum >= -85
                                        ? '#fbbf24'
                                        : '#f87171',
                              }}
                            >
                              {sigRaw || '--'}
                            </span>
                            <div className="signal-bar-track">
                              <div
                                className="signal-bar-fill"
                                style={{
                                  width: `${sigPct}%`,
                                  backgroundColor:
                                    sigNum >= -65
                                      ? '#2dd4bf'
                                      : sigNum >= -75
                                        ? '#38bdf8'
                                        : sigNum >= -85
                                          ? '#fbbf24'
                                          : '#f87171',
                                }}
                              />
                            </div>
                          </div>
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              isOpen ? 'badge-severity-high' : 'badge-status-resolved'
                            }`}
                          >
                            {isOpen ? (
                              <>
                                <IconUnlock size={12} /> Open
                              </>
                            ) : (
                              <>
                                <IconLock size={12} /> {enc || 'WPA2/WPA3'}
                              </>
                            )}
                          </span>
                        </td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => setActiveView('Network Recommendations')}
                            title="Evaluate quality with the ML Recommendation Engine"
                          >
                            QoS Rank
                          </button>
                        </td>
                      </tr>
                    )
                  })
                ) : (
                  <tr>
                    <td colSpan="5">
                      <div className="empty-state" style={{ padding: '24px' }}>
                        <p className="empty-state-title">No Networks Matched Your Search</p>
                        <p className="empty-state-text">
                          Try adjusting your search query or reset filter chips.
                        </p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-state-icon">
              <IconWifi size={28} />
            </div>
            <p className="empty-state-title">No Wi-Fi Networks Discovered</p>
            <p className="empty-state-text">
              Click &ldquo;Start Scan&rdquo; above to sweep available Wi-Fi channels and discover nearby access points.
            </p>
          </div>
        )}
      </div>
    </section>
  )
}
