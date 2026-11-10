import React from 'react'
import {
  formatValue,
  getValue,
  getInterfaceName,
} from '../utils/helpers'
import { IconWifi } from '../components/Icons'

export const WifiScanView = ({
  wifiScanError,
  isScannerRunning,
  isScannerStarting,
  isScannerStopping,
  isScannerActive,
  scannerStatus,
  selectableInterfaces = [],
  selectedInterfaceName,
  setSelectedInterfaceName,
  selectedInterface,
  wirelessAdapter,
  scannerProgress = {},
  networks = [],
  filteredScanNetworks = [],
  startScanDisabled,
  stopScanDisabled,
  handleStartScan,
  handleStopScan,
  wifiScanLoading,
  scanSearch,
  setScanSearch,
  scanFilter,
  setScanFilter,
  handleOpenConnectModal,
}) => {
  return (
    <div className="wifi-scan-view" aria-label="Wi-Fi scan">
      {wifiScanError ? <p className="error-banner">{wifiScanError}</p> : null}

      {/* Unified Control & Telemetry Bar (AegisWLAN Design) */}
      <section className="panel wifi-scan-control-panel">
        <div className="scan-control-row">
          <div className="scan-control-left">
            <div className="scan-title-wrap">
              <h2 className="scan-page-title">
                Wi-Fi Spectrum Scanner
              </h2>
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
                    (isScannerRunning ? 'Running' : 'Idle'),
                )}
              </span>
            </div>

            {selectableInterfaces.length > 1 ? (
              <label className="adapter-select-inline">
                <span>Interface:</span>
                <select
                  disabled={isScannerActive}
                  onChange={(e) => setSelectedInterfaceName(e.target.value)}
                  value={selectedInterfaceName}
                >
                  {selectableInterfaces.map((adapter) => {
                    const adapterName = getInterfaceName(adapter)
                    return (
                      <option key={adapterName} value={adapterName}>
                        {adapterName}
                      </option>
                    )
                  })}
                </select>
              </label>
            ) : (
              <span className="scan-meta-pill">
                Interface: <strong>{selectedInterface || 'None'}</strong>
              </span>
            )}

            {wirelessAdapter ? (
              <span className="scan-meta-pill">
                Mode: <strong>{formatValue(getValue(wirelessAdapter, ['mode']))}</strong>
              </span>
            ) : null}

            <span className="scan-meta-pill">
              Sweep: <strong>#{formatValue(getValue(scannerProgress, ['sweep_number']) || 1)}</strong> (Ch{' '}
              {formatValue(getValue(scannerProgress, ['current_channel']) || '--')} &bull;{' '}
              {formatValue(getValue(scannerProgress, ['channels_completed']) || 0)}/
              {formatValue(getValue(scannerProgress, ['total_channels']) || 14)})
            </span>

            <span className="scan-meta-pill">
              Discovered:{' '}
              <strong style={{ color: 'var(--accent-text)' }}>
                {formatValue(getValue(scannerProgress, ['session_network_count']) || networks.length)} APs
              </strong>
            </span>
          </div>

          <div className="scan-control-right">
            <button
              className="scan-button primary"
              disabled={startScanDisabled}
              onClick={handleStartScan}
              type="button"
            >
              {isScannerStarting ? 'Starting...' : isScannerRunning ? 'Scanning...' : 'Start Scan'}
            </button>
            <button
              className="scan-button"
              disabled={stopScanDisabled}
              onClick={handleStopScan}
              type="button"
            >
              {isScannerStopping ? 'Stopping...' : 'Stop Scan'}
            </button>
          </div>
        </div>

        {!wirelessAdapter && !wifiScanLoading ? (
          <div className="empty-state-notice">
            <p>
              No wireless adapter detected. Connect a compatible Wi-Fi adapter to enable channel sweeping.
            </p>
          </div>
        ) : null}

        {/* Filter Toolbar */}
        <div className="scan-filter-toolbar">
          <div className="search-box">
            <input
              aria-label="Filter networks by SSID, BSSID, or Vendor"
              className="search-input"
              onChange={(e) => setScanSearch(e.target.value)}
              placeholder="Search by SSID, BSSID, or vendor..."
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
      </section>

      {/* Scanned Networks Table Panel */}
      <section className="panel networks-panel">
        {wifiScanLoading && networks.length === 0 ? (
          <p className="muted-text" style={{ padding: '24px' }}>Loading scanned networks...</p>
        ) : networks.length > 0 ? (
          <div className="table-wrap wifi-scan-table-scroll">
            <table>
              <thead>
                <tr>
                  <th>SSID &amp; Access Point</th>
                  <th>Band &amp; Channel</th>
                  <th>Signal Strength</th>
                  <th>Encryption / Security</th>
                  <th style={{ width: '100px', textAlign: 'right' }}>Action</th>
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
                    const enc = formatValue(getValue(network, ['encryption', 'Encryption', 'security']))
                    const isOpen = String(enc || '').toUpperCase().includes('OPEN') || enc === 'None' || !enc

                    return (
                      <tr key={bssid || index}>
                        <td>
                          <div className="net-ssid-cell">
                            <strong>{ssid || '<Hidden SSID>'}</strong>
                            <span className="net-bssid-sub">{bssid || 'Unknown BSSID'}</span>
                            {vendor && vendor !== 'Unknown Vendor' && vendor !== 'Unknown' ? (
                              <span className="net-vendor-chip">{vendor}</span>
                            ) : null}
                          </div>
                        </td>
                        <td>
                          <span className="mono-val">Ch {ch || '?'}</span>
                          <span className="band-sub">{band}</span>
                        </td>
                        <td>
                          <span
                            className="mono-val"
                            style={{
                              color:
                                sigNum >= -65
                                  ? 'var(--success-text)'
                                  : sigNum >= -75
                                    ? 'var(--accent)'
                                    : sigNum >= -85
                                      ? 'var(--warning-text)'
                                      : 'var(--danger-text)',
                              fontWeight: 600,
                            }}
                          >
                            {sigRaw || '--'}
                          </span>
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              isOpen ? 'badge-severity-high' : 'badge-status-resolved'
                            }`}
                          >
                            {enc || 'Open'}
                          </span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            className="scan-button small"
                            onClick={() => {
                              if (handleOpenConnectModal) {
                                handleOpenConnectModal({
                                  ssid,
                                  bssid,
                                  channel: ch,
                                  signal: sigRaw,
                                  encryption: enc,
                                  vendor,
                                })
                              }
                            }}
                          >
                            Connect
                          </button>
                        </td>
                      </tr>
                    )
                  })
                ) : (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', padding: '32px' }}>
                      <p style={{ color: 'var(--text-strong)', marginBottom: '8px' }}>
                        No networks match &ldquo;{scanSearch}&rdquo;
                      </p>
                      <button
                        className="scan-button"
                        onClick={() => {
                          setScanSearch('')
                          setScanFilter('all')
                        }}
                        type="button"
                      >
                        Clear Filter
                      </button>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state" style={{ padding: '36px 20px', textAlign: 'center' }}>
            <div style={{ display: 'inline-flex', padding: '12px', borderRadius: '50%', background: 'var(--nav-selected)', color: 'var(--accent)', marginBottom: '12px' }}>
              <IconWifi size={28} />
            </div>
            <p style={{ fontWeight: 600, color: 'var(--text-strong)', margin: '0 0 6px' }}>
              No scanned networks are available.
            </p>
            <p className="muted-text" style={{ margin: '0 0 16px', fontSize: '13px' }}>
              Click Start Scan to discover nearby wireless access points.
            </p>
            <button
              className="scan-button primary"
              disabled={startScanDisabled}
              onClick={handleStartScan}
              type="button"
            >
              Start Scan
            </button>
          </div>
        )}
      </section>
    </div>
  )
}
