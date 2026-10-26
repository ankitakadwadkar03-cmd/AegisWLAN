import React from 'react'
import {
  formatValue,
  formatWithUnit,
  formatProbability,
  getValue,
  getInterfaceName,
} from '../utils/helpers'
import {
  IconActivity,
  IconPlay,
  IconSquare,
  IconCpu,
} from '../components/Icons'

export const LiveMonitorView = ({
  liveMonitorError,
  isCaptureRunning,
  isCaptureStarting,
  isCaptureStopping,
  isCaptureActive,
  captureStatus,
  selectableInterfaces,
  selectedCaptureInterfaceName,
  setSelectedCaptureInterfaceName,
  selectedCaptureInterface,
  captureAdapter,
  captureProgress,
  packets,
  startCaptureDisabled,
  stopCaptureDisabled,
  handleStartCapture,
  handleStopCapture,
  liveMonitorLoading,
  packetTypeCounts,
  mlLiveStatus,
  setActiveView,
}) => {
  const hasPackets = packets && packets.length > 0
  const isCapturing = isCaptureRunning

  return (
    <section className="live-monitor-view" aria-label="Live packet monitor">
      {liveMonitorError && <p className="error-banner">{liveMonitorError}</p>}

      {/* Control & Interface Panel */}
      <div className="panel scan-control-panel">
        <div className="control-bar-row">
          <div className="control-bar-info">
            <div className="control-title-group">
              <h2 className="section-title">Live 802.11 Packet Monitor</h2>
              <span
                className={`badge ${
                  isCaptureRunning
                    ? 'badge-status-resolved'
                    : isCaptureStarting || isCaptureStopping
                      ? 'badge-severity-medium'
                      : 'badge-default'
                }`}
              >
                {isCaptureRunning
                  ? 'Capturing'
                  : isCaptureStarting
                    ? 'Starting...'
                    : isCaptureStopping
                      ? 'Stopping...'
                      : 'Standby'}
              </span>
            </div>

            <div className="meta-pills-row">
              {selectableInterfaces.length > 1 ? (
                <label className="adapter-select-label">
                  <span>Interface:</span>
                  <select
                    disabled={isCaptureActive}
                    onChange={(e) => setSelectedCaptureInterfaceName(e.target.value)}
                    value={selectedCaptureInterfaceName}
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
                  Interface: <strong>{selectedCaptureInterface || 'None Detected'}</strong>
                </span>
              )}

              <span className="scan-meta-pill">
                Mode:{' '}
                <strong>
                  {formatValue(getValue(captureStatus, ['mode']) ?? getValue(captureAdapter, ['mode']))}
                </strong>
              </span>

              {isCaptureRunning && (
                <span className="scan-meta-pill">
                  Sweep: <strong>#{formatValue(getValue(captureProgress, ['sweep_number']) || 1)}</strong> (Ch{' '}
                  {formatValue(getValue(captureProgress, ['current_channel']) || '--')})
                </span>
              )}
            </div>
          </div>

          <div className="control-bar-actions">
            <button
              className="btn btn-primary"
              disabled={startCaptureDisabled}
              onClick={handleStartCapture}
              type="button"
            >
              <IconPlay size={14} />
              <span>{isCaptureStarting ? 'Starting...' : isCaptureRunning ? 'Capturing...' : 'Start Capture'}</span>
            </button>
            <button
              className="btn btn-secondary"
              disabled={stopCaptureDisabled}
              onClick={handleStopCapture}
              type="button"
            >
              <IconSquare size={14} />
              <span>{isCaptureStopping ? 'Stopping...' : 'Stop Capture'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* CONCISE INSTRUCTION CARD WHEN INACTIVE */}
      {!isCapturing && !hasPackets && !liveMonitorLoading && (
        <div className="panel instruction-card-panel">
          <div className="instruction-header">
            <div className="instruction-icon-circle">
              <IconActivity size={22} />
            </div>
            <div>
              <h3 className="section-title">Live Capture Instruction &amp; Setup</h3>
              <p className="panel-subtitle">
                Monitor 802.11 management, control, and data frames in real time to feed the AWID3 intrusion detection engine.
              </p>
            </div>
          </div>

          <div className="instruction-steps-grid">
            <div className="instruction-step">
              <span className="step-num">1</span>
              <div>
                <strong>Select Wireless Interface</strong>
                <p>Choose an active Wi-Fi adapter configured for monitor mode from the dropdown above.</p>
              </div>
            </div>

            <div className="instruction-step">
              <span className="step-num">2</span>
              <div>
                <strong>Start Packet Ingestion</strong>
                <p>Click "Start Capture" to begin streaming raw 802.11 frames through the tumbling window buffer.</p>
              </div>
            </div>

            <div className="instruction-step">
              <span className="step-num">3</span>
              <div>
                <strong>Observe Threat Inference</strong>
                <p>Every 5 seconds, 31 canonical frame burst features are evaluated by the Random Forest classifier.</p>
              </div>
            </div>
          </div>

          <div className="platform-notice-box">
            <p>
              <strong>Platform Notice:</strong> Live IEEE 802.11 packet sniffing requires root/administrator privileges and a compatible wireless adapter supporting monitor mode (rfmon), standard in Kali Linux. On Windows, use the <strong>PCAP Analysis</strong> view to inspect pre-captured traces with full 31-feature ML inference.
            </p>
          </div>
        </div>
      )}

      {/* TELEMETRY STRIP (Shown when active or when packets exist) */}
      {(isCapturing || hasPackets) && (
        <div className="telemetry-strip-grid">
          <article className="telemetry-card">
            <span className="telemetry-card-label">Session Packets</span>
            <strong className="telemetry-card-val">
              {formatValue(getValue(captureProgress, ['packet_count']) ?? packets.length)}
            </strong>
            <span className="telemetry-card-sub">Frames ingested</span>
          </article>

          <article className="telemetry-card">
            <span className="telemetry-card-label">Packet Rate</span>
            <strong
              className="telemetry-card-val"
              style={{ color: isCaptureRunning ? 'var(--accent)' : 'inherit' }}
            >
              {formatWithUnit(getValue(captureProgress, ['packet_rate']), 'pkt/s')}
            </strong>
            <span className="telemetry-card-sub">Throughput</span>
          </article>

          <article className="telemetry-card">
            <span className="telemetry-card-label">Elapsed Time</span>
            <strong className="telemetry-card-val">
              {formatWithUnit(getValue(captureProgress, ['elapsed_seconds']), 's')}
            </strong>
            <span className="telemetry-card-sub">Active duration</span>
          </article>

          <article className="telemetry-card">
            <span className="telemetry-card-label">Latest ML Verdict</span>
            <strong className="telemetry-card-val" style={{ fontSize: '15px' }}>
              {mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined
                ? mlLiveStatus.prediction === 0
                  ? 'Normal Traffic'
                  : (mlLiveStatus.label ?? 'Attack Detected')
                : 'Standby'}
            </strong>
            <span className="telemetry-card-sub">
              {mlLiveStatus?.attack_probability !== undefined
                ? `Attack: ${formatProbability(mlLiveStatus.attack_probability)}`
                : 'Awaiting 5s window'}
            </span>
          </article>
        </div>
      )}

      {/* Frame Types Observed Pill Strip */}
      {Object.keys(packetTypeCounts).length > 0 && (
        <div className="panel packet-types-panel">
          <div className="panel-header">
            <div>
              <h3 className="section-title">802.11 Frame Distribution</h3>
              <p className="panel-subtitle">Observed management, control, and data frame types in current session.</p>
            </div>
            <span className="badge badge-default">
              {Object.keys(packetTypeCounts).length} Types Observed
            </span>
          </div>

          <div className="packet-types-grid" style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '10px' }}>
            {Object.entries(packetTypeCounts).map(([packetType, count]) => {
              const isAlert =
                packetType.toLowerCase().includes('deauth') ||
                packetType.toLowerCase().includes('disas')

              return (
                <div
                  className={`scan-meta-pill ${isAlert ? 'badge-severity-high' : ''}`}
                  key={packetType}
                  style={{
                    background: isAlert ? 'var(--danger-light)' : 'var(--input-bg)',
                    color: isAlert ? 'var(--danger-text)' : 'var(--text)',
                    border: isAlert ? '1px solid var(--danger-border)' : '1px solid var(--border)',
                  }}
                >
                  <span>{packetType}:</span>
                  <strong className="mono-val">{formatValue(count)}</strong>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Live Packet Table Panel */}
      {(isCapturing || hasPackets) && (
        <div className="panel packets-panel">
          <div className="panel-header">
            <div>
              <h3 className="section-title">Buffered 802.11 Frame Feed</h3>
              <p className="panel-subtitle">
                Frames captured on interface {selectedCaptureInterface || '--'}.
              </p>
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span className="badge badge-default">{packets.length} Packets Buffered</span>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setActiveView('ML Engine')}
              >
                <IconCpu size={14} />
                <span>Inspect ML Engine</span>
              </button>
            </div>
          </div>

          {hasPackets ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Classification / Subtype</th>
                    <th>Source MAC</th>
                    <th>Destination MAC</th>
                    <th>BSSID</th>
                    <th>Frame Type</th>
                    <th>Signal</th>
                  </tr>
                </thead>
                <tbody>
                  {packets.map((packet, index) => {
                    const pType = formatValue(getValue(packet, ['packet_type', 'type', 'classification']))
                    const isDeauth =
                      String(pType).toLowerCase().includes('deauth') ||
                      String(pType).toLowerCase().includes('disas')
                    const sigRaw = getValue(packet, ['signal_strength'])
                    const sigNum = parseInt(String(sigRaw || '').replace(/[^0-9-]/g, ''), 10)

                    return (
                      <tr key={getValue(packet, ['id', 'packet_id']) ?? index}>
                        <td>
                          <span className="mono-val" style={{ fontSize: '12px' }}>
                            {formatValue(getValue(packet, ['time', 'timestamp', 'captured_at']))}
                          </span>
                        </td>
                        <td>
                          <span className={`badge ${isDeauth ? 'badge-severity-high' : 'badge-default'}`}>
                            {pType}
                          </span>
                        </td>
                        <td>
                          <span className="mono-val" style={{ fontSize: '12px' }}>
                            {formatValue(getValue(packet, ['source_mac', 'src_mac', 'source']))}
                          </span>
                        </td>
                        <td>
                          <span className="mono-val" style={{ fontSize: '12px' }}>
                            {formatValue(getValue(packet, ['destination_mac', 'dst_mac', 'destination']))}
                          </span>
                        </td>
                        <td>
                          <span className="mono-val" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                            {formatValue(getValue(packet, ['bssid']))}
                          </span>
                        </td>
                        <td>
                          <span className="mono-val" style={{ fontSize: '12px' }}>
                            {formatValue(getValue(packet, ['frame_type', 'frame']))}
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
                            }}
                          >
                            {formatWithUnit(sigRaw, 'dBm')}
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <p className="muted-text">Waiting for packets on selected interface...</p>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
