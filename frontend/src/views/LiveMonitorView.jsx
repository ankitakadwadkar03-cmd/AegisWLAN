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
  return (
    <section className="live-monitor-view" aria-label="Live packet monitor">
      {liveMonitorError && <p className="error-banner">{liveMonitorError}</p>}

      {/* Control & Telemetry Panel */}
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

              {getValue(captureStatus, ['pid', 'process_id']) ? (
                <span className="scan-meta-pill">
                  PID: <strong>{formatValue(getValue(captureStatus, ['pid', 'process_id']))}</strong>
                </span>
              ) : null}

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

        {/* Informative notice if no adapter */}
        {!captureAdapter && !liveMonitorLoading && (
          <div className="empty-state-notice">
            <p>
              <strong>Platform Notice:</strong> Live IEEE 802.11 monitor-mode packet capture requires root/administrator privileges and a compatible Wi-Fi chipset supporting rfmon/monitor mode (e.g. Linux / Kali). On Windows, simulated or pre-recorded captures are supported via the PCAP Analysis module.
            </p>
          </div>
        )}
      </div>

      {/* Live Ingest Telemetry Strip */}
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
            style={{ color: isCaptureRunning ? 'var(--accent-text)' : 'inherit' }}
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

      {/* Frame Types Observed Pill Strip */}
      {Object.keys(packetTypeCounts).length > 0 && (
        <div className="panel packet-types-panel">
          <div className="packet-types-header">
            <span className="packet-types-title">Live 802.11 Frame Distribution</span>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              {Object.keys(packetTypeCounts).length} types observed
            </span>
          </div>
          <div className="packet-types-grid">
            {Object.entries(packetTypeCounts).map(([packetType, count]) => {
              const isAlert =
                packetType.toLowerCase().includes('deauth') ||
                packetType.toLowerCase().includes('disas')

              return (
                <div className={`packet-type-pill ${isAlert ? 'alert' : ''}`} key={packetType}>
                  <span className="pill-type-name">{packetType}</span>
                  <strong className="pill-type-count">{formatValue(count)}</strong>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Live Packet Table Panel */}
      <div className="panel packets-panel">
        <div className="panel-header">
          <div>
            <h3>Buffered 802.11 Frame Feed</h3>
            <p className="panel-subtitle">
              Showing real-time frame telemetry captured on interface {selectedCaptureInterface || '--'}.
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
              <span>Inspect ML Inference</span>
            </button>
          </div>
        </div>

        {liveMonitorLoading && packets.length === 0 ? (
          <div className="empty-state">
            <p className="empty-state-title">Loading Packet Stream...</p>
          </div>
        ) : packets.length > 0 ? (
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
                                ? '#2dd4bf'
                                : sigNum >= -75
                                  ? '#38bdf8'
                                  : sigNum >= -85
                                    ? '#fbbf24'
                                    : '#f87171',
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
            <div className="empty-state-icon">
              <IconActivity size={28} />
            </div>
            <p className="empty-state-title">No Captured Packets Available</p>
            <p className="empty-state-text">
              Click &ldquo;Start Capture&rdquo; above to begin intercepting IEEE 802.11 wireless frames in monitor mode.
            </p>
          </div>
        )}
      </div>
    </section>
  )
}
