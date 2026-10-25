import React from 'react'
import { getRecommendationBadgeClass } from '../utils/helpers'
import { IconX } from './Icons'

export const ConnectModal = ({
  connectModalNetwork,
  handleCloseConnectModal,
  connectLoading,
  connectStatus,
  handleConnectSubmit,
  connectPassword,
  setConnectPassword,
  showPassword,
  setShowPassword,
}) => {
  if (!connectModalNetwork) return null

  const isOpen = String(connectModalNetwork.encryption || '').toLowerCase().includes('open')

  return (
    <div className="modal-backdrop" onClick={handleCloseConnectModal}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>Connect to Wi-Fi Network</h3>
          <button
            type="button"
            className="modal-close-btn"
            onClick={handleCloseConnectModal}
            disabled={connectLoading}
            aria-label="Close"
          >
            <IconX size={16} />
          </button>
        </div>

        <div className="modal-body">
          <div className="modal-network-preview">
            <div className="preview-row">
              <span className="preview-label">Network (SSID):</span>
              <strong>{connectModalNetwork.ssid || '<Hidden SSID>'}</strong>
            </div>
            <div className="preview-row">
              <span className="preview-label">BSSID:</span>
              <span className="mono-val">{connectModalNetwork.bssid || 'Unknown'}</span>
            </div>
            <div className="preview-row">
              <span className="preview-label">Encryption:</span>
              <span className="badge badge-default">{connectModalNetwork.encryption || 'Open'}</span>
            </div>
            <div className="preview-row">
              <span className="preview-label">Signal:</span>
              <span>{connectModalNetwork.signal || '--'}</span>
            </div>
            <div className="preview-row">
              <span className="preview-label">ML Classification:</span>
              <span className={getRecommendationBadgeClass(connectModalNetwork.classification)}>
                {connectModalNetwork.classification} (Score: {connectModalNetwork.score})
              </span>
            </div>
          </div>

          {connectStatus ? (
            <div className={`connect-status-box ${connectStatus.success ? 'success' : 'error'}`}>
              {connectStatus.success ? '✓ ' : '✗ '}
              {connectStatus.message}
            </div>
          ) : null}

          <form onSubmit={handleConnectSubmit} className="connect-form">
            {isOpen ? (
              <p className="open-network-notice">
                ℹ This network does not require a password (Open encryption).
              </p>
            ) : (
              <div className="form-group">
                <label htmlFor="wifi-password-input">
                  Network Security Key / Password:
                </label>
                <div className="password-input-wrap">
                  <input
                    id="wifi-password-input"
                    type={showPassword ? 'text' : 'password'}
                    className="password-input"
                    value={connectPassword}
                    onChange={(e) => setConnectPassword(e.target.value)}
                    placeholder="Enter Wi-Fi password (8-63 chars)"
                    disabled={connectLoading}
                    autoFocus
                  />
                  <button
                    type="button"
                    className="toggle-pwd-btn"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? 'Hide' : 'Show'}
                  </button>
                </div>
                <span className="form-hint">
                  WPA/WPA2/WPA3 passphrases are typically 8 to 63 characters long.
                </span>
              </div>
            )}

            <div className="modal-actions">
              <button
                type="button"
                className="scan-button"
                onClick={handleCloseConnectModal}
                disabled={connectLoading}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="scan-button primary"
                disabled={
                  connectLoading ||
                  (!isOpen && connectPassword.length < 8)
                }
              >
                {connectLoading ? 'Connecting...' : 'Connect Now'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
