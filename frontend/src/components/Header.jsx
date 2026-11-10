import React from 'react'
import { navGroups } from '../utils/navigation'
import { IconBot } from './Icons'

export const Header = ({
  activeView,
  setActiveView,
  isCaptureRunning,
  isCaptureStarting,
  isCaptureStopping,
  highSeverityIncidents,
  visualAlerts,
  adapterName,
  advisorOpen,
  setAdvisorOpen,
}) => {
  let groupName = 'MONITOR'
  for (const g of navGroups) {
    if (g.items.some((i) => i.id === activeView)) {
      groupName = g.group
      break
    }
  }

  return (
    <header className="top-header" aria-label="NetShield Top Navigation">
      <div className="header-breadcrumbs">
        <span className="breadcrumb-category">{groupName}</span>
        <span className="breadcrumb-separator">/</span>
        <h1 className="breadcrumb-current">{activeView}</h1>
      </div>

      <div className="header-status-group">
        <button
          type="button"
          className={`header-advisor-trigger ${advisorOpen ? 'active' : ''}`}
          onClick={() => setAdvisorOpen && setAdvisorOpen((prev) => !prev)}
          title="Open NetShield AI Wi-Fi Advisor"
          aria-label="Toggle NetShield AI Wi-Fi Advisor"
          aria-expanded={Boolean(advisorOpen)}
        >
          <IconBot size={15} />
          <span>AI Advisor</span>
        </button>

        {adapterName ? (
          <div className="header-adapter-pill" title="Active Network Interface">
            <span className="pill-dot" />
            <span className="pill-text">{adapterName}</span>
          </div>
        ) : null}

        {visualAlerts && highSeverityIncidents > 0 && (
          <button
            type="button"
            className="header-alert-badge"
            onClick={() => setActiveView('Incidents')}
            title="High severity incidents require immediate triage"
          >
            <span className="status-dot dot-alert" />
            <span>{highSeverityIncidents} HIGH ALERT{highSeverityIncidents > 1 ? 'S' : ''}</span>
          </button>
        )}

        <div className="header-status">
          <span className={`status-dot ${isCaptureRunning ? 'active' : ''}`} />
          <span>
            {isCaptureRunning
              ? 'Capture Streaming'
              : isCaptureStarting
                ? 'Starting...'
                : isCaptureStopping
                  ? 'Stopping...'
                  : 'Standby'}
          </span>
        </div>
      </div>
    </header>
  )
}
