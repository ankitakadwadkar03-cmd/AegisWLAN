import React from 'react'
import { navGroups } from '../utils/navigation'

export const Sidebar = ({ activeView, setActiveView, isCaptureRunning, newIncidentsCount }) => {
  return (
    <aside className="sidebar" aria-label="Primary navigation">
      <div className="brand" onClick={() => setActiveView('Dashboard')} style={{ cursor: 'pointer' }}>
        <span className="brand-mark">NS</span>
        <div>
          <p className="brand-name">NetShield</p>
          <p className="brand-subtitle">WIDS &bull; AWID3</p>
        </div>
      </div>

      <nav className="nav-list">
        {navGroups.map((group) => (
          <div key={group.group} className="nav-group-section">
            <span className="nav-group-title">{group.group}</span>
            <div className="nav-group-items">
              {group.items.map((item) => {
                const IconComponent = item.icon
                const isActive = activeView === item.id

                return (
                  <button
                    key={item.id}
                    className={`nav-item ${isActive ? 'active' : ''}`}
                    onClick={() => setActiveView(item.id)}
                    type="button"
                    title={item.label}
                  >
                    <span className="nav-icon-wrap">
                      <IconComponent size={17} />
                    </span>
                    <span className="nav-item-text">{item.label}</span>

                    {item.id === 'Live Monitor' && isCaptureRunning && (
                      <span className="live-pulse-dot" title="Live Capture Active" />
                    )}

                    {item.id === 'Incidents' && newIncidentsCount > 0 && (
                      <span className="nav-alert-badge">{newIncidentsCount}</span>
                    )}
                  </button>
                )
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="system-pill">
          <span className={`status-dot ${isCaptureRunning ? 'active' : ''}`} />
          <span className="system-pill-text">
            {isCaptureRunning ? 'Live Capture' : 'System Standby'}
          </span>
        </div>
      </div>
    </aside>
  )
}
