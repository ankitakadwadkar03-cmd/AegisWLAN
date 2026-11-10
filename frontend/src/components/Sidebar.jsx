import React, { useState } from 'react'
import { navGroups } from '../utils/navigation'
import { IconChevronLeft, IconChevronRight, IconBot } from './Icons'

export const Sidebar = ({
  activeView,
  setActiveView,
  isCaptureRunning,
  newIncidentsCount,
  advisorOpen,
  setAdvisorOpen,
}) => {
  const [isCollapsed, setIsCollapsed] = useState(() => {
    try {
      const saved = localStorage.getItem('netshield_sidebar_collapsed') ?? localStorage.getItem('aegiswlan_sidebar_collapsed')
      return saved === 'true'
    } catch {
      return false
    }
  })

  const toggleCollapse = () => {
    setIsCollapsed((prev) => {
      const next = !prev
      try {
        localStorage.setItem('netshield_sidebar_collapsed', String(next))
        localStorage.setItem('aegiswlan_sidebar_collapsed', String(next))
      } catch {
        // Handle unavailable or restricted localStorage gracefully
      }
      return next
    })
  }

  return (
    <aside className={`sidebar ${isCollapsed ? 'collapsed' : ''}`} aria-label="Primary navigation">
      <div
        className="brand"
        onClick={() => setActiveView('Admin Dashboard')}
        style={{ cursor: 'pointer' }}
        title="NetShield — Overview"
      >
        <span className="brand-mark" title="NetShield">NS</span>
        {!isCollapsed && (
          <div className="brand-info">
            <p className="brand-name">NetShield</p>
            <p className="brand-subtitle">Wireless Intrusion Defense</p>
          </div>
        )}
      </div>

      <nav className="nav-list">
        {navGroups.map((group) => (
          <div key={group.group} className="nav-group-section">
            {!isCollapsed && <span className="nav-group-title">{group.group}</span>}
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
                    aria-label={item.label}
                  >
                    <span className="nav-icon-wrap">
                      <IconComponent size={17} />
                      {isCollapsed && item.id === 'Live Monitor' && isCaptureRunning && (
                        <span className="live-pulse-dot micro-dot" title="Live Capture Active" />
                      )}
                      {isCollapsed && item.id === 'Incidents' && newIncidentsCount > 0 && (
                        <span className="nav-alert-badge micro-badge" title={`${newIncidentsCount} New Alerts`}>
                          {newIncidentsCount > 9 ? '9+' : newIncidentsCount}
                        </span>
                      )}
                    </span>
                    {!isCollapsed && <span className="nav-item-text">{item.label}</span>}

                    {!isCollapsed && item.id === 'Live Monitor' && isCaptureRunning && (
                      <span className="live-pulse-dot" title="Live Capture Active" />
                    )}

                    {!isCollapsed && item.id === 'Incidents' && newIncidentsCount > 0 && (
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
        <button
          type="button"
          className={`sidebar-advisor-btn ${advisorOpen ? 'active' : ''}`}
          onClick={() => setAdvisorOpen && setAdvisorOpen((prev) => !prev)}
          title="AI Security Advisor"
          aria-label="AI Security Advisor"
        >
          <IconBot size={16} />
          {!isCollapsed && <span>AI Advisor</span>}
        </button>

        {!isCollapsed && (
          <div className="system-pill" title="Hardware Monitor Status">
            <span className={`status-dot ${isCaptureRunning ? 'active' : ''}`} />
            <span className="system-pill-text">
              {isCaptureRunning ? 'Live Capture' : 'System Standby'}
            </span>
          </div>
        )}

        <button
          type="button"
          className="collapse-toggle-btn"
          onClick={toggleCollapse}
          title={isCollapsed ? 'Expand navigation' : 'Collapse navigation'}
          aria-label={isCollapsed ? 'Expand navigation' : 'Collapse navigation'}
        >
          {isCollapsed ? <IconChevronRight size={16} /> : <IconChevronLeft size={16} />}
          {!isCollapsed && <span className="toggle-label">Collapse</span>}
        </button>
      </div>
    </aside>
  )
}
