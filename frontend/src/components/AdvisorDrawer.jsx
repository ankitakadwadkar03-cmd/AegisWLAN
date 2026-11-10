import React, { useEffect, useRef } from 'react'
import { IconX, IconBot } from './Icons'

export const AdvisorDrawer = ({
  advisorOpen,
  setAdvisorOpen,
  advisorMessages,
  handleSendAdvisorMessage,
  advisorInput,
  setAdvisorInput,
}) => {
  const inputRef = useRef(null)

  useEffect(() => {
    if (!advisorOpen) return
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setAdvisorOpen(false)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    if (inputRef.current) {
      inputRef.current.focus()
    }
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [advisorOpen, setAdvisorOpen])

  if (!advisorOpen) return null

  return (
    <div
      className="advisor-floating-panel"
      role="dialog"
      aria-modal="true"
      aria-label="NetShield AI Wi-Fi Advisor"
    >
      <div className="advisor-header">
        <div className="advisor-title-row">
          <span className="advisor-avatar">
            <IconBot size={18} />
          </span>
          <div>
            <h4 className="advisor-title">NetShield AI Wi-Fi Advisor</h4>
            <span className="advisor-status">
              <span className="status-live-dot" /> Grounded in Real Scan Data
            </span>
          </div>
        </div>
        <button
          type="button"
          className="advisor-close-btn"
          onClick={() => setAdvisorOpen(false)}
          aria-label="Close Advisor"
        >
          <IconX size={16} />
        </button>
      </div>

      <div className="advisor-messages">
        {advisorMessages.map((msg, i) => (
          <div key={i} className={`advisor-msg-row ${msg.sender === 'user' ? 'user' : 'advisor'}`}>
            <div className="advisor-msg-bubble">
              <p style={{ whiteSpace: 'pre-line' }}>{msg.text}</p>
              <span className="advisor-msg-time">{msg.timestamp}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="advisor-quick-prompts">
        <span className="quick-prompt-label">Quick Questions:</span>
        <div className="quick-prompts-scroll">
          <button
            type="button"
            className="prompt-chip"
            onClick={() => handleSendAdvisorMessage('Why is the #1 network recommended?')}
          >
            Why is #1 recommended?
          </button>
          <button
            type="button"
            className="prompt-chip"
            onClick={() => handleSendAdvisorMessage('Is the best network safe for banking?')}
          >
            Is #1 safe for banking?
          </button>
          <button
            type="button"
            className="prompt-chip"
            onClick={() => handleSendAdvisorMessage('Which networks are on 5 GHz?')}
          >
            Which APs are 5 GHz?
          </button>
          <button
            type="button"
            className="prompt-chip"
            onClick={() => handleSendAdvisorMessage('Are there any open Wi-Fi risks?')}
          >
            Open Wi-Fi risks?
          </button>
          <button
            type="button"
            className="prompt-chip"
            onClick={() => handleSendAdvisorMessage('What does the ML confidence percentage mean?')}
          >
            Explain ML confidence
          </button>
        </div>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault()
          handleSendAdvisorMessage()
        }}
        className="advisor-input-form"
      >
        <input
          ref={inputRef}
          type="text"
          className="advisor-input"
          placeholder="Ask about signal, security, bands..."
          value={advisorInput}
          onChange={(e) => setAdvisorInput(e.target.value)}
        />
        <button
          type="submit"
          className="advisor-send-btn"
          disabled={!advisorInput.trim()}
        >
          Send
        </button>
      </form>
    </div>
  )
}
