import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import './App.css';

const socket = io('http://localhost:8443');

const SEVERITY_COLORS = {
  CRITICAL: '#ff1744',
  HIGH: '#ff6d00',
  MEDIUM: '#ffd600',
  LOW: '#00e676',
  INFO: '#2196f3'
};

function FindingCard({ finding, onView, onSubmit }) {
  const color = SEVERITY_COLORS[finding.severity] || '#fff';
  
  return (
    <div className="finding-card" style={{ borderLeft: `4px solid ${color}` }}>
      <div className="finding-header">
        <span className="finding-file">📄 {finding.file}</span>
        <span className="finding-status" style={{ color }}>
          ● CONFIRMED FINDING #{finding.id} [{finding.severity}]
        </span>
      </div>
      <p className="finding-desc">{finding.description}</p>
      <div className="finding-meta">
        <span>Target: <u>{finding.target}</u></span>
        <span>Report: <u>finding-{finding.id}.md</u></span>
      </div>
      <div className="finding-actions">
        <button onClick={() => onView(finding.id)} className="btn-view">
          View report
        </button>
        <button onClick={() => onSubmit(finding.id)} className="btn-submit">
          Submit..
        </button>
      </div>
    </div>
  );
}

function NotificationPopup({ finding, onClose }) {
  const color = SEVERITY_COLORS[finding.severity] || '#fff';
  const sizeKB = (finding.size / 1024).toFixed(1);
  
  return (
    <div className="notification-popup">
      <div className="notif-icon">📥</div>
      <div className="notif-content">
        <div className="notif-file">
          {finding.file} <span className="notif-size">{sizeKB} KB</span>
        </div>
        <div className="notif-status" style={{ color }}>
          ● CONFIRMED FINDING #{finding.id} [{finding.severity}]
        </div>
        <p className="notif-desc">{finding.description}</p>
      </div>
      <button onClick={onClose} className="notif-close">✕</button>
    </div>
  );
}

function Dashboard() {
  const [findings, setFindings] = useState([]);
  const [notification, setNotification] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [filter, setFilter] = useState('ALL');
  const [stats, setStats] = useState({
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0
  });

  useEffect(() => {
    fetch('/api/findings')
      .then(r => r.json())
      .then(data => {
        setFindings(data);
        updateStats(data);
      });

    socket.on('new_finding', (f) => {
      setFindings(prev => [f, ...prev]);
      setNotification(f);
      updateStats([f, ...findings]);
      setTimeout(() => setNotification(null), 8000);
    });

    return () => socket.disconnect();
  }, []);

  const updateStats = (data) => {
    const s = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    data.forEach(f => { if (s[f.severity] !== undefined) s[f.severity]++; });
    setStats(s);
  };

  const filtered = filter === 'ALL' 
    ? findings 
    : findings.filter(f => f.severity === filter);

  return (
    <div className="dashboard">
      <header className="header">
        <h1>🦅 Exec Hawk AI Agent Platform</h1>
        <div className="phase-indicator">Penetration Testing Active</div>
      </header>

      <div className="stats-bar">
        {Object.entries(stats).map(([sev, count]) => (
          <div key={sev} className="stat-item" 
               style={{ borderColor: SEVERITY_COLORS[sev] }}>
            <span className="stat-count">{count}</span>
            <span className="stat-label">{sev}</span>
          </div>
        ))}
      </div>

      <div className="filter-bar">
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(f => (
          <button key={f} 
                  className={`filter-btn ${filter === f ? 'active' : ''}`}
                  onClick={() => setFilter(f)}>
            {f}
          </button>
        ))}
      </div>

      <div className="findings-grid">
        {filtered.map(f => (
          <FindingCard key={f.id} finding={f}
                       onView={(id) => setSelectedFinding(id)}
                       onSubmit={(id) => {
                         fetch(`/api/findings/${id}/submit`, { method: 'POST' });
                       }} />
        ))}
      </div>

      {notification && (
        <NotificationPopup finding={notification}
                          onClose={() => setNotification(null)} />
      )}

      {selectedFinding && (
        <div className="modal-overlay" 
             onClick={() => setSelectedFinding(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <pre>{findings.find(f => f.id === selectedFinding)?.content}</pre>
            <button onClick={() => setSelectedFinding(null)}>Close</button>
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;