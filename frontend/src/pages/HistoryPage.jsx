import React, { useState, useEffect } from 'react';
import { getHistory } from '../api';

export default function HistoryPage() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getHistory(1, 50).then(data => {
      setHistory(data.items || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  if (loading) return <div className="card"><span className="spinner" /> Loading history...</div>;

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ fontSize: '1.2rem', fontWeight: 600, marginBottom: '1rem' }}>Scan History</div>
      
      {history.length === 0 ? (
        <div style={{ color: 'var(--text-3)' }}>No datasets have been scanned yet.</div>
      ) : (
        <div style={{ display: 'grid', gap: '0.75rem' }}>
          {history.map((item, idx) => (
            <div key={idx} style={{
              background: 'var(--bg-1)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--r-sm)',
              padding: '1rem',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '1rem'
            }}>
              <div>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-1)' }}>{item.original_filename}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-3)', fontFamily: 'var(--mono)' }}>{new Date(item.uploaded_at).toLocaleString()}</div>
              </div>
              <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', fontSize: '0.8rem' }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.65rem', color: 'var(--text-3)' }}>RISK</span>
                  <strong style={{ color: item.risk_score > 6 ? 'var(--rose)' : item.risk_score > 3 ? 'var(--amber)' : 'var(--emerald)' }}>{item.risk_score.toFixed(1)}</strong>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.65rem', color: 'var(--text-3)' }}>VERDICT</span>
                  <strong style={{ color: item.verdict === 'malicious' ? 'var(--rose)' : item.verdict === 'suspicious' ? 'var(--amber)' : 'var(--emerald)' }}>{item.verdict.toUpperCase()}</strong>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.65rem', color: 'var(--text-3)' }}>THREATS</span>
                  <strong style={{ color: item.threats_found_count > 0 ? 'var(--rose)' : 'var(--emerald)' }}>{item.threats_found_count}</strong>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
