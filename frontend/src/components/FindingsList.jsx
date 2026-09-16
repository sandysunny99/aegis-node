
import React, { useState } from 'react';

export default function FindingsList({ findings }) {
  if (!findings || findings.length === 0) {
    return (
      <div style={{ fontSize: '0.85rem', color: 'var(--emerald)', padding: '1rem', background: 'rgba(16, 185, 129, 0.05)', borderRadius: 'var(--r-sm)', border: '1px solid rgba(16, 185, 129, 0.1)' }}>
        ✓ No malicious findings detected in the dataset.
      </div>
    );
  }

  const getSeverityColor = (sev) => {
    switch(sev?.toUpperCase()) {
      case 'CRITICAL': return 'var(--rose)';
      case 'HIGH': return 'var(--rose)';
      case 'MEDIUM': return 'var(--amber)';
      case 'LOW': return 'var(--cyan)';
      default: return 'var(--text-2)';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      {findings.map((f, i) => (
        <div key={i} style={{ 
          background: 'var(--bg-2)', 
          border: '1px solid var(--border)', 
          borderLeft: `3px solid ${getSeverityColor(f.severity)}`,
          borderRadius: 'var(--r-sm)', 
          padding: '1rem',
          fontSize: '0.8rem'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <strong style={{ color: getSeverityColor(f.severity) }}>{f.severity || 'HIGH'}</strong>
            <span style={{ color: 'var(--text-3)', fontFamily: 'var(--mono)', fontSize: '0.75rem' }}>{f.rule_id || 'RULE'}</span>
          </div>
          <div style={{ color: 'var(--text-1)', marginBottom: '0.5rem' }}>{f.description}</div>
          {f.location && (
            <div style={{ fontSize: '0.75rem', color: 'var(--text-2)', fontFamily: 'var(--mono)' }}>
              Location: {f.location}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
