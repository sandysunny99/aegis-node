import React from 'react';

export default function ThreatIntelligence({ tiReport }) {
  if (!tiReport || tiReport.status === 'disabled') return null;

  return (
    <div style={{
      marginTop: '1.5rem',
      background: 'var(--bg-3)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--r-md)',
      overflow: 'hidden',
    }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: '0.625rem',
        padding: '1rem 1.25rem',
        borderBottom: '1px solid var(--border)',
      }}>
        <span style={{ fontSize: '1.25rem' }}>🌐</span>
        <div>
          <div style={{ fontWeight: 700, color: 'var(--text-1)', fontSize: '0.9rem', textTransform: 'uppercase' }}>
            Threat Intelligence
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>
            External Enrichment (Non-Authoritative)
          </div>
        </div>
      </div>

      <div style={{ padding: '1rem 1.25rem' }}>
        {tiReport.evidence?.map((ev, i) => (
          <div key={i} style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '0.75rem',
            padding: '0.5rem 0',
            borderBottom: '1px solid rgba(255,255,255,0.05)',
            fontFamily: 'var(--mono)',
            fontSize: '0.8rem',
          }}>
            <div style={{ color: 'var(--text-1)', fontWeight: 600 }}>{ev.provider}</div>
            <div style={{ color: 'var(--text-2)' }}>{ev.indicator_type}: {ev.indicator}</div>
            <div style={{ 
              color: ev.reputation === 'malicious' ? 'var(--rose)' : ev.reputation === 'suspicious' ? 'var(--amber)' : 'var(--emerald)',
              textTransform: 'uppercase',
              fontWeight: 700
            }}>
              {ev.reputation}
            </div>
            {ev.severity && (
              <div style={{ color: 'var(--cyan)' }}>{ev.severity.toUpperCase()}</div>
            )}
          </div>
        ))}
        {tiReport.evidence?.length === 0 && (
          <div style={{ color: 'var(--text-3)', fontSize: '0.8rem', fontFamily: 'var(--mono)', marginBottom: '0.75rem' }}>
            No malicious indicators found across {tiReport.providers_checked?.join(', ') || 'providers'}.
          </div>
        )}

        <div style={{
          marginTop: '1rem',
          padding: '0.75rem',
          background: 'var(--bg-2)',
          borderRadius: 'var(--r-sm)',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.5rem',
          fontFamily: 'var(--mono)',
          fontSize: '0.75rem'
        }}>
          <div style={{ display: 'flex', gap: '1rem' }}>
            <span style={{ color: 'var(--text-3)' }}>Fusion:</span>
            <span style={{ 
              color: tiReport.evidence_strength === 'CONFLICTED' ? 'var(--rose)' : 
                     tiReport.evidence_strength === 'CORROBORATED' ? 'var(--rose)' : 
                     'var(--cyan)',
              fontWeight: 700
            }}>
              {tiReport.evidence_strength}
            </span>
          </div>
          {tiReport.conflicts?.length > 0 && (
            <div style={{ display: 'flex', gap: '1rem' }}>
              <span style={{ color: 'var(--text-3)' }}>Conflicts:</span>
              <span style={{ color: 'var(--rose)' }}>{tiReport.conflicts.join(' | ')}</span>
            </div>
          )}
          {tiReport.limitations?.length > 0 && (
            <div style={{ display: 'flex', gap: '1rem' }}>
              <span style={{ color: 'var(--text-3)' }}>Limitations:</span>
              <span style={{ color: 'var(--amber)' }}>{tiReport.limitations.join(' | ')}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
