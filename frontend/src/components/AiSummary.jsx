
import React, { useState, useEffect } from 'react';
import { getAnalysis } from '../api';

export default function AiSummary({ datasetId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    getAnalysis(datasetId)
      .then(res => {
        setData(res);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, [datasetId]);

  if (loading) return <div className="card"><span className="spinner" /> Loading AI Security Analysis...</div>;
  if (error) return <div className="card"><div style={{color: 'var(--rose)'}}>AI Analysis Unavailable: {error}</div></div>;
  if (!data || !data.analysis) return null;

  const a = data.analysis;
  
  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div className="card-title" style={{ marginBottom: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ color: 'var(--blue)' }}>🛡️</span> AI SECURITY & ANALYSIS
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>LLM Analysis protected by native Guardrails.</div>
        </div>
        <button className="btn btn-ghost" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }} onClick={() => setCollapsed(!collapsed)}>
          {collapsed ? 'Expand ▼' : 'Collapse ▲'}
        </button>
      </div>

      {!collapsed && (
        <div style={{ marginTop: '1.5rem' }}>
          {a.guardrail_action && (
            <div style={{ background: 'var(--bg-1)', padding: '1rem', borderRadius: 'var(--r-sm)', border: '1px solid var(--border)', marginBottom: '1.5rem', fontFamily: 'var(--mono)', fontSize: '0.75rem', display: 'grid', gap: '0.5rem' }}>
              <div style={{ display: 'flex' }}><span style={{ width: '100px', color: 'var(--text-3)' }}>Guardrail:</span> <strong style={{ color: a.guardrail_action === 'BLOCK' ? 'var(--rose)' : a.guardrail_action === 'RESTRICT' ? 'var(--amber)' : 'var(--emerald)' }}>{a.guardrail_action}</strong></div>
              <div style={{ display: 'flex' }}><span style={{ width: '100px', color: 'var(--text-3)' }}>LLM State:</span> <strong style={{ color: a.guardrail_action === 'BLOCK' ? 'var(--text-3)' : 'var(--cyan)' }}>{a.guardrail_action === 'BLOCK' ? 'BYPASSED' : 'INVOKED'}</strong></div>
              <div style={{ display: 'flex' }}><span style={{ width: '100px', color: 'var(--text-3)' }}>Context:</span> <span style={{ color: 'var(--text-2)' }}>{a.context_mode || 'STANDARD'}</span></div>
            </div>
          )}

          <div style={{ fontSize: '0.85rem', lineHeight: '1.5', color: 'var(--text-1)', whiteSpace: 'pre-wrap', background: 'var(--bg-2)', padding: '1.25rem', borderRadius: 'var(--r-sm)', border: '1px solid var(--border)' }}>
            {a.narrative_explanation || 'No narrative provided.'}
          </div>

          <div style={{ marginTop: '1.5rem', fontSize: '0.7rem', color: 'var(--text-3)', borderTop: '1px solid var(--border)', paddingTop: '0.75rem', display: 'flex', gap: '2rem' }}>
            <div>
              <strong>DETERMINISTIC AUTHORITY:</strong><br/>
              Local scanner + verification
            </div>
            <div>
              <strong>AI ROLE:</strong><br/>
              Explanation / analyst assistance
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
