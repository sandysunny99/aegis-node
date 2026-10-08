import React, { useState, useEffect } from 'react';
import { getAnalysis, analyseDataset, getLlmProviders } from '../api';

export default function AiSummary({ datasetId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [collapsed, setCollapsed] = useState(false);
  const [providers, setProviders] = useState([]);
  
  const [llmMode, setLlmMode] = useState('auto');
  const [selectedProvider, setSelectedProvider] = useState('');
  const [analyzing, setAnalyzing] = useState(false);

  useEffect(() => {
    fetchData();
    getLlmProviders().then(res => {
      setProviders(res.providers || []);
      if (res.providers?.length > 0) {
        setSelectedProvider(res.providers[0].id);
      }
    }).catch(console.error);
  }, [datasetId]);

  const fetchData = () => {
    setLoading(true);
    getAnalysis(datasetId)
      .then(res => {
        setData(res);
        setLoading(false);
      })
      .catch(err => {
        // If 404, it just means no analysis yet, which is fine if we allow manual triggering
        if (err.message.includes('404')) {
          setData(null);
        } else {
          setError(err.message);
        }
        setLoading(false);
      });
  };

  const handleAnalyze = async () => {
    setAnalyzing(true);
    setError(null);
    try {
      const res = await analyseDataset(datasetId, {
        llmMode,
        provider: llmMode === 'manual' ? selectedProvider : null,
      });
      setData(res);
    } catch (err) {
      setError(err.message);
    }
    setAnalyzing(false);
  };

  if (loading && !data) return <div className="card"><span className="spinner" /> Loading AI Security Analysis...</div>;

  const a = data || {};
  
  // Format model name output
  let displayProvider = a.final_provider || a.initial_provider || "Unknown";
  let displayModel = a.model_name || "Unknown";
  
  if (a.model_name) {
    if (a.model_name === "chain_exhausted") {
       displayProvider = "Chain Exhausted";
       displayModel = "None";
    } else if (a.model_name.includes('/')) {
       const parts = a.model_name.split('/');
       displayProvider = a.final_provider || parts[0];
       displayModel = parts.slice(1).join('/');
    } else {
       // Legacy or groq fallback
       displayProvider = a.final_provider || (a.model_name.includes('gemini') ? 'gemini' : a.model_name.includes('llama') ? 'groq' : 'unknown');
       displayModel = a.model_name;
    }
  }

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
          
          <div style={{ marginBottom: '1.5rem', display: 'flex', gap: '1rem', alignItems: 'center', background: 'var(--bg-1)', padding: '1rem', borderRadius: 'var(--r-md)', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 600 }}>Mode:</div>
            <label style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              <input type="radio" name="llmMode" value="auto" checked={llmMode === 'auto'} onChange={() => setLlmMode('auto')} /> Auto
            </label>
            <label style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              <input type="radio" name="llmMode" value="manual" checked={llmMode === 'manual'} onChange={() => setLlmMode('manual')} /> Manual
            </label>
            
            {llmMode === 'manual' && (
              <select value={selectedProvider} onChange={(e) => setSelectedProvider(e.target.value)} style={{ padding: '0.25rem', fontSize: '0.8rem', borderRadius: 'var(--r-sm)', background: 'var(--bg-2)', border: '1px solid var(--border)', color: 'var(--text-1)' }}>
                {providers.filter(p => p.configured).map(p => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            )}
            <button className="btn btn-primary" style={{ padding: '0.25rem 0.75rem', fontSize: '0.8rem', marginLeft: 'auto' }} onClick={handleAnalyze} disabled={analyzing}>
              {analyzing ? <><span className="spinner" /> Analyzing...</> : (data ? 'Re-Analyze' : 'Analyze Dataset')}
            </button>
          </div>
          
          {error && <div style={{ color: 'var(--rose)', marginBottom: '1rem', fontSize: '0.8rem' }}>Error: {error}</div>}

          {data && (
            <>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', background: 'var(--bg-1)', padding: '1rem', borderRadius: 'var(--r-md)', border: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: '0.8rem', marginBottom: '1.5rem' }}>
                 <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>AI PROVIDER</div><strong style={{ color: 'var(--cyan)', textTransform: 'capitalize' }}>{displayProvider}</strong></div>
                 <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>MODEL</div><strong style={{ color: 'var(--text-1)' }}>{displayModel}</strong></div>
                 <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>AI STATUS</div><strong style={{ color: a.status === 'completed' ? 'var(--emerald)' : 'var(--amber)' }}>{a.status}</strong></div>
              </div>

              {/* Observability metadata */}
              <div style={{ background: 'var(--bg-1)', padding: '1rem', borderRadius: 'var(--r-sm)', border: '1px solid var(--border)', marginBottom: '1.5rem', fontFamily: 'var(--mono)', fontSize: '0.75rem', display: 'grid', gap: '0.5rem' }}>
                <div style={{ display: 'flex' }}><span style={{ width: '120px', color: 'var(--text-3)' }}>LLM Mode:</span> <span style={{ color: 'var(--text-2)' }}>{a.llm_mode || 'auto'}</span></div>
                <div style={{ display: 'flex' }}><span style={{ width: '120px', color: 'var(--text-3)' }}>Initial / Final:</span> <span style={{ color: 'var(--text-2)' }}>{a.initial_provider || 'N/A'} ➔ {a.final_provider || 'N/A'}</span></div>
                <div style={{ display: 'flex' }}><span style={{ width: '120px', color: 'var(--text-3)' }}>Provider Attempts:</span> <span style={{ color: 'var(--text-2)' }}>{(a.provider_attempts || []).join(', ') || 'N/A'}</span></div>
                <div style={{ display: 'flex' }}><span style={{ width: '120px', color: 'var(--text-3)' }}>Fallback Used:</span> <strong style={{ color: a.fallback_used ? 'var(--amber)' : 'var(--emerald)' }}>{a.fallback_used ? `Yes (${a.fallback_reason})` : 'No'}</strong></div>
              </div>

              {a.guardrail_status && (
                <div style={{ background: 'var(--bg-1)', padding: '1rem', borderRadius: 'var(--r-sm)', border: '1px solid var(--border)', marginBottom: '1.5rem', fontFamily: 'var(--mono)', fontSize: '0.75rem', display: 'grid', gap: '0.5rem' }}>
                  <div style={{ display: 'flex' }}><span style={{ width: '100px', color: 'var(--text-3)' }}>Guardrail:</span> <strong style={{ color: a.guardrail_status === 'BLOCK' ? 'var(--rose)' : a.guardrail_status === 'RESTRICT' ? 'var(--amber)' : 'var(--emerald)' }}>{a.guardrail_status}</strong></div>
                  <div style={{ display: 'flex' }}><span style={{ width: '100px', color: 'var(--text-3)' }}>LLM State:</span> <strong style={{ color: a.guardrail_status === 'BLOCK' ? 'var(--text-3)' : 'var(--cyan)' }}>{a.guardrail_status === 'BLOCK' ? 'BYPASSED' : 'INVOKED'}</strong></div>
                  <div style={{ display: 'flex' }}><span style={{ width: '100px', color: 'var(--text-3)' }}>Context:</span> <span style={{ color: 'var(--text-2)' }}>{a.llm_context_mode || 'STANDARD'}</span></div>
                </div>
              )}

              <div style={{ fontSize: '0.85rem', lineHeight: '1.5', color: 'var(--text-1)', whiteSpace: 'pre-wrap', background: 'var(--bg-2)', padding: '1.25rem', borderRadius: 'var(--r-sm)', border: '1px solid var(--border)' }}>
                {a.summary || 'No narrative provided.'}
              </div>
            </>
          )}

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
