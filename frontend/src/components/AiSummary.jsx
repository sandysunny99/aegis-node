import React, { useState } from 'react';
import { analyseDataset } from '../api';

export default function AiSummary({ datasetId }) {
  const [state, setState] = useState('idle'); // idle | loading | done | error | unavailable
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [isExpanded, setIsExpanded] = useState(true);

  const handleAnalyse = async () => {
    setState('loading'); setError('');
    try {
      const r = await analyseDataset(datasetId);
      if (r.status === 'unavailable') {
        setState('unavailable');
        setResult(r);
      } else {
        setResult(r); setState('done');
      }
    } catch (e) {
      setError(e.message); setState('error');
    }
  };

  const verdictConfig = {
    clean:         { color: 'var(--emerald)', bg: 'rgba(16,185,129,0.08)',  border: 'rgba(16,185,129,0.25)', icon: '🟢' },
    suspicious:    { color: 'var(--amber)',   bg: 'rgba(245,158,11,0.08)',  border: 'rgba(245,158,11,0.25)', icon: '🟡' },
    high_risk:     { color: 'var(--rose)',    bg: 'rgba(244,63,94,0.08)',   border: 'rgba(244,63,94,0.25)',  icon: '🔴' },
    inconclusive:  { color: 'var(--purple)',  bg: 'rgba(139,92,246,0.08)',  border: 'rgba(139,92,246,0.25)', icon: '🟣' },
  };
  const vc = result ? (verdictConfig[result.verdict] || verdictConfig.inconclusive) : {};

  return (
    <div style={{
      marginTop: '1.5rem',
      background: 'var(--bg-3)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--r-md)',
      overflow: 'hidden',
    }}>
      {/* Panel Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '1rem 1.25rem',
        borderBottom: state === 'done' || state === 'unavailable' ? '1px solid var(--border)' : 'none',
        flexWrap: 'wrap', gap: '0.75rem',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <span style={{ fontSize: '1.25rem' }}>🤖</span>
          <div>
            <div style={{ fontWeight: 700, color: 'var(--text-1)', fontSize: '0.9rem' }}>
              AI Threat Context & Explainability
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>
              Contextual reasoning powered by LLM (advisory only).
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {state === 'idle' && (
            <button className="btn btn-ghost" onClick={handleAnalyse} id="ai-analyse-btn" style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}>
              ✨ Generate AI Analysis
            </button>
          )}
          {state === 'loading' && (
            <button className="btn btn-ghost" disabled style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}>
              <span className="spinner" /> Reasoning…
            </button>
          )}
          {(state === 'done' || state === 'unavailable') && (
            <button
              onClick={() => setIsExpanded(x => !x)}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--cyan)',
                cursor: 'pointer',
                fontSize: '0.8rem',
                fontFamily: 'var(--font)',
                padding: '0.25rem 0.5rem',
              }}
            >
              {isExpanded ? 'Collapse ▲' : 'Expand ▼'}
            </button>
          )}
        </div>
      </div>

      {/* Unavailable state */}
      {state === 'unavailable' && isExpanded && (
        <div style={{
          padding: '1.25rem',
          background: 'rgba(139,92,246,0.06)',
          fontSize: '0.85rem',
          color: 'var(--purple)',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.75rem',
        }}>
          <span style={{ fontSize: '1.2rem' }}>🔑</span>
          <div>
            <div style={{ fontWeight: 700, marginBottom: '0.25rem' }}>AI Provider Setup</div>
            <div style={{ color: 'var(--text-2)', fontSize: '0.8rem', lineHeight: 1.5 }}>
              {result?.error
                ? `${result.error} — configure GEMINI_API_KEY, GROQ_API_KEY, or XAI_API_KEY to enable AI threat assessment.`
                : (result?.summary || 'No AI API key is configured. Set GEMINI_API_KEY or XAI_API_KEY in your environment to activate automated threat explanation.')}
            </div>
          </div>
        </div>
      )}

      {/* Error state */}
      {state === 'error' && (
        <div style={{ padding: '1rem 1.25rem' }}>
          <div className="error-banner fade-in">⚠️ {error}</div>
        </div>
      )}

      {/* Done state */}
      {state === 'done' && result && isExpanded && (
        <div className="fade-in" style={{ padding: '1.25rem' }}>
          {/* Top row: verdict, severity, and confidence */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '1rem',
            flexWrap: 'wrap',
            gap: '0.75rem',
            background: vc.bg,
            border: `1px solid ${vc.border}`,
            borderRadius: 'var(--r-sm)',
            padding: '0.75rem 1rem',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
              <span style={{ fontSize: '1.3rem' }}>{vc.icon}</span>
              <div>
                <div style={{ fontWeight: 800, color: vc.color, fontSize: '0.88rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  {result.verdict.replace(/_/g, ' ')}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-3)' }}>
                  Severity Level: <strong style={{ color: vc.color }}>{result.severity?.toUpperCase()}</strong>
                </div>
              </div>
            </div>
            <ConfidenceBar value={result.confidence} color={vc.color} />
          </div>

          {/* Model info badge */}
          <div style={{
            fontSize: '0.72rem',
            color: 'var(--text-3)',
            fontFamily: 'var(--mono)',
            marginBottom: '0.875rem',
            display: 'flex',
            gap: '0.75rem',
            alignItems: 'center',
          }}>
            <span>Model: <strong style={{ color: 'var(--text-2)' }}>{result.model_name}</strong></span>
            <span>·</span>
            <span>Tokens: <strong style={{ color: 'var(--text-2)' }}>{result.prompt_tokens + result.completion_tokens}</strong></span>
          </div>

          {/* Executive Summary */}
          <div style={{
            fontSize: '0.88rem',
            color: 'var(--text-1)',
            lineHeight: 1.6,
            marginBottom: '1.25rem',
            background: 'var(--bg-2)',
            padding: '0.875rem 1rem',
            borderRadius: 'var(--r-sm)',
            border: '1px solid var(--border)',
          }}>
            {result.summary}
          </div>

          {/* Evidence Points */}
          {result.evidence?.length > 0 && (
            <Section title="Evidence & Signal Corroboration" icon="🔍" color={vc.color}>
              {result.evidence.map((e, i) => <ListItem key={i} text={e} color={vc.color} />)}
            </Section>
          )}

          {/* Recommendations */}
          {result.recommendations?.length > 0 && (
            <Section title="Security Recommendations" icon="💡" color="var(--cyan)">
              {result.recommendations.map((r, i) => <ListItem key={i} text={r} color="var(--cyan)" />)}
            </Section>
          )}

          {/* Limitations */}
          {result.limitations?.length > 0 && (
            <div style={{
              marginTop: '0.875rem', padding: '0.75rem 1rem',
              background: 'rgba(255,255,255,0.02)', borderRadius: 'var(--r-sm)',
              borderLeft: '3px solid var(--border)',
            }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-3)', marginBottom: '0.35rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                ⚠️ Analysis Limitations
              </div>
              {result.limitations.map((l, i) => (
                <div key={i} style={{ fontSize: '0.75rem', color: 'var(--text-3)', lineHeight: 1.5 }}>• {l}</div>
              ))}
            </div>
          )}

          {/* Advisory disclaimer */}
          <div style={{
            marginTop: '1rem', padding: '0.625rem 0.875rem',
            background: 'rgba(0,0,0,0.25)', borderRadius: 'var(--r-sm)',
            fontSize: '0.72rem', color: 'var(--text-3)',
            display: 'flex', alignItems: 'center', gap: '0.5rem',
          }}>
            🛡️ AI assessment is advisory. The deterministic scanner pipeline (Stage 0 raw bytes + heuristics + ClamAV + content rules) remains the authoritative verdict.
          </div>
        </div>
      )}
    </div>
  );
}

function ConfidenceBar({ value, color }) {
  const pct = Math.round((value || 0) * 100);
  return (
    <div style={{ textAlign: 'right', minWidth: '110px' }}>
      <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', marginBottom: '0.25rem' }}>
        Confidence: <span style={{ color, fontFamily: 'var(--mono)', fontWeight: 700 }}>{pct}%</span>
      </div>
      <div style={{ width: '110px', height: '6px', background: 'rgba(255,255,255,0.08)', borderRadius: '9999px', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: '9999px', transition: 'width 0.6s ease' }} />
      </div>
    </div>
  );
}

function Section({ title, icon, color, children }) {
  return (
    <div style={{ marginBottom: '1rem' }}>
      <div style={{ fontSize: '0.75rem', fontWeight: 700, color, letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
        <span>{icon}</span> <span>{title}</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        {children}
      </div>
    </div>
  );
}

function ListItem({ text, color }) {
  return (
    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start' }}>
      <span style={{ color, flexShrink: 0, marginTop: '2px', fontWeight: 700 }}>›</span>
      <span style={{ fontSize: '0.82rem', color: 'var(--text-2)', lineHeight: 1.5 }}>{text}</span>
    </div>
  );
}

