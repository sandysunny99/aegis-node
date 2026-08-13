import React, { useState } from 'react';
import { analyseDataset } from '../api';

export default function AiSummary({ datasetId }) {
  const [state, setState] = useState('idle'); // idle | loading | done | error | unavailable
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

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
    <div style={{ marginTop: '1.5rem' }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem',
      }}>
        <div>
          <div style={{ fontWeight: 600, color: 'var(--text-1)', marginBottom: '0.25rem' }}>
            🤖 AI Threat Analysis
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-3)' }}>
            Advisory only — deterministic scanner results are authoritative.
          </div>
        </div>

        {state === 'idle' && (
          <button className="btn btn-ghost" onClick={handleAnalyse} id="ai-analyse-btn">
            ✨ Explain with AI
          </button>
        )}
        {state === 'loading' && (
          <button className="btn btn-ghost" disabled>
            <span className="spinner" /> Analysing…
          </button>
        )}
      </div>

      {/* Unavailable state */}
      {state === 'unavailable' && (
        <div style={{
          padding: '1rem', background: 'rgba(139,92,246,0.06)',
          border: '1px solid rgba(139,92,246,0.2)', borderRadius: 'var(--r-sm)',
          fontSize: '0.85rem', color: 'var(--purple)',
          display: 'flex', alignItems: 'flex-start', gap: '0.75rem',
        }}>
          <span>🔑</span>
          <div>
            <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>AI Analysis Unavailable</div>
            <div style={{ color: 'var(--text-3)' }}>
              {result?.error ? `${result.error} — set GEMINI_API_KEY or GROQ_API_KEY in your environment to enable AI threat analysis.` : (result?.summary || 'No AI API key is configured. Set GEMINI_API_KEY or GROQ_API_KEY in .env to enable AI-assisted analysis.')}
            </div>
          </div>
        </div>
      )}

      {/* Error state */}
      {state === 'error' && (
        <div className="error-banner fade-in">⚠️ {error}</div>
      )}

      {/* Done state */}
      {state === 'done' && result && (
        <div className="fade-in" style={{
          background: vc.bg, border: `1px solid ${vc.border}`,
          borderRadius: 'var(--r-md)', padding: '1.25rem',
        }}>
          {/* Top row: verdict + confidence */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
              <span style={{ fontSize: '1.25rem' }}>{vc.icon}</span>
              <div>
                <div style={{ fontWeight: 700, color: vc.color, fontSize: '0.9rem', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  {result.verdict.replace('_', ' ')}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-3)' }}>
                  Severity: <span style={{ color: vc.color, fontWeight: 600 }}>{result.severity}</span>
                </div>
              </div>
            </div>
            <ConfidenceBar value={result.confidence} color={vc.color} />
          </div>

          {/* Model info */}
          <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', fontFamily: 'var(--mono)', marginBottom: '0.875rem' }}>
            Model: {result.model_name} · {result.prompt_tokens + result.completion_tokens} tokens used
          </div>

          {/* Summary */}
          <div style={{ fontSize: '0.9rem', color: 'var(--text-1)', lineHeight: 1.6, marginBottom: '1rem' }}>
            {result.summary}
          </div>

          {/* Evidence */}
          {result.evidence?.length > 0 && (
            <Section title="Evidence Points" icon="🔍" color={vc.color}>
              {result.evidence.map((e, i) => <ListItem key={i} text={e} color={vc.color} />)}
            </Section>
          )}

          {/* Recommendations */}
          {result.recommendations?.length > 0 && (
            <Section title="Recommendations" icon="💡" color="var(--cyan)">
              {result.recommendations.map((r, i) => <ListItem key={i} text={r} color="var(--cyan)" />)}
            </Section>
          )}

          {/* Limitations */}
          {result.limitations?.length > 0 && (
            <div style={{
              marginTop: '0.875rem', padding: '0.75rem',
              background: 'rgba(255,255,255,0.03)', borderRadius: 'var(--r-sm)',
              borderLeft: '3px solid rgba(255,255,255,0.1)',
            }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                ⚠️ Limitations
              </div>
              {result.limitations.map((l, i) => (
                <div key={i} style={{ fontSize: '0.78rem', color: 'var(--text-3)', lineHeight: 1.5 }}>• {l}</div>
              ))}
            </div>
          )}

          {/* Advisory disclaimer */}
          <div style={{
            marginTop: '1rem', padding: '0.625rem 0.875rem',
            background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--r-sm)',
            fontSize: '0.72rem', color: 'var(--text-3)',
            display: 'flex', alignItems: 'center', gap: '0.5rem',
          }}>
            🛡️ This AI assessment is advisory only. The deterministic scan engine (ClamAV + regex rules) remains the authoritative security verdict.
          </div>
        </div>
      )}
    </div>
  );
}

function ConfidenceBar({ value, color }) {
  const pct = Math.round(value * 100);
  return (
    <div style={{ textAlign: 'right' }}>
      <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', marginBottom: '0.35rem' }}>
        Confidence: <span style={{ color, fontFamily: 'var(--mono)', fontWeight: 700 }}>{pct}%</span>
      </div>
      <div style={{ width: '100px', height: '4px', background: 'rgba(255,255,255,0.08)', borderRadius: '9999px', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: '9999px', transition: 'width 0.6s ease' }} />
      </div>
    </div>
  );
}

function Section({ title, icon, color, children }) {
  return (
    <div style={{ marginBottom: '0.875rem' }}>
      <div style={{ fontSize: '0.75rem', fontWeight: 700, color, letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
        {icon} {title}
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
      <span style={{ color, flexShrink: 0, marginTop: '2px' }}>›</span>
      <span style={{ fontSize: '0.85rem', color: 'var(--text-2)', lineHeight: 1.5 }}>{text}</span>
    </div>
  );
}
