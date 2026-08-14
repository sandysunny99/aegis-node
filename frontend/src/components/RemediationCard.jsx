import React, { useCallback, useState } from 'react';
import { downloadSanitized, remediateDataset } from '../api';

function CircleProgress({ value, size = 56, strokeWidth = 5, color }) {
  const r = (size - strokeWidth) / 2;
  const circ = 2 * Math.PI * r;
  const dash = circ * (value / 100);
  return (
    <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={strokeWidth} />
      <circle
        cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color}
        strokeWidth={strokeWidth} strokeLinecap="round"
        strokeDasharray={`${dash} ${circ - dash}`}
        style={{ transition: 'stroke-dasharray 0.8s ease' }}
      />
    </svg>
  );
}

export default function RemediationCard({ datasetId, scanResult }) {
  const [state, setState] = useState('idle'); // idle | loading | done | error
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');

  const hasThreats = scanResult?.threats_found_count > 0;

  const handleRemediate = useCallback(async () => {
    setState('loading'); setError('');
    try {
      const r = await remediateDataset(datasetId);
      setReport(r); setState('done');
    } catch (e) {
      setError(e.message); setState('error');
    }
  }, [datasetId]);

  if (!hasThreats) {
    return (
      <div style={{
        marginTop: '1.5rem', padding: '1.25rem',
        background: 'rgba(16,185,129,0.06)',
        border: '1px solid rgba(16,185,129,0.2)',
        borderRadius: 'var(--r-md)',
        display: 'flex', alignItems: 'center', gap: '0.875rem',
      }}>
        <span style={{ fontSize: '1.5rem' }}>✅</span>
        <div>
          <div style={{ fontWeight: 600, color: 'var(--emerald)', marginBottom: '0.2rem' }}>Dataset is Clean</div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-3)' }}>No threats were detected. No remediation is needed.</div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ marginTop: '1.5rem' }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem',
      }}>
        <div>
          <div style={{ fontWeight: 600, color: 'var(--text-1)', marginBottom: '0.25rem' }}>
            🛠️ Risk-Based Remediation
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-3)' }}>
            Neutralizes threats in-place while preserving dataset schema and structure.
          </div>
        </div>
        {state === 'idle' && (
          <button className="btn btn-primary" onClick={handleRemediate} id="remediate-btn">
            Remediate & Sanitize
          </button>
        )}
        {state === 'loading' && (
          <button className="btn btn-primary" disabled>
            <span className="spinner" /> Sanitizing…
          </button>
        )}
      </div>

      {state === 'error' && (
        <div className="error-banner fade-in">⚠️ {error}</div>
      )}

      {state === 'done' && report && (
        <div className="fade-in">
          {/* Metrics grid */}
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px,1fr))',
            gap: '0.875rem', marginBottom: '1.25rem',
          }}>
            <MetricRing
              label="Threat Reduction"
              value={report.threat_reduction_percent}
              color={report.threat_reduction_percent === 100 ? 'var(--emerald)' : 'var(--amber)'}
            />
            <MetricRing
              label="Data Integrity"
              value={report.integrity_preserved ?? 100}
              color="var(--cyan)"
            />
            <MetricBox label="Threats Resolved" value={report.resolved_findings_count} color="var(--emerald)" />
            <MetricBox label="Remaining" value={report.remaining_findings_count} color={report.remaining_findings_count > 0 ? 'var(--rose)' : 'var(--emerald)'} />
            <MetricBox label="Changes Made" value={report.changes_count} color="var(--blue)" />
          </div>

          {/* Status banner */}
          <div style={{
            padding: '0.75rem 1rem', borderRadius: 'var(--r-sm)',
            background: report.remediation_status === 'completed'
              ? 'rgba(16,185,129,0.08)' : 'rgba(245,158,11,0.08)',
            border: `1px solid ${report.remediation_status === 'completed'
              ? 'rgba(16,185,129,0.25)' : 'rgba(245,158,11,0.25)'}`,
            marginBottom: '1rem',
            fontSize: '0.85rem',
            color: report.remediation_status === 'completed' ? 'var(--emerald)' : 'var(--amber)',
            display: 'flex', alignItems: 'center', gap: '0.625rem',
          }}>
            {report.remediation_status === 'completed' ? '✅' : '⚠️'}
            Remediation {report.remediation_status === 'completed' ? 'completed — all threats neutralized' : 'partial — some threats may remain'}
          </div>

          {/* Actions taken */}
          {report.actions && report.actions.length > 0 && (
            <ActionsList actions={report.actions} />
          )}

          {/* Download — only shown when download_token is available (A-002, A-018) */}
          {report.download_token && (
            <div style={{ marginTop: '1rem', display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <button
                onClick={async () => {
                  try {
                    await downloadSanitized(datasetId, report.download_token);
                  } catch (err) {
                    setError(err.message);
                  }
                }}
                className="btn btn-primary"
                id="download-sanitized-btn"
              >
                ⬇ Download Clean Dataset
              </button>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>
                SHA-256: <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-2)', fontSize: '0.7rem' }}>
                  {report.sanitized_sha256?.slice(0, 12)}…
                </span>
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function MetricRing({ label, value, color }) {
  return (
    <div style={{
      background: 'var(--bg-3)', border: '1px solid var(--border)',
      borderRadius: 'var(--r-sm)', padding: '1rem',
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem',
    }}>
      <div style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>
        <CircleProgress value={value} size={60} strokeWidth={5} color={color} />
        <span style={{
          position: 'absolute', fontSize: '0.75rem', fontWeight: 700,
          fontFamily: 'var(--mono)', color,
        }}>{value.toFixed(0)}%</span>
      </div>
      <div style={{ fontSize: '0.7rem', color: 'var(--text-3)', textAlign: 'center', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        {label}
      </div>
    </div>
  );
}

function MetricBox({ label, value, color }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={{ color }}>{value}</div>
    </div>
  );
}

function ActionsList({ actions }) {
  const [show, setShow] = React.useState(false);
  return (
    <div>
      <button
        onClick={() => setShow(x => !x)}
        style={{
          background: 'none', border: 'none', color: 'var(--cyan)',
          cursor: 'pointer', fontSize: '0.8rem', fontFamily: 'var(--font)',
          display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0',
          marginBottom: show ? '0.75rem' : '0',
        }}
      >
        {show ? '▾' : '▸'} {actions.length} remediation action{actions.length !== 1 ? 's' : ''} taken
      </button>
      {show && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {actions.map((a, i) => (
            <div key={i} style={{
              background: 'var(--bg-0)', border: '1px solid var(--border)',
              borderRadius: 'var(--r-sm)', padding: '0.625rem 0.875rem',
              fontSize: '0.8rem',
            }}>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.25rem' }}>
                <span style={{ fontFamily: 'var(--mono)', color: 'var(--cyan)', fontSize: '0.72rem' }}>{a.rule_id}</span>
                <span style={{ color: 'var(--text-3)', fontSize: '0.7rem' }}>{a.location}</span>
              </div>
              <div style={{ color: 'var(--text-2)' }}>{a.action_taken}</div>
              {a.sample_after && (
                <div style={{
                  marginTop: '0.35rem', fontFamily: 'var(--mono)', fontSize: '0.72rem',
                  color: 'var(--emerald)', background: 'rgba(0,0,0,0.3)',
                  padding: '0.25rem 0.5rem', borderRadius: '4px',
                }}>→ {a.sample_after}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
