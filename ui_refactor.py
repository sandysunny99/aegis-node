import os

# --- Update App.jsx ---
app_jsx_path = "frontend/src/App.jsx"
with open(app_jsx_path, "r", encoding="utf-8") as f:
    app_jsx = f.read()

# Replace header structure for responsiveness
new_header = """
      <header className="header" style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="brand" style={{ flexShrink: 0 }}>
          <div className="brand-shield">🛡️</div>
          <div>
            <div className="brand-name">Aegis Node</div>
            <div className="brand-sub">Dataset Threat Detection & Remediation</div>
          </div>
        </div>
        <div style={{ flex: '1 1 auto', overflowX: 'auto' }}>
          <HealthStatus health={health} />
        </div>
      </header>
"""
import re
app_jsx = re.sub(r'<header className="header">.*?</header>', new_header.strip(), app_jsx, flags=re.DOTALL)

# Replace Stepper with a compact progress bar
new_stepper = """
      {/* COMPACT PROGRESS BAR */}
      <div style={{
        display: 'flex', gap: '0.5rem', marginBottom: '1.5rem', background: 'var(--bg-1)', padding: '0.75rem',
        borderRadius: 'var(--r-md)', border: '1px solid var(--border)', fontSize: '0.75rem', fontWeight: 600,
        overflowX: 'auto', whiteSpace: 'nowrap', alignItems: 'center'
      }}>
        <span style={{ color: phase !== 'idle' ? 'var(--cyan)' : 'var(--text-1)' }}>01 UPLOAD</span>
        <span style={{ color: 'var(--text-3)' }}>→</span>
        <span style={{ color: phase === 'uploaded' || isScanning || isDone || isError ? 'var(--cyan)' : 'var(--text-3)' }}>02 SCAN</span>
        <span style={{ color: 'var(--text-3)' }}>→</span>
        <span style={{ color: isDone || isError ? 'var(--cyan)' : 'var(--text-3)' }}>03 AI + TI</span>
        <span style={{ color: 'var(--text-3)' }}>→</span>
        <span style={{ color: isDone || isError ? 'var(--cyan)' : 'var(--text-3)' }}>04 REMEDIATE</span>
        <span style={{ color: 'var(--text-3)' }}>→</span>
        <span style={{ color: isDone || isError ? 'var(--cyan)' : 'var(--text-3)' }}>05 VERIFY</span>
      </div>
"""
app_jsx = re.sub(r'\{/\*\s*Stepper\s*\*/\}(.*?)\{/\*\s*Upload & Scan Actions\s*\*/\}', new_stepper + "\n      {/* Upload & Scan Actions */}", app_jsx, flags=re.DOTALL)

# Refactor the main results structure
new_results = """
      {/* Scan Results */}
      {isDone && scanResult && (
        <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>📄</span> Multi-Stage Security Report: {scanResult.dataset_id}
          </div>

          {/* COMPACT RESULT HEADER */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', background: 'var(--bg-1)', padding: '1rem', borderRadius: 'var(--r-md)', border: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: '0.8rem' }}>
             <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>VERDICT</div><StatusBadge verdict={scanResult.verdict} /></div>
             <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>RISK SCORE</div><strong style={{ color: scanResult.risk_score > 6 ? 'var(--rose)' : scanResult.risk_score > 3 ? 'var(--amber)' : 'var(--emerald)' }}>{scanResult.risk_score.toFixed(1)}/10</strong></div>
             <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>DETECTIONS</div><strong style={{ color: scanResult.threats_found_count > 0 ? 'var(--rose)' : 'var(--emerald)' }}>{scanResult.threats_found_count}</strong></div>
             <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>COVERAGE</div><strong style={{ color: 'var(--cyan)' }}>{scanResult.coverage_percentage ?? 100}%</strong></div>
             <div style={{ flex: 1, minWidth: '120px' }}><div style={{ color: 'var(--text-3)', fontSize: '0.65rem' }}>SCAN TIME</div><strong style={{ color: 'var(--text-1)' }}>{scanResult.scan_duration_ms} ms</strong></div>
          </div>

          {/* B. LOCAL DETECTION */}
          <div className="card">
            <div className="card-title">B. LOCAL DETECTION <span style={{fontSize: '0.7rem', color: 'var(--text-3)', fontWeight: 400}}>(Primary Authority)</span></div>
            <div style={{ display: 'flex', gap: '1.5rem', marginBottom: '1rem', fontSize: '0.85rem' }}>
              <div>ClamAV: <strong style={{ color: 'var(--text-1)' }}>{scanResult.clamav_status}</strong> {scanResult.clamav_virus_name && <span style={{color: 'var(--rose)'}}>({scanResult.clamav_virus_name})</span>}</div>
              <div>YARA: <strong style={{ color: 'var(--text-1)' }}>Enabled</strong></div>
              <div>Heuristics: <strong style={{ color: 'var(--text-1)' }}>Active</strong></div>
            </div>
            <FindingsList findings={scanResult.findings} />
          </div>

          {/* C. THREAT INTELLIGENCE */}
          <ThreatIntelligence tiReport={scanResult.threat_intel} />

          {/* D. AI SECURITY */}
          <AiSummary datasetId={scanResult.dataset_id} />

          {/* E & F. REMEDIATION & VERIFICATION */}
          <RemediationCard datasetId={scanResult.dataset_id} scanResult={scanResult} />
        </div>
      )}
"""
app_jsx = re.sub(r'\{/\*\s*Scan Results\s*\*/\}.*?(?=\{uploadResult && \()', new_results, app_jsx, flags=re.DOTALL)

with open(app_jsx_path, "w", encoding="utf-8") as f:
    f.write(app_jsx)


# --- Update ThreatIntelligence.jsx ---
ti_path = "frontend/src/components/ThreatIntelligence.jsx"
with open(ti_path, "r", encoding="utf-8") as f:
    ti_jsx = f.read()

new_ti = """import React, { useState } from 'react';

export default function ThreatIntelligence({ tiReport }) {
  const [collapsed, setCollapsed] = useState(false);
  
  if (!tiReport) return null;

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div className="card-title" style={{ marginBottom: '0.2rem' }}>C. THREAT INTELLIGENCE</div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-3)' }}>External Enrichment (Non-Authoritative)</div>
        </div>
        <button className="btn btn-ghost" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }} onClick={() => setCollapsed(!collapsed)}>
          {collapsed ? 'Expand ▼' : 'Collapse ▲'}
        </button>
      </div>

      {!collapsed && (
        <div style={{ marginTop: '1.5rem' }}>
          <div style={{ background: 'rgba(59, 130, 246, 0.05)', padding: '0.75rem', borderRadius: 'var(--r-sm)', border: '1px solid rgba(59, 130, 246, 0.1)', marginBottom: '1.5rem', fontSize: '0.8rem', color: 'var(--text-2)' }}>
            <span style={{ marginRight: '1rem' }}><strong>IOC SUMMARY:</strong></span>
            <span>{(tiReport.urlhaus?.url_count || 0) + (tiReport.abuseipdb?.ip_count || 0)} IOCs extracted</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
            {/* VirusTotal */}
            <div style={{ background: 'var(--bg-2)', padding: '1rem', borderRadius: 'var(--r-sm)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-1)', marginBottom: '0.5rem' }}>VirusTotal</div>
              {tiReport.virustotal?.status === 'not_configured' ? (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>UNCONFIGURED</div>
              ) : tiReport.virustotal?.status === 'not_found' ? (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-2)' }}>NOT FOUND (Hash unknown)</div>
              ) : (
                <div style={{ fontSize: '0.75rem' }}>
                  <div style={{ color: tiReport.virustotal?.malicious > 0 ? 'var(--rose)' : 'var(--emerald)' }}>
                    <strong>{tiReport.virustotal?.malicious || 0}</strong> malicious
                  </div>
                  <div style={{ color: 'var(--amber)' }}>{tiReport.virustotal?.suspicious || 0} suspicious</div>
                </div>
              )}
            </div>

            {/* URLhaus */}
            <div style={{ background: 'var(--bg-2)', padding: '1rem', borderRadius: 'var(--r-sm)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-1)', marginBottom: '0.5rem' }}>URLhaus</div>
              {tiReport.urlhaus?.status === 'not_configured' ? (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>UNCONFIGURED</div>
              ) : (
                <div style={{ fontSize: '0.75rem', color: tiReport.urlhaus?.malicious_found ? 'var(--rose)' : 'var(--text-2)' }}>
                  {tiReport.urlhaus?.malicious_found ? 'Malicious URLs detected' : 'No malicious match'}
                  <div style={{ color: 'var(--text-3)', marginTop: '0.25rem' }}>{tiReport.urlhaus?.url_count || 0} checked</div>
                </div>
              )}
            </div>

            {/* AbuseIPDB */}
            <div style={{ background: 'var(--bg-2)', padding: '1rem', borderRadius: 'var(--r-sm)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-1)', marginBottom: '0.5rem' }}>AbuseIPDB</div>
              {tiReport.abuseipdb?.status === 'not_configured' ? (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-3)' }}>UNCONFIGURED</div>
              ) : (
                <div style={{ fontSize: '0.75rem', color: tiReport.abuseipdb?.malicious_found ? 'var(--rose)' : 'var(--text-2)' }}>
                  {tiReport.abuseipdb?.malicious_found ? 'Malicious IPs detected' : 'No malicious evidence'}
                  <div style={{ color: 'var(--text-3)', marginTop: '0.25rem' }}>{tiReport.abuseipdb?.ip_count || 0} public IPs checked</div>
                </div>
              )}
            </div>
          </div>
          
          <div style={{ marginTop: '1.5rem', fontSize: '0.7rem', color: 'var(--text-3)', borderTop: '1px solid var(--border)', paddingTop: '0.75rem' }}>
            ⓘ <strong>Evidence note:</strong> External intelligence is enrichment. Local deterministic scanning remains the primary security authority.
          </div>
        </div>
      )}
    </div>
  );
}
"""
with open(ti_path, "w", encoding="utf-8") as f:
    f.write(new_ti)


# --- Update AiSummary.jsx ---
ai_path = "frontend/src/components/AiSummary.jsx"
with open(ai_path, "r", encoding="utf-8") as f:
    ai_jsx = f.read()

new_ai = """
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
            <span style={{ color: 'var(--blue)' }}>🛡️</span> D. AI SECURITY & ANALYSIS
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
"""
with open(ai_path, "w", encoding="utf-8") as f:
    f.write(new_ai)


# --- Update FindingsList.jsx ---
findings_path = "frontend/src/components/FindingsList.jsx"
with open(findings_path, "r", encoding="utf-8") as f:
    findings_jsx = f.read()

new_findings = """
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
"""
with open(findings_path, "w", encoding="utf-8") as f:
    f.write(new_findings)

# --- Update RemediationCard.jsx to E & F ---
rem_path = "frontend/src/components/RemediationCard.jsx"
with open(rem_path, "r", encoding="utf-8") as f:
    rem_jsx = f.read()

# Just change the title
rem_jsx = rem_jsx.replace('className="card-title" style={{ marginBottom: \'0.2rem\' }}>', 'className="card-title" style={{ marginBottom: \'0.2rem\' }}>E. REMEDIATION & F. VERIFICATION')
with open(rem_path, "w", encoding="utf-8") as f:
    f.write(rem_jsx)

# --- CSS responsive fixes ---
css_path = "frontend/src/index.css"
with open(css_path, "a", encoding="utf-8") as f:
    f.write("""
/* --- UI OPTIMIZATIONS --- */
.main {
  max-width: 1180px;
  margin: 0 auto;
  padding: 0 1rem;
}

@media (max-width: 768px) {
  .header {
    flex-direction: column;
    align-items: flex-start;
  }
}
""")
