import React, { useState } from 'react';

export default function ThreatIntelligence({ tiReport }) {
  const [collapsed, setCollapsed] = useState(false);
  
  if (!tiReport) return null;

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div className="card-title" style={{ marginBottom: '0.2rem' }}>THREAT INTELLIGENCE</div>
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
