import React, { useEffect, useState } from 'react';
import { getHistory, getSanitizedDownloadUrl } from '../api';

function formatBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 ** 2).toFixed(1)} MB`;
}

function formatDate(dt) {
  if (!dt) return '-';
  return new Date(dt).toLocaleString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

const STATUS_COLORS = {
  uploaded:            'var(--blue)',
  scanning:            'var(--cyan)',
  clean:               'var(--emerald)',
  quarantined:         'var(--rose)',
  suspicious:          'var(--amber)',
  remediated:          'var(--emerald)',
  partial_remediated:  'var(--amber)',
  error:               'var(--rose)',
};

const VERDICT_COLORS = {
  clean:     'var(--emerald)',
  suspicious:'var(--amber)',
  malicious: 'var(--rose)',
};

export default function HistoryPage() {
  const [state, setState] = useState('loading');
  const [data, setData] = useState(null);
  const [page, setPage] = useState(1);
  const [error, setError] = useState('');

  const loadPage = async (p) => {
    setState('loading'); setError('');
    try {
      const r = await getHistory(p, 20);
      setData(r); setPage(p); setState('done');
    } catch (e) {
      setError(e.message); setState('error');
    }
  };

  useEffect(() => { loadPage(1); }, []);

  if (state === 'loading') {
    return (
      <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-3)' }}>
        <div className="spinner" style={{ margin: '0 auto 0.75rem' }} />
        Loading scan history…
      </div>
    );
  }

  if (state === 'error') {
    return <div className="error-banner">⚠️ {error}</div>;
  }

  if (!data || data.items.length === 0) {
    return (
      <div className="card fade-in">
        <div className="empty">
          <div className="empty-icon">📂</div>
          <div>No scans yet. Upload a dataset to get started.</div>
        </div>
      </div>
    );
  }

  const totalPages = Math.ceil(data.total / 20);

  return (
    <div className="card fade-in" id="history-page">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div className="card-title" style={{ marginBottom: 0 }}>📋 Scan History</div>
        <div style={{ fontSize: '0.78rem', color: 'var(--text-3)', fontFamily: 'var(--mono)' }}>
          {data.total} dataset{data.total !== 1 ? 's' : ''} total
        </div>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.83rem' }}>
          <thead>
            <tr>
              {['#', 'Filename', 'Format', 'Size', 'Status', 'Verdict', 'Risk', 'Threats', 'Scanned At', 'Download'].map(h => (
                <th key={h} style={{
                  padding: '0.5rem 0.75rem', textAlign: 'left',
                  color: 'var(--text-3)', fontWeight: 600, fontSize: '0.72rem',
                  textTransform: 'uppercase', letterSpacing: '0.06em',
                  borderBottom: '1px solid var(--border)',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.items.map((item, idx) => (
              <HistoryRow key={item.dataset_id} item={item} idx={(page - 1) * 20 + idx + 1} />
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center', marginTop: '1.25rem', flexWrap: 'wrap' }}>
          <button className="btn btn-ghost" disabled={page <= 1} onClick={() => loadPage(page - 1)}>← Prev</button>
          <span style={{ alignSelf: 'center', fontSize: '0.8rem', color: 'var(--text-3)', fontFamily: 'var(--mono)' }}>
            {page} / {totalPages}
          </span>
          <button className="btn btn-ghost" disabled={page >= totalPages} onClick={() => loadPage(page + 1)}>Next →</button>
        </div>
      )}
    </div>
  );
}

function HistoryRow({ item, idx }) {
  const statusColor = STATUS_COLORS[item.status] || 'var(--text-3)';
  const verdictColor = VERDICT_COLORS[item.verdict] || 'var(--text-3)';
  const showDownload = ['remediated', 'partial_remediated'].includes(item.status);

  return (
    <tr style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.15s' }}
      onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
    >
      <td style={{ padding: '0.75rem', color: 'var(--text-3)', fontFamily: 'var(--mono)', fontSize: '0.72rem' }}>
        #{item.dataset_id}
      </td>
      <td style={{ padding: '0.75rem', maxWidth: '180px' }}>
        <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-1)' }}>
          {item.original_filename}
        </div>
      </td>
      <td style={{ padding: '0.75rem' }}>
        <span style={{
          padding: '0.15rem 0.5rem', borderRadius: '9999px',
          background: 'rgba(59,130,246,0.1)', color: 'var(--blue)',
          fontSize: '0.7rem', fontWeight: 600, fontFamily: 'var(--mono)',
        }}>
          {item.file_format?.toUpperCase() || '—'}
        </span>
      </td>
      <td style={{ padding: '0.75rem', color: 'var(--text-3)', fontFamily: 'var(--mono)', fontSize: '0.75rem' }}>
        {formatBytes(item.file_size_bytes)}
      </td>
      <td style={{ padding: '0.75rem' }}>
        <span style={{
          padding: '0.15rem 0.5rem', borderRadius: '9999px',
          background: `${statusColor}18`, color: statusColor,
          border: `1px solid ${statusColor}30`,
          fontSize: '0.7rem', fontWeight: 600,
        }}>
          {item.status.replace(/_/g, ' ')}
        </span>
      </td>
      <td style={{ padding: '0.75rem', color: verdictColor, fontWeight: 600, fontSize: '0.78rem', textTransform: 'capitalize' }}>
        {item.verdict || '—'}
      </td>
      <td style={{ padding: '0.75rem', fontFamily: 'var(--mono)', color: item.risk_score > 6 ? 'var(--rose)' : item.risk_score > 3 ? 'var(--amber)' : 'var(--emerald)', fontWeight: 700 }}>
        {item.risk_score !== null ? item.risk_score.toFixed(1) : '—'}
      </td>
      <td style={{ padding: '0.75rem', color: item.threats_found_count > 0 ? 'var(--rose)' : 'var(--emerald)', fontFamily: 'var(--mono)', fontWeight: 700 }}>
        {item.threats_found_count !== null ? item.threats_found_count : '—'}
      </td>
      <td style={{ padding: '0.75rem', color: 'var(--text-3)', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
        {formatDate(item.scanned_at)}
      </td>
      <td style={{ padding: '0.75rem' }}>
        {showDownload ? (
          <a
            href={getSanitizedDownloadUrl(item.dataset_id)}
            download
            title="Download sanitized dataset"
            style={{
              color: 'var(--cyan)', textDecoration: 'none',
              fontSize: '1rem', cursor: 'pointer',
            }}
          >
            ⬇
          </a>
        ) : <span style={{ color: 'var(--text-3)' }}>—</span>}
      </td>
    </tr>
  );
}
