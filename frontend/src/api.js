import { scanQuery } from './status/history';

/**
 * Aegis Node API client.
 * Uses fetch for standard requests and XMLHttpRequest for upload progress tracking.
 */

// Same origin by default: FastAPI serves the built UI, and the Vite dev server proxies
// /api and /health. Set VITE_API_URL only when the API lives on another host.
const BASE = import.meta.env.VITE_API_URL ?? '';

// S2: no API key in the browser. Anything read from import.meta.env.VITE_* is
// compiled into the public bundle, so a key here would protect nothing. API_KEY
// is for server-to-server/admin use; the public UI relies on Turnstile, rate
// limits and unguessable dataset ids.

/** Map HTTP status codes to user-friendly messages. */
function friendlyError(status, fallback) {
  if (status === 429) return 'Too many requests. Wait a moment before trying again.';
  if (status === 403) {
    if (fallback && fallback.toLowerCase().includes('turnstile')) return 'Upload blocked: bot verification failed or is unavailable.';
    if (fallback && fallback.toLowerCase().includes('download')) return 'Access denied: the sanitized download token may be invalid or expired.';
    return fallback || 'Access denied.';
  }
  if (status === 401) return 'This server requires an API key; the public web UI cannot use it.';
  // The limit is per deployment (25 MB on Render), so use the server's own message.
  if (status === 413) return fallback && !/^HTTP \d+/.test(fallback) && fallback !== 'Request Entity Too Large' ? fallback : 'File is too large for this server. Settings shows the upload limit.';
  if (status === 415) return 'Unsupported file type. Please upload a CSV, JSON, JSONL, Parquet, XLSX, or TXT file.';
  if (status === 404) return 'Resource not found. Please refresh and try again.';
  if (status === 500) return 'An internal server error occurred. Check that the backend is running.';
  return fallback;
}

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { ...(options.headers ?? {}) },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    const detail = err.detail ?? `HTTP ${res.status}`;
    const error = new Error(friendlyError(res.status, typeof detail === 'string' ? detail : `HTTP ${res.status}`));
    // Kept so callers can tell "route not on this server" from "resource not found".
    error.status = res.status;
    error.detail = detail;
    throw error;
  }
  return res.json();
}

/**
 * Upload a file with progress tracking.
 * @param {File} file - The file to upload.
 * @param {(pct: number) => void} onProgress - Progress callback (0–100).
 * @param {string|null} turnstileToken - Optional Cloudflare Turnstile token.
 * @returns {Promise<Object>} Upload response
 */
export function uploadDataset(file, onProgress, turnstileToken = null) {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append('file', file);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${BASE}/api/v1/datasets/upload`);

    if (turnstileToken) xhr.setRequestHeader('X-Turnstile-Token', turnstileToken);

    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable && onProgress) {
        onProgress(Math.round((e.loaded / e.total) * 100));
      }
    });

    xhr.addEventListener('load', () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const body = JSON.parse(xhr.responseText);
          rememberDataset(body.dataset_id);
          resolve(body);
        } catch {
          reject(new Error('Invalid JSON response from server.'));
        }
      } else {
        try {
          const err = JSON.parse(xhr.responseText);
          const detail = err.detail ?? `HTTP ${xhr.status}`;
          reject(new Error(friendlyError(xhr.status, detail)));
        } catch {
          reject(new Error(friendlyError(xhr.status, `HTTP ${xhr.status}: ${xhr.statusText}`)));
        }
      }
    });

    xhr.addEventListener('error', () => reject(new Error('Network error. Check your connection and try again.')));
    xhr.addEventListener('abort', () => reject(new Error('Upload was cancelled.')));

    xhr.send(form);
  });
}


export async function scanDataset(datasetId) {
  return request(`/api/v1/datasets/${datasetId}/scan`, { method: 'POST' });
}

export async function getDatasetStatus(datasetId) {
  return request(`/api/v1/datasets/${datasetId}`);
}

export async function getScanReport(datasetId) {
  return request(`/api/v1/datasets/${datasetId}/report`);
}

export async function analyseDataset(datasetId, { llmMode = 'auto', provider = null, model = null } = {}) {
  const params = new URLSearchParams({ llm_mode: llmMode });
  if (provider) params.append('provider', provider);
  if (model) params.append('model', model);
  return request(`/api/v1/datasets/${datasetId}/analyse?${params.toString()}`, { method: 'POST' });
}

export async function getLlmProviders() {
  return request('/api/v1/datasets/llm/providers');
}

export async function getAnalysis(datasetId) {
  return request(`/api/v1/datasets/${datasetId}/analysis`);
}

export async function remediateDataset(datasetId) {
  return request(`/api/v1/datasets/${datasetId}/remediate`, { method: 'POST' });
}

export async function getRemediationReport(datasetId) {
  return request(`/api/v1/datasets/${datasetId}/remediation`);
}

/**
 * Download a sanitized dataset file using Authorization header (A-002, A-018).
 * Token is sent via 'Authorization: Bearer <token>' to avoid URL exposure in access logs and browser history.
 * @param {string} datasetId - public dataset id
 * @param {string} token - The download_token from remediation response
 */
export async function downloadSanitized(datasetId, token) {
  const headers = {};
  if (token) {
    headers.Authorization = 'Bearer ' + token;
  }

  const res = await fetch(`${BASE}/api/v1/datasets/${datasetId}/download-sanitized`, {
    headers,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(friendlyError(res.status, err.detail ?? 'Download failed'));
  }

  const blob = await res.blob();
  // Extract filename from Content-Disposition if present, else fallback
  const cd = res.headers.get('Content-Disposition') || '';
  const match = cd.match(/filename="?([^"]+)"?/);
  const filename = match ? match[1] : `sanitized_dataset_${datasetId}`;

  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(blobUrl);
}

/**
 * @deprecated Use downloadSanitized() instead to avoid leaking download tokens in query params.
 */
export function getSanitizedDownloadUrl(datasetId, token) {
  const url = `${BASE}/api/v1/datasets/${datasetId}/download-sanitized`;
  return token ? `${url}?token=${encodeURIComponent(token)}` : url;
}

// ─── Uploads made from this browser ──────────────────────────────────────────
// Dataset ids are unguessable, so they double as access capabilities. History
// lists only the ids this browser uploaded (a public deployment has no API key
// to grant a global view). Wrapped in try/catch: storage can be unavailable.
const MY_DATASETS_KEY = 'aegis.myDatasets';

export function myDatasetIds() {
  try {
    const ids = JSON.parse(window.localStorage.getItem(MY_DATASETS_KEY) || '[]');
    return Array.isArray(ids) ? ids.filter((id) => /^[0-9a-f]{32}$/.test(id)) : [];
  } catch {
    return [];
  }
}

function rememberDataset(id) {
  if (!/^[0-9a-f]{32}$/.test(id || '')) return;
  try {
    const ids = [id, ...myDatasetIds().filter((x) => x !== id)].slice(0, 100);
    window.localStorage.setItem(MY_DATASETS_KEY, JSON.stringify(ids));
  } catch {
    // storage unavailable (private mode); history just stays empty
  }
}

export async function getHistory(page = 1, pageSize = 20) {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  params.set('ids', myDatasetIds().join(','));
  return request(`/api/v1/history?${params.toString()}`);
}

// ─── Scan history (GET /api/v1/scans …, docs/SCAN_HISTORY_API.md) ────────────
// Older servers do not have these routes; see status/history.js historyMissing().

export async function listScans(filters = {}, page = 1, pageSize = 20) {
  const params = scanQuery(filters, page, pageSize);
  // A public deployment has no API key, so the list is scoped to this browser's uploads.
  params.set('ids', myDatasetIds().join(','));
  return request(`/api/v1/scans?${params.toString()}`);
}

export async function getScan(scanId) {
  return request(`/api/v1/scans/${scanId}`);
}

export async function getScanEvents(scanId) {
  return request(`/api/v1/scans/${scanId}/events`);
}

export async function getDatasetScans(datasetId) {
  return request(`/api/v1/datasets/${datasetId}/scans`);
}

export async function getDatasetEvents(datasetId) {
  return request(`/api/v1/datasets/${datasetId}/events`);
}

export async function getDetectors() {
  return request('/health/detectors');
}

export async function healthCheck() {
  return request('/health');
}
