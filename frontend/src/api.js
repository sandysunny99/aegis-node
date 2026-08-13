/**
 * Aegis Node — API Client
 * Uses fetch for standard requests and XMLHttpRequest for upload progress tracking.
 */

const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

// Optional API key — set VITE_API_KEY in .env (local) or Render dashboard (production).
// When set, sent as X-API-Key header on all write endpoints (upload, scan, remediate).
// If not set (default), write endpoints are open (dev mode).
const API_KEY = import.meta.env.VITE_API_KEY ?? '';

/** Returns X-API-Key header object if key is configured, else empty object. */
function authHeader() {
  return API_KEY ? { 'X-API-Key': API_KEY } : {};
}

/** Map HTTP status codes to user-friendly messages. */
function friendlyError(status, fallback) {
  if (status === 429) return 'Too many requests — please wait a moment before trying again.';
  if (status === 403) return 'Access denied. The download link may have expired (60 min limit) — please re-run remediation.';
  if (status === 401) return 'API key required. Configure VITE_API_KEY in your environment.';
  if (status === 413) return 'File is too large. Maximum upload size is 500 MB.';
  if (status === 415) return 'Unsupported file type. Please upload a CSV, JSON, JSONL, Parquet, XLSX, or TXT file.';
  if (status === 404) return 'Resource not found. Please refresh and try again.';
  if (status === 500) return 'An internal server error occurred. Check that the backend is running.';
  return fallback;
}

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { ...authHeader(), ...(options.headers ?? {}) },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    const detail = err.detail ?? `HTTP ${res.status}`;
    throw new Error(friendlyError(res.status, detail));
  }
  return res.json();
}

/**
 * Upload a file with progress tracking.
 * @param {File} file - The file to upload.
 * @param {(pct: number) => void} onProgress - Progress callback (0–100).
 * @returns {Promise<Object>} Upload response
 */
export function uploadDataset(file, onProgress) {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append('file', file);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${BASE}/api/v1/datasets/upload`);

    // Include API key header if configured
    if (API_KEY) xhr.setRequestHeader('X-API-Key', API_KEY);

    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable && onProgress) {
        onProgress(Math.round((e.loaded / e.total) * 100));
      }
    });

    xhr.addEventListener('load', () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText));
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

    xhr.addEventListener('error', () => reject(new Error('Network error — check your connection and try again.')));
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

export async function analyseDataset(datasetId) {
  return request(`/api/v1/datasets/${datasetId}/analyse`, { method: 'POST' });
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
 * Build a download URL for a sanitized dataset, with the required download token.
 * @param {number} datasetId
 * @param {string} token - The download_token returned from the remediation API response
 */
export function getSanitizedDownloadUrl(datasetId, token) {
  const url = `${BASE}/api/v1/datasets/${datasetId}/download-sanitized`;
  return token ? `${url}?token=${encodeURIComponent(token)}` : url;
}

export async function getHistory(page = 1, pageSize = 20) {
  return request(`/api/v1/history?page=${page}&page_size=${pageSize}`);
}

export async function healthCheck() {
  return request('/health');
}
