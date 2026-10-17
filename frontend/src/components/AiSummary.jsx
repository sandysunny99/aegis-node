import { useCallback, useEffect, useState } from 'react';
import { analyseDataset, getAnalysis, getLlmProviders } from '../api';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import Skeleton from '../ui/Skeleton';

/** "Resource not found" is how api.js reports a 404: here it means "no analysis yet". */
const isNotFound = (err) => /not found|404/i.test(err?.message ?? '');

export default function AiSummary({ datasetId }) {
  const [data, setData] = useState(null);
  const [state, setState] = useState('loading'); // loading | empty | ready | error
  const [error, setError] = useState('');
  const [providers, setProviders] = useState([]);
  const [llmMode, setLlmMode] = useState('auto');
  const [selectedProvider, setSelectedProvider] = useState('');
  const [analyzing, setAnalyzing] = useState(false);

  const load = useCallback(() => {
    setState('loading');
    getAnalysis(datasetId)
      .then((res) => { setData(res); setState('ready'); })
      .catch((err) => {
        if (isNotFound(err)) { setData(null); setState('empty'); }
        else { setError(err.message); setState('error'); }
      });
  }, [datasetId]);

  useEffect(() => {
    load();
    getLlmProviders()
      .then((res) => {
        const configured = (res.providers || []).filter((p) => p.configured);
        setProviders(configured);
        if (configured.length > 0) setSelectedProvider(configured[0].id);
      })
      .catch(() => setProviders([]));
  }, [load]);

  const handleAnalyze = async () => {
    setAnalyzing(true);
    setError('');
    try {
      const res = await analyseDataset(datasetId, {
        llmMode,
        provider: llmMode === 'manual' ? selectedProvider : null,
      });
      setData(res);
      setState('ready');
    } catch (err) {
      setError(err.message);
    }
    setAnalyzing(false);
  };

  return (
    <Card title="AI analysis" id="ai-analysis">
      <p className="card-sub card-lede">
        An LLM explains the scanner findings. Raw cell values are never sent to it, and it cannot change the verdict.
      </p>

      <div className="field-row">
        <fieldset className="field-row" style={{ border: 0, margin: 0, padding: 0 }}>
          <legend className="visually-hidden">Provider selection</legend>
          <label><input type="radio" name="llmMode" value="auto" checked={llmMode === 'auto'} onChange={() => setLlmMode('auto')} /> Automatic fallback chain</label>
          <label><input type="radio" name="llmMode" value="manual" checked={llmMode === 'manual'} onChange={() => setLlmMode('manual')} disabled={providers.length === 0} /> Choose a provider</label>
        </fieldset>
        {llmMode === 'manual' && (
          <label>
            <span className="visually-hidden">Provider</span>
            <select className="select" value={selectedProvider} onChange={(e) => setSelectedProvider(e.target.value)}>
              {providers.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </label>
        )}
        <Button variant="secondary" onClick={handleAnalyze} loading={analyzing}>
          {data ? 'Analyse again' : 'Analyse findings'}
        </Button>
      </div>

      {state === 'loading' && (
        <div className="stack-sm" aria-label="Loading AI analysis">
          <Skeleton width="60%" /><Skeleton width="90%" /><Skeleton width="75%" />
        </div>
      )}
      {state === 'empty' && <p className="empty">No AI analysis has been run for this dataset yet.</p>}
      {(state === 'error' || error) && (
        <div className="error-banner error-banner--spaced" role="alert">
          <Icon name="CircleAlert" />
          <span>{error || 'The analysis could not be loaded.'}</span>
          {state === 'error' && <Button variant="ghost" onClick={load}>Retry</Button>}
        </div>
      )}

      {state === 'ready' && data && (
        <div className="stack">
          <dl className="kv">
            <dt>Status</dt><dd>{data.status}</dd>
            <dt>Provider</dt><dd>{data.final_provider || data.initial_provider || 'none'}{data.model_name ? ` (${data.model_name})` : ''}</dd>
            <dt>Providers tried</dt><dd>{(data.provider_attempts || []).join(', ') || 'none'}</dd>
            <dt>Fallback used</dt><dd>{data.fallback_used ? `yes (${data.fallback_reason})` : 'no'}</dd>
            <dt>Prompt guardrail</dt><dd>{data.guardrail_status || 'not run'}{data.guardrail_status === 'BLOCK' ? ', LLM not called' : ''}</dd>
          </dl>
          <p className="prose">{data.summary || 'The provider returned no summary.'}</p>
        </div>
      )}
    </Card>
  );
}
