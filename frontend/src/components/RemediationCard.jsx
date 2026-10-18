import { useCallback, useState } from 'react';
import { downloadSanitized, remediateDataset } from '../api';
import { describeLimitation } from '../status/limitations';
import { VERDICT_TO_STATUS } from '../status/statusToPlate';
import Button from '../ui/Button';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import StatusPill from '../ui/StatusPill';

const OUTCOME = {
  completed: { status: 'remediated', text: 'Remediation completed and the sanitized copy passed the verification re-scan.' },
  partial: { status: 'partial_remediated', text: 'Remediation was partial: some actionable findings remain in the sanitized copy.' },
  unverified: { status: 'remediated_unverified', text: 'The sanitized copy could not be fully verified by the re-scan. Treat it as unverified.' },
};

export default function RemediationCard({ datasetId, scanResult }) {
  const [state, setState] = useState('idle'); // idle | loading | done | error
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [downloading, setDownloading] = useState(false);
  const [downloaded, setDownloaded] = useState(false);

  const hasFindings = scanResult?.threats_found_count > 0;

  const handleRemediate = useCallback(async () => {
    setState('loading'); setError('');
    try {
      setReport(await remediateDataset(datasetId));
      setState('done');
    } catch (e) {
      setError(e.message); setState('error');
    }
  }, [datasetId]);

  const handleDownload = async () => {
    setDownloading(true); setError('');
    try {
      await downloadSanitized(datasetId, report.download_token);
      setDownloaded(true);
    } catch (err) {
      setError(err.message);
    }
    setDownloading(false);
  };

  if (!hasFindings) {
    return (
      <Card title="Remediation" id="remediation">
        <p className="muted">The scanner reported no findings, so there is nothing to remediate.</p>
      </Card>
    );
  }

  const outcome = report ? OUTCOME[report.remediation_status] : null;

  return (
    <Card
      title="Remediation and verification"
      id="remediation"
      actions={state !== 'done' && (
        <Button variant="primary" onClick={handleRemediate} loading={state === 'loading'} id="remediate-btn">
          Remediate dataset
        </Button>
      )}
    >
      <p className="card-sub card-lede">
        Neutralises findings in a copy of the dataset, keeps its schema, then re-scans the copy before you can download it.
      </p>

      {error && (
        <div className="error-banner error-banner--spaced" role="alert">
          <Icon name="CircleAlert" />
          <span>{error}</span>
        </div>
      )}

      {state === 'done' && report && (
        <div className="stack">
          <div className="notice" role="status">
            {outcome && <StatusPill status={outcome.status} />}
            <span>{outcome ? outcome.text : `Remediation status: ${report.remediation_status}`}</span>
          </div>

          <dl className="summary">
            <div><dt>Findings resolved</dt><dd>{report.resolved_findings_count} of {report.original_findings_count}</dd></div>
            <div><dt>Remaining</dt><dd>{report.remaining_findings_count}</dd></div>
            <div><dt>Cells changed</dt><dd>{report.changes_count}</dd></div>
            <div>
              <dt>{report.integrity_method === 'exact_rows' ? 'Fields unchanged' : 'Fields unchanged (estimated)'}</dt>
              <dd>{report.integrity_preserved}%</dd>
            </div>
            <div>
              <dt>Re-scan verdict</dt>
              <dd>
                {report.rescan_verdict
                  ? <StatusPill status={VERDICT_TO_STATUS[report.rescan_verdict] ?? 'incomplete'} size="sm" />
                  : 'not reported'}
              </dd>
            </div>
          </dl>

          {report.rescan_limitations?.length > 0 && (
            <div className="notice notice--risk" role="note">
              <Icon name="ShieldMinus" className="notice__icon" />
              <ul className="notice__list">
                {report.rescan_limitations.map((c) => <li key={c}>{describeLimitation(c)}</li>)}
              </ul>
            </div>
          )}

          {report.actions?.length > 0 && <ActionsList actions={report.actions} />}

          {report.download_token && !downloaded && (
            <div className="btn-row">
              <Button variant="secondary" onClick={handleDownload} loading={downloading} id="download-sanitized-btn">
                Download sanitized copy
              </Button>
              <span className="muted">
                One-time download. SHA-256 <span className="mono">{report.sanitized_sha256?.slice(0, 12)}</span>
              </span>
            </div>
          )}
          {downloaded && <p className="muted">Downloaded. The link was single-use; remediate again for a new copy.</p>}
        </div>
      )}
    </Card>
  );
}

function ActionsList({ actions }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button type="button" className="link-btn" aria-expanded={open} onClick={() => setOpen((x) => !x)}>
        {open ? 'Hide' : 'Show'} {actions.length} remediation action{actions.length !== 1 ? 's' : ''}
      </button>
      {open && (
        <ul className="findings">
          {actions.map((a, i) => (
            <li key={`${a.rule_id}-${a.location}-${i}`} className="finding">
              <div className="finding__top">
                <span className="finding__rule">{a.rule_id}</span>
                <span className="finding__loc">{a.location}</span>
              </div>
              <p>{a.action_taken}</p>
              {a.sample_after && <p className="finding__loc">After: {a.sample_after}</p>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
