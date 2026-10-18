import Button from '../ui/Button';
import Card from '../ui/Card';
import Icon from '../ui/Icon';
import Skeleton from '../ui/Skeleton';

/** Read-only view of what this server is configured to run (GET /health). */
export default function SettingsPage({ health, reloadHealth }) {
  if (!health) {
    return <Card title="System status" id="settings"><Skeleton height="160px" /></Card>;
  }
  if (health.status !== 'ok') {
    return (
      <div className="error-banner" role="alert">
        <Icon name="CircleAlert" />
        <span>The API did not answer, so the server configuration is unknown.</span>
        <Button variant="ghost" onClick={reloadHealth}>Retry</Button>
      </div>
    );
  }
  return (
    <div className="settings">
      <Card title="Detection" id="settings-detection">
        <dl className="kv">
          <dt>Antivirus</dt>
          <dd>
            {health.av_mock_mode ? 'Simulated (mock mode): antivirus results are not real' : `${health.av_provider}${health.av_available ? '' : ' (unavailable)'}`}
          </dd>
          <dt>Antivirus version</dt><dd>{health.av_version}</dd>
          <dt>Accepted formats</dt><dd>{(health.supported_formats || []).join(', ')}</dd>
          <dt>Upload limit</dt><dd>{health.max_file_size_mb} MB</dd>
        </dl>
      </Card>
      <Card title="AI analysis" id="settings-ai">
        <dl className="kv">
          <dt>Primary provider</dt><dd>{health.ai_provider}{health.ai_configured ? '' : ' (not configured)'}</dd>
          <dt>Fallback chain</dt><dd>{(health.ai_fallback_chain || []).join(', ') || 'none'}</dd>
        </dl>
      </Card>
      <Card title="Bot protection" id="settings-bot">
        <dl className="kv">
          <dt>Cloudflare Turnstile</dt><dd>{health.turnstile_enabled ? 'on for uploads' : 'off'}</dd>
          <dt>Server version</dt><dd>{health.version}</dd>
        </dl>
      </Card>
      <p className="muted">These values come from the server's environment. Change them in its .env file or hosting dashboard and restart the server.</p>
    </div>
  );
}
