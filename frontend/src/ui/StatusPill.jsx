import { statusToPlate } from '../status/statusToPlate';
import Icon from './Icon';

/**
 * Status chip: a chamfered plate in the status tone with an icon and the status word.
 * Meaning never depends on colour alone.
 */
export default function StatusPill({ status, size = 'md' }) {
  const s = statusToPlate(status);
  return (
    <span className={`status-pill status-pill--${s.tone} status-pill--${size}`} data-status={status}>
      <Icon name={s.icon} size={size === 'sm' ? 14 : 16} className={status === 'scanning' ? 'spin' : undefined} />
      <span className="status-pill__label">{s.label}</span>
    </span>
  );
}
