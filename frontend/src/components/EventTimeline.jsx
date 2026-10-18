import { formatTime } from '../data/useDatasets';
import { describeEvent } from '../status/history';

/** A ScanEvent list, oldest first. Only steps that ran are recorded; failures keep their colour. */
export default function EventTimeline({ events, linkScans = false }) {
  if (!events?.length) return <p className="empty">No events were recorded.</p>;
  return (
    <ol className="timeline">
      {events.map((e, i) => {
        const { title, text, tone } = describeEvent(e);
        return (
          // Events have no id; the position in an append-only list is stable.
          <li key={`${e.event_type}-${e.created_at}-${i}`} className={`timeline__item timeline__item--${tone}`}>
            <span className="timeline__dot" aria-hidden="true" />
            <span>
              <strong className="timeline__title">{title}</strong>
              {tone === 'breach' && <span className="visually-hidden"> (failed)</span>}
              {text && <span className="timeline__text"> {text}</span>}
              {linkScans && e.scan_id && e.event_type === 'SCAN_COMPLETED' && (
                <> <a href={`#/app/history/${e.scan_id}`}>View scan</a></>
              )}
            </span>
            <time className="mono muted" dateTime={e.created_at}>{formatTime(e.created_at, '')}</time>
          </li>
        );
      })}
    </ol>
  );
}
