import { Suspense, lazy, useEffect, useState } from 'react';
import { statusToPlate } from '../status/statusToPlate';
import ShieldGrid from './ShieldGrid';

// The WebGL shield (three + R3F) is a separate lazy chunk: it never blocks first paint.
const Shield3D = lazy(() => import('./Shield3D'));

function useMedia(query) {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const mq = window.matchMedia(query);
    const onChange = () => setMatches(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [query]);
  return matches;
}

function hasWebGL() {
  try {
    const c = document.createElement('canvas');
    return Boolean(c.getContext('webgl2') || c.getContext('webgl'));
  } catch {
    return false;
  }
}

/**
 * The shield: WebGL plates on capable desktop screens, a 2D plate grid on phones,
 * without WebGL, and while the 3D chunk loads. Always paired with a text list of
 * datasets and statuses for screen readers and keyboard users.
 */
export default function Shield({ datasets, mode = 'compact', theme, onSelect, selectedId, label = 'Datasets on the shield' }) {
  const isPhone = useMedia('(max-width: 767px)');
  const reducedMotion = useMedia('(prefers-reduced-motion: reduce)');
  const [webgl] = useState(hasWebGL);
  const [focusedId, setFocusedId] = useState(null);
  const use3D = webgl && !isPhone;
  const fallback = <ShieldGrid datasets={datasets} interactive={false} theme={theme} />;

  return (
    <figure className={`shield shield--${mode}`}>
      <div className="shield__stage">
        {use3D ? (
          <Suspense fallback={fallback}>
            <Shield3D
              datasets={datasets}
              mode={mode}
              theme={theme}
              reducedMotion={reducedMotion}
              onSelect={onSelect}
              focusedId={focusedId ?? selectedId}
            />
          </Suspense>
        ) : (
          <ShieldGrid datasets={datasets} interactive={Boolean(onSelect)} onSelect={onSelect} selectedId={selectedId} theme={theme} />
        )}
      </div>
      <figcaption className={use3D ? 'visually-hidden' : 'shield__caption'}>
        <span className={use3D ? undefined : 'visually-hidden'}>{label}</span>
        {datasets.length > 0 && (
          <ul className={use3D && onSelect ? 'shield__keylist' : 'visually-hidden'}>
            {datasets.map((d) => (
              <li key={d.dataset_id}>
                {onSelect ? (
                  <button
                    type="button"
                    onFocus={() => setFocusedId(d.dataset_id)}
                    onBlur={() => setFocusedId(null)}
                    onClick={() => onSelect(d)}
                  >
                    {d.original_filename}: {statusToPlate(d.shown).label}
                  </button>
                ) : (
                  `${d.original_filename}: ${statusToPlate(d.shown).label}`
                )}
              </li>
            ))}
          </ul>
        )}
      </figcaption>
    </figure>
  );
}
