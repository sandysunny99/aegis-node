import { motion, useMotionValueEvent, useReducedMotion, useScroll, useTransform } from 'framer-motion';
import { useRef, useState } from 'react';
import { SCAN_STEPS } from '../landing.content';

/**
 * "How a scan works": the section pins while one plate travels down a rail through
 * each check (scroll-linked, framer-motion useScroll). With reduced motion it is a
 * plain ordered list.
 */
export default function ScanSteps() {
  const reduced = useReducedMotion();
  const ref = useRef(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start start', 'end end'] });
  const [active, setActive] = useState(0);
  const plateY = useTransform(scrollYProgress, [0, 1], ['0%', '100%']);

  useMotionValueEvent(scrollYProgress, 'change', (v) => {
    setActive(Math.min(SCAN_STEPS.length - 1, Math.floor(v * SCAN_STEPS.length)));
  });

  if (reduced) {
    return (
      <ol className="steps-static">
        {SCAN_STEPS.map((s, i) => (
          <li key={s.title}>
            <span className="steps__num mono">{String(i + 1).padStart(2, '0')}</span>
            <h3>{s.title}</h3>
            <p>{s.body}</p>
          </li>
        ))}
      </ol>
    );
  }

  return (
    <div ref={ref} className="steps" style={{ '--steps': SCAN_STEPS.length }}>
      <div className="steps__pin">
        <div className="steps__rail" aria-hidden="true">
          <span className="steps__track" />
          <motion.span className="steps__plate" style={{ top: plateY }} />
        </div>
        <ol className="steps__list">
          {SCAN_STEPS.map((s, i) => (
            <li key={s.title} className={i === active ? 'is-active' : i < active ? 'is-done' : undefined} aria-current={i === active ? 'step' : undefined}>
              <span className="steps__num mono">{String(i + 1).padStart(2, '0')}</span>
              <div>
                <h3>{s.title}</h3>
                <p>{s.body}</p>
              </div>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}
