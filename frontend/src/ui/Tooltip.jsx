import { useId, useState } from 'react';

/**
 * Tooltip shown on hover and on keyboard focus, dismissed with Escape.
 * The trigger must be focusable; the tip is linked with aria-describedby.
 */
export default function Tooltip({ content, children }) {
  const id = useId();
  const [open, setOpen] = useState(false);
  return (
    <span
      className="tooltip"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      onKeyDown={(e) => { if (e.key === 'Escape') setOpen(false); }}
    >
      <span aria-describedby={id}>{children}</span>
      <span role="tooltip" id={id} className={`tooltip__tip ${open ? 'is-open' : ''}`}>
        {content}
      </span>
    </span>
  );
}
