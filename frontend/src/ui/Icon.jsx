import {
  Circle, CircleAlert, CircleDashed, CircleHelp, FileText, LoaderCircle, Moon, ShieldAlert,
  ShieldCheck, ShieldHalf, ShieldMinus, ShieldQuestion, ShieldX, Sun, Upload, X,
} from 'lucide-react';

// Only icons the UI actually uses are imported, so the bundle stays small.
const ICONS = {
  Circle, CircleAlert, CircleDashed, CircleHelp, FileText, LoaderCircle, Moon, ShieldAlert,
  ShieldCheck, ShieldHalf, ShieldMinus, ShieldQuestion, ShieldX, Sun, Upload, X,
};

/** Decorative by default: the text next to an icon always carries the meaning. */
export default function Icon({ name, size = 16, label, ...rest }) {
  const Component = ICONS[name] ?? CircleHelp;
  return (
    <Component
      size={size}
      strokeWidth={1.75}
      aria-hidden={label ? undefined : true}
      aria-label={label}
      role={label ? 'img' : undefined}
      focusable="false"
      {...rest}
    />
  );
}
