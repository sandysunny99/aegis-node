import {
  ArrowDown, ArrowUp, ArrowUpDown, Circle, CircleAlert, CircleDashed, CircleHelp, FileText, History, LayoutGrid,
  LoaderCircle, Menu, Moon, PanelLeftClose, PanelLeftOpen, RefreshCw, Search, ShieldAlert, ShieldCheck,
  ShieldHalf, ShieldMinus, ShieldQuestion, ShieldX, SlidersHorizontal, Sun, Table2, Upload, X,
} from 'lucide-react';

// Only icons the UI actually uses are imported, so the bundle stays small.
const ICONS = {
  ArrowDown, ArrowUp, ArrowUpDown, Circle, CircleAlert, CircleDashed, CircleHelp, FileText, History, LayoutGrid,
  LoaderCircle, Menu, Moon, PanelLeftClose, PanelLeftOpen, RefreshCw, Search, ShieldAlert, ShieldCheck,
  ShieldHalf, ShieldMinus, ShieldQuestion, ShieldX, SlidersHorizontal, Sun, Table2, Upload, X,
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
