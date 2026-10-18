import { useEffect, useState } from 'react';
import Icon from './Icon';

const STORAGE_KEY = 'aegis.theme';

function readStoredTheme() {
  try {
    const value = window.localStorage.getItem(STORAGE_KEY);
    return value === 'light' || value === 'dark' ? value : null;
  } catch {
    return null;
  }
}

/** Dark is the default (DESIGN.md: operators watch it for hours in low light). */
export function useTheme() {
  const [theme, setTheme] = useState(() => readStoredTheme() ?? 'dark');
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // storage unavailable (private mode): the toggle still works for this visit
    }
  }, [theme]);
  return [theme, setTheme];
}

export default function ThemeToggle({ theme, onChange }) {
  const next = theme === 'dark' ? 'light' : 'dark';
  return (
    <button
      type="button"
      className="icon-btn"
      onClick={() => onChange(next)}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
    >
      <Icon name={theme === 'dark' ? 'Sun' : 'Moon'} size={18} />
    </button>
  );
}
