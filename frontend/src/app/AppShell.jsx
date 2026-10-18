import { useEffect, useMemo, useRef, useState } from 'react';
import { statusToPlate } from '../status/statusToPlate';
import Icon from '../ui/Icon';
import ThemeToggle from '../ui/ThemeToggle';

const NAV = [
  { href: '#/app', label: 'Overview', icon: 'LayoutGrid', match: (r) => r === '/app' },
  { href: '#/app/scan', label: 'Scan a dataset', icon: 'Upload', match: (r) => r === '/app/scan' },
  { href: '#/app/datasets', label: 'Datasets', icon: 'Table2', match: (r) => r.startsWith('/app/datasets') },
  { href: '#/app/history', label: 'History', icon: 'History', match: (r) => r.startsWith('/app/history') },
  { href: '#/app/settings', label: 'Settings', icon: 'SlidersHorizontal', match: (r) => r === '/app/settings' },
];

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

/** Ctrl/Cmd+K dataset search: a modal list filtered by name, Enter opens, Escape closes. */
function SearchDialog({ open, onClose, datasets, state }) {
  const [q, setQ] = useState('');
  const [index, setIndex] = useState(0);
  const input = useRef(null);
  const dialog = useRef(null);
  const results = useMemo(
    () => datasets.filter((d) => d.original_filename.toLowerCase().includes(q.trim().toLowerCase())).slice(0, 8),
    [datasets, q],
  );

  useEffect(() => {
    const el = dialog.current;
    if (!el) return;
    if (open && !el.open) { el.showModal(); setQ(''); setIndex(0); setTimeout(() => input.current?.focus(), 0); }
    if (!open && el.open) el.close();
  }, [open]);

  const openDataset = (d) => { onClose(); window.location.hash = `/app/datasets/${d.dataset_id}`; };

  return (
    <dialog ref={dialog} className="search" aria-label="Search datasets" onClose={onClose} onCancel={onClose}>
      <div className="search__field">
        <Icon name="Search" size={18} />
        <input
          ref={input}
          type="search"
          value={q}
          placeholder="Search datasets by name"
          aria-label="Search datasets by name"
          aria-controls="search-results"
          aria-activedescendant={results[index] ? `search-${results[index].dataset_id}` : undefined}
          onChange={(e) => { setQ(e.target.value); setIndex(0); }}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); setIndex((i) => Math.min(i + 1, results.length - 1)); }
            if (e.key === 'ArrowUp') { e.preventDefault(); setIndex((i) => Math.max(i - 1, 0)); }
            if (e.key === 'Enter' && results[index]) openDataset(results[index]);
            // A search input swallows the first Escape to clear itself; close the dialog instead.
            if (e.key === 'Escape') { e.preventDefault(); onClose(); }
          }}
        />
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Close search"><Icon name="X" size={18} /></button>
      </div>
      <ul id="search-results" className="search__results" role="listbox" aria-label="Matching datasets">
        {results.length === 0 && (
          <li className="muted search__empty">
            {state === 'error' ? 'Datasets could not be loaded, so search has nothing to look through. Reload the page to retry.'
              : state === 'loading' ? 'Loading datasets.'
              : datasets.length ? 'No dataset matches that name.' : 'No datasets uploaded from this browser yet.'}
          </li>
        )}
        {results.map((d, i) => (
          <li
            key={d.dataset_id}
            id={`search-${d.dataset_id}`}
            role="option"
            aria-selected={i === index}
            className={i === index ? 'is-active' : undefined}
            onMouseEnter={() => setIndex(i)}
            onClick={() => openDataset(d)}
          >
            <span className="break">{d.original_filename}</span>
            <span className="muted">{statusToPlate(d.shown).label}</span>
          </li>
        ))}
      </ul>
    </dialog>
  );
}

export default function AppShell({ route, crumbs, datasets, datasetsState, theme, onThemeChange, children }) {
  const [collapsed, setCollapsed] = useState(() => {
    try { return window.localStorage.getItem('aegis.sidebar') === 'collapsed'; } catch { return false; }
  });
  const [navOpen, setNavOpen] = useState(false); // phones: off-canvas sidebar
  const [searchOpen, setSearchOpen] = useState(false);

  useEffect(() => {
    try { window.localStorage.setItem('aegis.sidebar', collapsed ? 'collapsed' : 'open'); } catch { /* storage unavailable */ }
  }, [collapsed]);

  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setSearchOpen(true); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => { setNavOpen(false); }, [route]);

  return (
    <div className={`shell${collapsed ? ' is-collapsed' : ''}${navOpen ? ' is-nav-open' : ''}`}>
      <a className="skip-link" href="#app-main">Skip to content</a>
      <aside className="shell__side" aria-label="App navigation">
        <a className="brand shell__brand" href="#/">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name shell__label">Aegis Node</span>
        </a>
        <nav>
          <ul className="shell__nav">
            {NAV.map((n) => (
              <li key={n.href}>
                <a href={n.href} aria-current={n.match(route) ? 'page' : undefined} title={collapsed ? n.label : undefined}>
                  <Icon name={n.icon} size={18} />
                  <span className="shell__label">{n.label}</span>
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <button
          type="button"
          className="shell__collapse"
          onClick={() => setCollapsed((c) => !c)}
          aria-expanded={!collapsed}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          <Icon name={collapsed ? 'PanelLeftOpen' : 'PanelLeftClose'} size={18} />
          <span className="shell__label">Collapse</span>
        </button>
      </aside>
      {navOpen && <button type="button" className="shell__scrim" aria-label="Close navigation" onClick={() => setNavOpen(false)} />}

      <div className="shell__body">
        <header className="topbar">
          <button type="button" className="icon-btn topbar__menu" aria-label="Open navigation" aria-expanded={navOpen} onClick={() => setNavOpen(true)}>
            <Icon name="Menu" size={18} />
          </button>
          <nav aria-label="Breadcrumb" className="crumbs">
            <ol>
              {crumbs.map((c, i) => (
                <li key={c.label}>
                  {i < crumbs.length - 1 && c.href ? <a href={c.href}>{c.label}</a> : <span aria-current="page" className="break">{c.label}</span>}
                </li>
              ))}
            </ol>
          </nav>
          <button type="button" className="topbar__search" onClick={() => setSearchOpen(true)}>
            <Icon name="Search" size={16} />
            <span>Search datasets</span>
            <kbd>{isMac ? '⌘' : 'Ctrl'} K</kbd>
          </button>
          <ThemeToggle theme={theme} onChange={onThemeChange} />
        </header>
        <main id="app-main" className="shell__main" tabIndex={-1}>
          {/* Every page gets an h1; the dataset page shows its own visible one */}
          {!route.startsWith('/app/datasets/') && <h1 className="visually-hidden">{crumbs[crumbs.length - 1].label}</h1>}
          {children}
        </main>
      </div>
      <SearchDialog open={searchOpen} onClose={() => setSearchOpen(false)} datasets={datasets} state={datasetsState} />
    </div>
  );
}
