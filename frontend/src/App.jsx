import { useCallback, useEffect, useState } from 'react';
import { healthCheck } from './api';
import AppShell from './app/AppShell';
import DatasetDetail from './app/DatasetDetail';
import DatasetsPage from './app/DatasetsPage';
import HistoryPage from './app/HistoryPage';
import Overview from './app/Overview';
import ScanDetailPage from './app/ScanDetailPage';
import ScanPage from './app/ScanPage';
import SettingsPage from './app/SettingsPage';
import { useDatasets } from './data/useDatasets';
import Landing from './pages/Landing';
import Styleguide from './pages/Styleguide';
import { useRoute } from './router';
import { useTheme } from './ui/ThemeToggle';

const APP_HOME = { label: 'Aegis Node', href: '#/app' };

/** Routes under #/app share the shell, the dataset list and /health. */
function AppRoutes({ route, theme, onThemeChange }) {
  const datasets = useDatasets();
  const [health, setHealth] = useState(null);
  const reloadHealth = useCallback(() => {
    setHealth(null);
    healthCheck().then(setHealth).catch(() => setHealth({ status: 'error' }));
  }, []);
  useEffect(reloadHealth, [reloadHealth]);

  const detailMatch = route.match(/^\/app\/datasets\/([0-9a-f]{32})$/);
  const scanMatch = route.match(/^\/app\/history\/([0-9a-f]{32})$/);
  let crumbs;
  let page;

  if (detailMatch) {
    const id = detailMatch[1];
    const known = datasets.items.find((d) => d.dataset_id === id);
    crumbs = [APP_HOME, { label: 'Datasets', href: '#/app/datasets' }, { label: known?.original_filename ?? id.slice(0, 12) }];
    page = <DatasetDetail key={id} id={id} onChanged={datasets.reload} />;
  } else if (scanMatch) {
    crumbs = [APP_HOME, { label: 'History', href: '#/app/history' }, { label: scanMatch[1].slice(0, 12) }];
    page = <ScanDetailPage key={scanMatch[1]} id={scanMatch[1]} datasets={datasets.items} />;
  } else if (route === '/app/history') {
    crumbs = [APP_HOME, { label: 'History' }];
    page = <HistoryPage datasets={datasets.items} />;
  } else if (route === '/app/datasets') {
    crumbs = [APP_HOME, { label: 'Datasets' }];
    page = <DatasetsPage datasets={datasets.items} state={datasets.state} error={datasets.error} reload={datasets.reload} />;
  } else if (route === '/app/scan') {
    crumbs = [APP_HOME, { label: 'Scan a dataset' }];
    page = <ScanPage health={health} onScanned={datasets.reload} />;
  } else if (route === '/app/settings') {
    crumbs = [APP_HOME, { label: 'Settings' }];
    page = <SettingsPage health={health} reloadHealth={reloadHealth} />;
  } else {
    crumbs = [APP_HOME, { label: 'Overview' }];
    page = <Overview datasets={datasets.items} state={datasets.state} error={datasets.error} reload={datasets.reload} theme={theme} />;
  }

  return (
    <AppShell route={route} crumbs={crumbs} datasets={datasets.items} datasetsState={datasets.state} theme={theme} onThemeChange={onThemeChange}>
      {page}
    </AppShell>
  );
}

export default function App() {
  const route = useRoute();
  const [theme, setTheme] = useTheme();

  useEffect(() => { window.scrollTo(0, 0); }, [route]);

  if (route === '/styleguide') return <Styleguide theme={theme} onThemeChange={setTheme} />;
  if (route.startsWith('/app')) return <AppRoutes route={route} theme={theme} onThemeChange={setTheme} />;
  return <Landing theme={theme} onThemeChange={setTheme} />;
}
