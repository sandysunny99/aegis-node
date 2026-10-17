import { useEffect, useState } from 'react';

/** Current hash route without the leading "#", e.g. "/styleguide". Empty hash is "/". */
function currentRoute() {
  const raw = window.location.hash.replace(/^#/, '');
  return raw.startsWith('/') ? raw : '/';
}

/**
 * Minimal hash router (no router dependency): returns the current path and re-renders
 * on navigation. Hash routes work on the FastAPI static mount without server rewrites.
 */
export function useRoute() {
  const [route, setRoute] = useState(currentRoute);
  useEffect(() => {
    const onChange = () => setRoute(currentRoute());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return route;
}
