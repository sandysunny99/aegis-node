import { statusToPlate } from '../status/statusToPlate';

/** Token that colours each plate state; read from the live stylesheet so themes apply. */
const TONE_VAR = {
  clean: '--status-clean',
  risk: '--status-risk',
  breach: '--status-breach',
  scanning: '--accent',
  neutral: '--status-neutral',
};

export function readTokens() {
  const css = getComputedStyle(document.documentElement);
  const get = (name) => css.getPropertyValue(name).trim();
  return {
    tone: Object.fromEntries(Object.entries(TONE_VAR).map(([k, v]) => [k, get(v)])),
    filler: get('--surface-overlay'),
    unscanned: get('--status-neutral'),
    accent: get('--accent'),
    breach: get('--status-breach-fill'),
  };
}

/** Visual description of one plate, from the shared status map. */
export function plateLook(plate, tokens) {
  if (!plate.dataset) return { kind: 'filler', color: tokens.filler };
  const s = statusToPlate(plate.dataset.shown);
  if (s.plate === 'unscanned') return { kind: 'unscanned', color: tokens.unscanned, label: s.label };
  return { kind: s.plate, color: tokens.tone[s.tone], label: s.label };
}
