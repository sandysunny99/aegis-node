import { statusToPlate } from '../status/statusToPlate';

/** Plate material per status tone (tokens.css --plate-*), read live so themes apply. */
const TONE_VAR = {
  clean: '--plate-clean',
  risk: '--plate-risk',
  breach: '--plate-breach',
  scanning: '--plate-scan',
  neutral: '--plate-neutral',
};

export function readTokens() {
  const css = getComputedStyle(document.documentElement);
  const get = (name) => css.getPropertyValue(name).trim();
  return {
    tone: Object.fromEntries(Object.entries(TONE_VAR).map(([k, v]) => [k, get(v)])),
    filler: get('--plate-filler'),
    unscanned: get('--plate-neutral'),
    accent: get('--plate-scan'),
  };
}

/** Visual description of one plate, from the shared status map. */
export function plateLook(plate, tokens) {
  if (!plate.dataset) return { kind: 'filler', color: tokens.filler };
  const s = statusToPlate(plate.dataset.shown);
  if (s.plate === 'unscanned') return { kind: 'unscanned', color: tokens.unscanned, label: s.label };
  return { kind: s.plate, color: tokens.tone[s.tone], label: s.label };
}
