/**
 * Backend rule descriptions use em dashes ("CSV formula injection — cell starts…").
 * The UI never shows them (anti-slop R-02), so they are rendered as a colon.
 */
export function plainDashes(text) {
  return String(text ?? '').replace(/\s*—\s*/g, ': ');
}
