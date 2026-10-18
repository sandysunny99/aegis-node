/** Loading placeholder shaped like the real content (a row, a line, a block). */
export default function Skeleton({ width = '100%', height = '1em', className = '' }) {
  return <span className={`skeleton ${className}`.trim()} style={{ '--sk-w': width, '--sk-h': height }} aria-hidden="true" />;
}
