/** A chip for states outside the dataset status map (enrichment, AI, provider). Word always shown. */
export default function ToneChip({ tone = 'neutral', children }) {
  return (
    <span className={`status-pill status-pill--${tone} status-pill--sm`}>
      <span className="status-pill__label">{children}</span>
    </span>
  );
}
