import Icon from './Icon';

/**
 * PlateButton (docs/design/PLATE_BUTTON.md): a face on a darker edge layer; pressing drops
 * the face onto the edge. Variants: primary | secondary | danger | ghost.
 * Loading keeps the width and replaces the label with a spinner (the label stays for
 * screen readers).
 */
export default function Button({
  variant = 'secondary',
  loading = false,
  disabled = false,
  type = 'button',
  children,
  className = '',
  ...rest
}) {
  const isDisabled = disabled || loading;
  return (
    <button
      type={type}
      className={`plate-btn plate-btn--${variant} ${loading ? 'is-loading' : ''} ${className}`.trim()}
      disabled={isDisabled}
      aria-busy={loading || undefined}
      {...rest}
    >
      {variant !== 'ghost' && <span className="plate-btn__edge" aria-hidden="true" />}
      <span className="plate-btn__face">
        <span className="plate-btn__label">{children}</span>
        {loading && (
          <span className="plate-btn__spinner" aria-hidden="true">
            <Icon name="LoaderCircle" size={18} className="spin" />
          </span>
        )}
      </span>
    </button>
  );
}
