/** Surface container. `as` lets a card be a section or article for the document outline. */
export default function Card({ as: Tag = 'section', title, actions, children, className = '', ...rest }) {
  const headingId = rest.id ? `${rest.id}-title` : undefined;
  return (
    <Tag className={`card ${className}`.trim()} aria-labelledby={title ? headingId : undefined} {...rest}>
      {(title || actions) && (
        <header className="card__header">
          {title && <h2 className="card__title" id={headingId}>{title}</h2>}
          {actions && <div className="card__actions">{actions}</div>}
        </header>
      )}
      {children}
    </Tag>
  );
}
