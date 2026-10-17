/**
 * Data table with a sticky header and tabular numerals. Columns:
 * [{ key, header, render?(row), numeric?, mono? }]. Below 768px each row
 * becomes a stacked card (labels come from data-label).
 */
export default function Table({ columns, rows, rowKey, caption, onRowClick, selectedKey }) {
  return (
    <div className="table-wrap">
      <table className="table">
        {caption && <caption className="visually-hidden">{caption}</caption>}
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col" className={c.numeric ? 'is-numeric' : undefined}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = rowKey(row);
            return (
              <tr
                key={key}
                className={key === selectedKey ? 'is-selected' : undefined}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
              >
                {columns.map((c) => (
                  <td
                    key={c.key}
                    data-label={c.header}
                    className={[c.numeric && 'is-numeric', c.mono && 'is-mono'].filter(Boolean).join(' ') || undefined}
                  >
                    {c.render ? c.render(row) : row[c.key]}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
