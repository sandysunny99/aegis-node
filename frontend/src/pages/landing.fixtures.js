// Sample plates for the landing-page illustration only (brief §7: fixtures stay out of
// production components). The page labels this shield as an illustration, not live data.
const sample = (id, name, shown) => ({
  dataset_id: id.padEnd(32, '0'),
  original_filename: name,
  shown,
  scanned_at: null,
});

export const LANDING_PLATES = [
  sample('d1', 'customer_feedback.csv', 'clean'),
  sample('d2', 'support_tickets.jsonl', 'clean'),
  sample('d3', 'vendor_export.xlsx', 'quarantined'),
  sample('d4', 'web_scrape_2026.parquet', 'suspicious'),
  sample('d5', 'invoices_q3.csv', 'remediated'),
  sample('d6', 'chat_logs.jsonl', 'scanning'),
  sample('d7', 'product_catalog.csv', 'clean'),
  sample('d8', 'survey_raw.txt', 'clean_limited'),
  sample('d9', 'partner_feed.json', 'clean'),
  sample('da', 'labels_v2.csv', 'uploaded'),
  sample('db', 'reviews.csv', 'clean'),
  sample('dc', 'scraped_forum.jsonl', 'partial_remediated'),
];
