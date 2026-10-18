/**
 * Hexagonal plate layout shared by the 3D shield and the 2D plate grid.
 * Plates are placed on a hex spiral (centre, then ring 1 with 6, ring 2 with 12...),
 * so the shield grows with the dataset count. A minimum of one full ring (7 plates)
 * is drawn; plates beyond the real count are inert filler.
 */

// Axial neighbour directions; walking them in this order from (-ring, ring) traces one ring.
const RING_DIRS = [
  [1, 0], [1, -1], [0, -1], [-1, 0], [-1, 1], [0, 1],
];

/** Axial hex coordinates (q, r) in spiral order. */
export function hexSpiral(count) {
  const coords = [[0, 0]];
  for (let ring = 1; coords.length < count; ring += 1) {
    let q = -ring;
    let r = ring; // start at direction 4 * ring
    for (let side = 0; side < 6 && coords.length < count; side += 1) {
      for (let step = 0; step < ring && coords.length < count; step += 1) {
        coords.push([q, r]);
        q += RING_DIRS[side][0];
        r += RING_DIRS[side][1];
      }
    }
  }
  return coords;
}

/** Number of slots: real plates rounded up to a complete ring, never fewer than 7. */
export function slotCount(realCount) {
  let total = 1;
  for (let ring = 1; total < Math.max(realCount, 7); ring += 1) total += 6 * ring;
  return total;
}

/** Flat-top hex centres in plane units (radius 1 = centre to corner). */
export function hexToPlane(q, r, size = 1) {
  return [size * 1.5 * q, size * Math.sqrt(3) * (r + q / 2)];
}

/**
 * Build the plate list: real datasets first (most urgent at the centre), then filler.
 * Each plate: { key, dataset|null, x, y, ring }.
 */
export function buildPlates(datasets, gap = 1.08) {
  const total = slotCount(datasets.length);
  return hexSpiral(total).map(([q, r], i) => {
    const [x, y] = hexToPlane(q, r, gap);
    const ring = Math.max(Math.abs(q), Math.abs(r), Math.abs(-q - r));
    const dataset = datasets[i] ?? null;
    return { key: dataset ? dataset.dataset_id : `filler-${i}`, dataset, x, y, ring };
  });
}
