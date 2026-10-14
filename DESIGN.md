# DESIGN.md: Aegis Node

Design direction "The Bastion", from Sandeep's redesign spec (section 3). Read it as data
(palette, type, dials, motif). Fields marked *inferred* were filled from the codebase and
need Sandeep's confirmation; `[DECISION NEEDED]` items are open.

## Identity
Product: Aegis Node scans uploaded datasets (CSV, JSON, JSONL, Parquet, XLSX, TXT) for
malware, formula/script/SQL injection and prompt-injection payloads, explains the findings
with a guarded LLM, and returns a sanitized copy that has been re-scanned before download.
Audience (*inferred*): security engineers and data/ML engineers who vet datasets before use,
plus researchers and examiners evaluating the M.Tech prototype.
Personality: calm, exact, protective. Speaks in facts, never hype.
Concept: the Bastion. The UI is a shield of hexagonal plates. Each plate = one real node.
`[DECISION NEEDED]` Aegis Node has no network nodes or heartbeats. Proposed mapping: one
plate per scanned dataset, state taken from the real scan/remediation status
(clean → healthy, scanning → scanning, suspicious → degraded, quarantined → breached,
remediated → restored).

## Dial
ENERGY 2 / RHYTHM 3 / MOTION 2
Reason: an operator tool must stay calm (ENERGY 2), but the landing page tells a
story in distinct chapters (RHYTHM 3), and motion only ever reports state (MOTION 2).

## Palette (2 core + 1 accent + 1 status)
Dark (default; reason: operators watch it for hours in low light)
  --graphite   #16181B  background
  --slate      #24272C  raised surfaces
  --bone       #ECE6DA  primary text
  --ash        #A7A39A  secondary text (verify 4.5:1 on graphite)
  --bronze     #C08A3E  the single accent: primary action, active plate edge
  --breach     #D9472B  status only: compromised plate. Large text/icons only;
               small text uses #F06A4F
Light (toggle must fully work, R-34)
  --graphite -> #F3EFE7, --slate -> #E6E0D4, --bone -> #1B1D21,
  --ash -> #55524C, --bronze -> #8A5E22, --breach -> #B23A22
No gradients except one: the bronze plate material (brushed metal), reason: it is
the shield, the brand object itself.

## Typography
Display: Instrument Serif (headlines only). Reason: classical origin of the Aegis myth.
UI/body: IBM Plex Sans. Reason: engineered, very legible in dense tables.
Data: IBM Plex Mono, only for real dataset ids, hashes, timestamps. Never as decoration.
No uppercase wide-tracked section labels.

## Shape and identity motif
Chamfered corners (cut 45 degrees, 6px) instead of rounded corners, via clip-path.
The hexagon plate appears in exactly three places: the 3D shield, status chips,
and the press face of primary buttons. Nowhere else.
Radius scale: 0 (chamfer) for actions and plates, 4px for inputs, 8px for dialogs.

## Depth
One light source, top-left, everywhere (3D scene, button edges, card shadows),
so the 2D UI and the 3D scene feel lit by the same lamp.
Shadows only mark elevation: 3 levels (resting, raised, pressed).
Glow only on a breached plate. Glass/blur: none.

## Motion
Plates breathe slowly only when the item is healthy and fresh data arrives.
A breached plate cracks and tilts out of the shield (the one dramatic moment).
Buttons press down 4px with a 90ms ease-out, return in 140ms.
Respect prefers-reduced-motion: freeze the scene, keep state colours.

## Voice
CTAs name the action. Spec examples: "Inspect node", "Quarantine node",
"Connect your first node", "Read the threat model". Never "Get started" or "Learn more".
Adapted to this product (*inferred*): "Upload a dataset", "Scan dataset",
"Inspect findings", "Remediate dataset", "Download sanitized copy", "Read the threat model".
Numbers only from the live API or marked [REAL DATA].

## Assets still needed
Logo: [LOGO] text wordmark in Instrument Serif until a real mark exists.
Screenshots: real dashboard captures only.

## Current frontend (input to the P0 audit)
React 18 + Vite 6, plain JavaScript (no TypeScript), hand-written CSS in
`frontend/src/index.css`, Inter + JetBrains Mono from Google Fonts, no UI or 3D library.
Backend API (REST only, no websocket): `POST /api/v1/datasets/upload`, `POST /{id}/scan`,
`GET /{id}/report`, `POST /{id}/analyse`, `GET /{id}/analysis`, `POST /{id}/remediate`,
`GET /{id}/remediation`, `GET /{id}/download-sanitized`, `GET /api/v1/history?ids=`,
`GET /health`.
