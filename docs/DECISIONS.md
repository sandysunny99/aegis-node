# Architectural Decisions
- **ADR-001**: Use FastAPI and SQLite for a lightweight, deployable runtime.
- **ADR-002**: Local Detection First. ClamAV and YARA provide ground truth; LLM provides context, not primary detection.
- **ADR-003**: No AGPL dependencies in runtime. OpenViking ideas used for context only.
- **ADR-004**: Render Free Tier compatibility requires ephemeral SQLite (/tmp) instead of persistent disks.

## Bastion frontend redesign (branch feat/bastion-frontend)
- **2026-10-15, merge**: merged local tag `core-baseline-v2` (571e5d4: fix/audit-2026-10 + c895a6b + 7 core fixes) into feat/bastion-frontend before any P1 work, so the UI is built against the final status and threat-intel shapes. Result: 458 tests pass, ruff clean, frontend lint and build pass. Not pushed.
- **2026-10-15, status defaults**: `clean_limited` → degraded "Clean, limited scan"; `incomplete` → degraded "Scan incomplete"; `remediated_unverified` → degraded "Remediation unverified". Why: a scan or clean-up that could not be fully verified must never look healthy. Defaults pending Sandeep's confirmation; the full map is in DESIGN.md.
- **2026-10-15, re-merge**: `core-baseline-v2` moved to 9f473b0 (Dockerfile creates `/app/db` so the compose SQLite volume is writable); merged again as 920549f. 458 tests pass, ruff clean, `docker compose config` valid. Not pushed.

### 17 Oct brief (one line per choice, R-31)
- **P0 picks**: defaulted to all HIGH findings (#1 to #12, #30 to #34) because Sandeep said "continue" without picking numbers; he can add or drop numbers.
- **Go for steps 3 and 4**: taken from Sandeep's "continue" on 17 Oct after the plan was posted.
- **Stack kept**: React 18 + Vite + plain JavaScript and CSS, as the brief says to keep the existing stack (no TypeScript, Tailwind or shadcn).
- **Design system**: the Raycast entry on styles.refero.design could not be fetched, so tokens follow the brief's §4 rules; bronze stays the one accent because DESIGN.md makes the bronze shield the identity.
- **Surfaces**: four warm near-black steps (#0b0c0e to #202327), never pure black, so raised panels separate without borders everywhere.
- **Type**: IBM Plex Sans for UI and headlines, IBM Plex Mono only for IDs, hashes, sizes and timestamps; one grotesk + one mono per §4 (Instrument Serif dropped).
- **Shape**: one 4px radius for surfaces and inputs; the 6px chamfer is the plate motif on buttons and status chips.
- **Status colour + icon + word**: every status shows a lucide icon and its word, so meaning never depends on colour.
- **Contrast**: body text 12.7:1 or better, muted text 5.7:1 or better in both themes (computed with the WCAG formula).
- **Plate materials**: `--plate-*` tokens stay the same in both themes, because the plates are lit metal in the 3D scene, not page colour.
- **Shield**: one instanced hex plate per dataset (R3F), most urgent at the centre, filler plates for a full ring and never fake datasets.
- **Shield fallbacks**: 2D SVG grid while the 3D chunk loads, on phones (<768px), without WebGL and if the chunk fails (error boundary), so there is never a blank box.
- **Motion**: idle sway, cursor parallax capped at 6 degrees and the sequential scan highlight run on the landing shield only; the app shield is still unless a dataset is scanning; reduced motion turns all of it off.
- **Halftone**: CSS dot pattern behind the hero only, masked and about 9% contrast; the brief asks for a low-contrast background there, and a CSS pattern costs no JavaScript.
- **Smooth scroll**: Lenis on the landing page only, never in the app, off for reduced motion.
- **Scroll chapter**: framer-motion `useScroll` drives the pinned "how a scan works" chapter; chosen over GSAP so there is one motion library.
- **Routing**: hash routes (`#/`, `#/app/...`, `#/styleguide`) with a 20-line hook, because they work on the FastAPI static mount without server rewrites and need no router package.
- **Sidebar**: Overview, Scan a dataset, Datasets, Settings; "Scans" and "Reports" left out because the API has no separate lists for them (R-24).
- **History scope**: the app lists datasets uploaded from this browser (ids kept in localStorage), matching the S1 rule that a public deployment cannot list everyone's datasets.
- **No source or row columns in the table**: the history API returns neither; row counts appear on the dataset page from its scan report.
- **Landing shield data**: sample plates from `landing.fixtures.js`, labelled on the page as an illustration.
- **Fonts and CSP**: IBM Plex loads from Google Fonts, so the CSP now allows fonts.googleapis.com (styles) and fonts.gstatic.com (font files).
- **index.html no-cache**: the backend sends `Cache-Control: no-cache` for index.html so a rebuild is visible on the next reload; hashed assets still cache.
- **Local serving**: `scripts/serve_local.ps1 [-Port 8001]` builds and serves with APP_ENV=development, because the real .env is production and refuses to start with test Turnstile keys.
- **History page (18 Oct)**: built against the scan history contract on `integrate/core-audit` (4d8072d) without merging it. `#/app/history` lists `GET /api/v1/scans` for this browser's dataset ids, with the API's filters and stable paging; `#/app/history/<scan_id>` shows one scan and its event timeline; the dataset page lists that dataset's scans and full timeline. When the routes are absent (a bare 404 "Not Found" from an older backend), each place says the server has no scan history and the dataset page falls back to its latest-scan summary. A failed request is an error with Retry, never an empty list. `persistence.durable: false` shows a warning that history is lost on restart.
