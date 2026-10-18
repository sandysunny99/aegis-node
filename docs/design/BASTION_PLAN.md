# Bastion redesign plan (step 1 of the 17 Oct brief)

Branch `feat/bastion-frontend`. The brief says to stop for Sandeep's "go" after this plan. Step 2 (tokens, primitives, `/styleguide`) goes ahead now because he said to go ahead on 15 Oct. Steps 3 (landing page) and 4 (app) wait for his reply to this plan.

## Today's frontend (read from the repo)

- **Stack:** React 18 + Vite 6, plain JavaScript, hand-written CSS (`src/index.css` plus inline styles), no router, no component library. I'm keeping this stack, so there is no TypeScript, Tailwind or shadcn.
- **Routes:** a single page with two tabs and no URLs.
  - *Threat Scanner:* upload a file, then scan it (`POST /datasets/upload`, `POST /{id}/scan`). The result shows the verdict, risk, findings, threat intelligence, AI analysis (`/analyse`, `/analysis`, `/llm/providers`) and remediation with a one-time download (`/remediate`, `/download-sanitized`).
  - *Scan History:* `GET /history?ids=` for the datasets this browser uploaded. Each row has name, size, format, status, upload time, scan count, risk, findings count, verdict and last scan time.
  - *Header:* `GET /health` (AV provider/version, AI provider, Turnstile, size limit, formats).

## Filling the brief's [[ ]] slots from the code

- **Statuses (11, `backend/models.py`):** uploaded, scanning, clean, clean_limited, incomplete, suspicious, quarantined, remediated, partial_remediated, remediated_unverified, error. They are mapped to plates in `DESIGN.md`.
- **What a scan checks** (`scanner/`):
  - Antivirus: ClamAV or MetaDefender, hash only.
  - Raw bytes: EICAR, PE/ELF headers, NOP sleds.
  - Heuristics: entropy, non-printable bytes, process-injection and downloader strings, embedded PE, packers, MIME mismatch, base64 payloads, suspicious PE imports.
  - YARA: 4 rules.
  - 22 content rules over every cell: formula/DDE injection, script injection, SQL injection, shellcode, executable artifacts, C2 strings, macro threats, prompt injection, malware references.
  - Encoding normalisation.
  - Optional threat intel, off by default: VirusTotal hash, URLhaus URLs, AbuseIPDB IPs.
  - It does **not** check PII, licences or statistical training-data poisoning, so the site will not claim it does.

## Routes to build (hash routes, no router package)

| Route | Page |
|---|---|
| `#/` | Landing |
| `#/app` | Overview: compact shield, status summary row, recent scans |
| `#/app/scan` | Scan a dataset: the existing upload, scan, analyse and remediate flow, restyled |
| `#/app/datasets` | Datasets table |
| `#/app/datasets/<id>` | Dataset detail |
| `#/app/settings` | Read-only system status from `/health` (AV, AI provider, threat-intel providers, limits) |
| `#/styleguide` | Every token, status and component state |

The brief's sidebar also lists "Scans" and "Reports". The API has no scan list or report list separate from datasets, so those links would point nowhere (R-24). Scan history and the report live inside Dataset detail instead.

## Sections and components, with the reference each borrows from (layout only, never branding)

| Piece | Borrowed from |
|---|---|
| Tokens: surface steps, text roles, type scale, 4px spacing, one radius | Brief §4. I could not fetch the Raycast "midnight command center" entry from styles.refero.design (no public page at that URL), so the tokens follow the §4 rules: near-black steps, one bronze accent from DESIGN.md, semantic status colours |
| Landing navbar: slim, sticky, 4 links, one CTA | navbar.gallery "Static/Sticky" (Cloudflare, Browserbase) |
| Hero: copy left, shield right, restrained | supahero.io dev-tool heroes (Evervault, Better Stack, Zed) |
| Problem strip, 3 points with no stats | none (content only) |
| How a scan works: pinned scroll, one plate through 5 checks | scrolltide "Scroll Index" pattern, built with Framer Motion `useScroll` |
| What it detects: dense table of the real checks | scrolltide dashboard density (Widget Board), as a table rather than tiles |
| For examiners: SVG pipeline diagram, evaluation method, links | none |
| CTA band: "Scan a dataset" + "View source" | cta.gallery Tines / Native Security |
| Footer: small type, dense | footer.design "Small Type" |
| App shell: collapsible sidebar, top bar with Ctrl/⌘K dataset search, breadcrumbs | navbar.gallery "Sidebar" + "Search Bar" |
| Primitives: Button (PlateButton), StatusPill (hex chip + icon + word), Card, Table, Tooltip, Skeleton | brief §7 and the PlateButton spec |
| Shield: R3F instanced hex plates, static SVG before load, 2D plate grid on mobile | brief §2/§7; no reference |
| Icons: lucide-react, outline only | brief §3 |

## Packages (only the ones the brief and coordinator allow; each logged in docs/DEPENDENCIES.md)

three, @react-three/fiber, @react-three/drei, framer-motion, lenis (landing page only), lucide-react. Nothing else. The status-map unit test uses Node's built-in test runner, so no test framework is added.

## P0 findings folded in

HIGH #1 to #12 and #30 to #34 are fixed as part of steps 2 to 4 (for example, contrast through the new tokens and focus rings in the primitives). The rest go with the rewrite.
