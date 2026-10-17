# Delivery Gate: Bastion steps 2 to 4 (17 Oct 2026)

Design Read: *Reading this as: a dataset-security tool for ML and security engineers, in the Bastion style (bronze hex shield on graphite), dial ENERGY 2 / RHYTHM 3 / MOTION 2.*

Branch `feat/bastion-frontend`, checked against anti-slop v3.2.20 (`antislop.md`), read from the copy in Downloads because the files are not in the repo yet. The checks ran against the build served at `http://localhost:8000` (2026-10-17), in Chromium at 1440×900 and 390×844, in both themes.

## Block 1: Hard Gate

| Rule | Result | Evidence |
|---|---|---|
| R-02 em dash | PASS | No em dash in `frontend/src` UI strings. Backend rule descriptions that contain one are shown with a colon instead (`status/text.js`). |
| R-03 mobile | PASS | `scrollWidth == clientWidth` (375) on the landing page and the app overview at 390px. On phones the table becomes cards, the sidebar becomes a drawer and the shield becomes a 2D grid. |
| R-17 numbers | PASS | Every number on screen comes from the API. The landing page shows no statistics. |
| R-18 testimonials | PASS | None. |
| R-23 assets | PASS (placeholder) | The logo is the text wordmark plus the hex motif from DESIGN.md, standing in for the `[LOGO]` placeholder until a real mark exists. |
| R-24 navigation | PASS | Nav: Overview, Scan a dataset, Datasets, Settings. Landing anchors (#product, #how, #research) all exist. "Scans" and "Reports" were left out because those routes don't exist. |
| R-25 contrast | PASS | Body text is at least 12.7:1, muted text at least 5.7:1 and the accent at least 5.1:1, in both themes (WCAG formula over all four surfaces). |
| R-26 controls | PASS | See the click-through under R-35. |
| R-27 states | PASS | Overview, datasets, detail, settings, AI analysis and scan history each have empty, loading (skeleton) and error-with-retry states. |
| R-28 FAQ | PASS | No FAQ. |
| R-32 keyboard | PASS | Tab shows the bronze focus ring. Ctrl/⌘K opens search, and arrow keys plus Enter select a result. Escape closes search (it used to clear the field first; fixed). A visually hidden button list mirrors the shield plates. Sort headers are buttons with `aria-sort`. |
| R-33 patch scripts | PASS | Every feature is written in source. No patch scripts are left in the repo (the old `ui_refactor.py` was deleted in the audit). |
| R-34 themes | PASS | The overview, search dialog and styleguide were checked in light and dark. |
| R-35 click-through | PASS | Theme toggle: light to dark and back. Sidebar collapse: collapses and expands. Sort by Name: first row changes from demo_malicious.csv to demo_clean.csv. Status filter "Quarantined": 1 row. Dataset link: opens `#/app/datasets/<id>`. Settings: 3 cards. Upload button disabled with no file. Ctrl+K: opens, filters, Escape closes. The only console errors are Google Fonts blocked by the test browser and expected 404s for a dataset with no analysis yet. |
| R-36 claims | PASS | The landing page lists only checks in `scanner/` and says what is *not* checked (PII, licences, label poisoning). |
| R-37 direction | PASS | DESIGN.md and the 17 Oct brief, with the dial declared. |
| R-38 real content | PASS | The landing shield uses fixtures labelled "Illustration with sample datasets". The app uses live API data only. |

## Block 2: Purpose-Gate

| Rule | Result | Reason written |
|---|---|---|
| R-01 gradients/glow | PASS | Two only: the skeleton shimmer (it signals loading) and the hero halftone (the brief asks for a low-contrast hero background). Both are in DECISIONS.md. |
| R-04 icons | PASS | lucide-react, which the brief names. Icons always sit next to the status word. No sparkle, robot, orb, padlock or lightning icons. |
| R-06 typography | PASS | IBM Plex Sans and Mono, reasons in DESIGN.md and DECISIONS.md. No uppercase wide-tracked labels. |
| R-07 background | PASS | The halftone is hero-only, masked, and has a written reason. |
| R-08 arrows | PASS | None on buttons. |
| R-09 badges | PASS | Status chips carry a real status. There is no "AI powered" badge. |
| R-10 glass | PASS | None. |
| R-12 shadow | PASS | Three elevation levels only. |
| R-13 glow | PASS | None. The breached plate tilts out instead; bloom would need `@react-three/postprocessing`, which is not on the allowed package list. |
| R-14 cards | PASS | Sections use different compositions: tables, a list, the shield, a diagram. |
| R-19 animation | PASS | Each motion has a purpose: the scan sweep, the pinned scan steps, and button press. Reduced motion turns all of it off. |
| R-22 illustrations | PASS | No stock illustrations. The diagram is the real pipeline. |

## Block 3: Liveliness

| Check | Result |
|---|---|
| Dials declared | YES: ENERGY 2 / RHYTHM 3 / MOTION 2 |
| Output matches the dials | YES: the landing chapters each use a different composition, and motion only reports state or scan progress |
| One focal point per screen | YES: the hero shield, the overview shield, the detail title |
| Structural whitespace | YES |
| One deliberate accent | YES: bronze, used for actions, focus and the active nav item |
| Identity motif | YES: the hex plate (shield, brand mark, stepper, timeline) and chamfered buttons and chips |
| Design Read before building | YES (above, and in the plan) |

## Block 4: Craftsmanship and Quality Locks

All **no**:
- C-1 to C-5: no default-only choices, no dead controls, no filler sections, nothing breaks in the states, themes and breakpoints checked, and no fabricated claims.
- R-05: not the template layout. The hero sits on an asymmetric 5/6 grid, the problems use a numbered list, and there is a pinned scroll chapter, a dense table and a diagram.
- R-11: no pill shapes; one 4px radius plus the chamfer.
- R-15: CTAs are "Scan a dataset", "Read the threat model" and "View source on GitHub".
- R-16: no buzzwords.
- R-20: hide the logo and the bronze hex shield still identifies it.
- R-21: dark is the default for a stated reason, and the light toggle works.
- R-29: two neutrals, one accent, and semantic status colours only.
- R-30: not a clone of any product.
- R-31: reasons are in docs/DECISIONS.md.

## P5: performance and accessibility pass (17 Oct, after the gate above)

Measured in Chromium against the local server, without network throttling (not a Lighthouse run; see below).

| Check | Result | Budget |
|---|---|---|
| Landing JS on the wire | 113 KB gzipped | < 250 KB |
| 3D shield chunk (lazy, desktop only) | 215 KB gzipped; not downloaded on phones | < 250 KB |
| CSS | 8 KB gzipped | none set |
| LCP, landing, 1440px | 224 ms | < 2.5 s |
| LCP, landing, 390px | 172 ms | < 2.5 s |
| CLS, landing | 0 | < 0.05 |
| Reduced motion | The pinned chapter becomes a static list and the shield stops moving | required |
| Focusable elements without an accessible name (landing) | 0 of 22 | 0 |
| One h1 per page | yes; app pages have a visually hidden h1 with the page name | required |

Fixed in this pass: the server sent the UI uncompressed (359 KB of JavaScript per visit); FastAPI now gzips responses over 1 KB (`backend/main.py`, `tests/test_static_delivery.py`). App pages had no h1; added.

Not done: a real Lighthouse report. The `lighthouse` package is not on the approved package list, so these figures come from the browser's own PerformanceObserver. They are local, unthrottled numbers, not mid-range-phone numbers.

## Open items

- `[LOGO]`: a real logo mark is still needed. The wordmark plus hex is the placeholder.
- Not yet measured (step P5): Lighthouse, LCP and CLS. Built sizes: landing JS is 116 KB gzipped, and the lazy 3D chunk is 222 KB gzipped (budget: 250 KB each).
- The anti-slop files (`antislop.md`, `skills/`) still need to be unzipped into Aegis-Node so `contrast-check.py` can run from the repo.
- The Raycast design-system entry could not be fetched, so the tokens derive from the brief's §4 rules.
