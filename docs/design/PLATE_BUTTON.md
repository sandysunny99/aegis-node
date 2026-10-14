# PlateButton: the 3D button spec

From Sandeep's redesign spec (section 5). The button is a bronze plate on a darker edge
layer; pressing it drops the face 4px onto the edge, the same physical metaphor as the
shield. Adapted from the classic pushable-button pattern (front face + edge span), with
chamfered corners instead of rounding.

```css
.plate-btn {
  --cut: 6px;
  --depth: 4px;
  --chamfer: polygon(var(--cut) 0, calc(100% - var(--cut)) 0, 100% var(--cut),
    100% calc(100% - var(--cut)), calc(100% - var(--cut)) 100%, var(--cut) 100%,
    0 calc(100% - var(--cut)), 0 var(--cut));
  position: relative;
  border: 0;
  padding: 0;
  background: transparent;
  cursor: pointer;
  min-height: 44px;
  min-width: 44px;
  outline-offset: 3px;
}
.plate-btn .edge {               /* the darker side of the plate */
  position: absolute; inset: 0;
  background: color-mix(in oklab, var(--bronze) 55%, black);
  clip-path: var(--chamfer);
}
.plate-btn .face {               /* the part you press */
  position: relative; display: flex; align-items: center; gap: 8px;
  padding: 12px 20px;
  font: 500 15px/1.2 "IBM Plex Sans", sans-serif;
  color: var(--graphite);
  background: var(--bronze);
  clip-path: var(--chamfer);
  transform: translateY(calc(var(--depth) * -1));
  transition: transform 140ms cubic-bezier(.3,.7,.4,1);
}
.plate-btn:hover .face  { transform: translateY(calc(var(--depth) * -1.5)); }
.plate-btn:active .face { transform: translateY(0); transition-duration: 90ms; }
.plate-btn:focus-visible { outline: 2px solid var(--bronze); }
.plate-btn[disabled] { cursor: not-allowed; }
.plate-btn[disabled] .face { transform: translateY(0); opacity: .55; }
@media (prefers-reduced-motion: reduce) {
  .plate-btn .face { transition: none; }
}

/* markup: <button class="plate-btn"><span class="edge"></span><span class="face">Inspect node</span></button> */
```

| Variant | Face | Edge | Use for |
|---|---|---|---|
| primary | `--bronze`, text `--graphite` | bronze 55% toward black | One per screen: the main action |
| secondary | `--slate`, text `--bone`, 1px `--ash` inner line | slate 60% toward black | "Read the threat model", filters |
| danger | `--breach`, text `--bone` (check contrast, else darken face) | breach 55% toward black | Destructive actions; opens a confirm dialog first |
| ghost | transparent, text `--bone`, no edge, no depth | none | Table row actions; underline on hover |

Required states: `:hover`, `:active`, `:focus-visible` (2px bronze outline, offset 3px),
disabled, and loading (spinner replaces the label, width locked). Minimum 44x44px target.
Labels name the action. No arrows, no glow, no pill.

Related components: the status chip is a small flat hexagon (clip-path) with the state word
next to it, never colour alone; the mobile card uses the 3-level shadow scale; the
Aceternity 3D tilt card is allowed only in the "How a breach looks" chapter, tilt max
8 degrees, with its purpose recorded in DECISIONS.md.
