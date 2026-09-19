---
name: Precision DevSecOps
colors:
  surface: '#101318'
  surface-dim: '#101318'
  surface-bright: '#36393f'
  surface-container-lowest: '#0b0e13'
  surface-container-low: '#191c21'
  surface-container: '#1d2025'
  surface-container-high: '#272a2f'
  surface-container-highest: '#32353a'
  on-surface: '#e1e2e9'
  on-surface-variant: '#c7c4d7'
  inverse-surface: '#e1e2e9'
  inverse-on-surface: '#2e3036'
  outline: '#908fa0'
  outline-variant: '#464554'
  surface-tint: '#c0c1ff'
  primary: '#c0c1ff'
  on-primary: '#1000a9'
  primary-container: '#8083ff'
  on-primary-container: '#0d0096'
  inverse-primary: '#494bd6'
  secondary: '#89ceff'
  on-secondary: '#00344d'
  secondary-container: '#00a2e6'
  on-secondary-container: '#00344e'
  tertiary: '#4edea3'
  on-tertiary: '#003824'
  tertiary-container: '#00885d'
  on-tertiary-container: '#000703'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#e1e0ff'
  primary-fixed-dim: '#c0c1ff'
  on-primary-fixed: '#07006c'
  on-primary-fixed-variant: '#2f2ebe'
  secondary-fixed: '#c9e6ff'
  secondary-fixed-dim: '#89ceff'
  on-secondary-fixed: '#001e2f'
  on-secondary-fixed-variant: '#004c6e'
  tertiary-fixed: '#6ffbbe'
  tertiary-fixed-dim: '#4edea3'
  on-tertiary-fixed: '#002113'
  on-tertiary-fixed-variant: '#005236'
  background: '#101318'
  on-background: '#e1e2e9'
  surface-variant: '#32353a'
typography:
  headline-xl:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.025em
  headline-xl-mobile:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: Geist
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.015em
  headline-sm:
    fontFamily: Geist
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.015em
  title-md:
    fontFamily: Geist
    fontSize: 15px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: -0.01em
  body-md:
    fontFamily: Geist
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: 0em
  body-sm:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
    letterSpacing: 0.005em
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: -0.01em
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0em
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.06em
  metric-display:
    fontFamily: Geist
    fontSize: 36px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.03em
  metric-display-mobile:
    fontFamily: Geist
    fontSize: 28px
    fontWeight: '700'
    lineHeight: 34px
    letterSpacing: -0.025em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  space-3xs: 0.125rem
  space-2xs: 0.25rem
  space-xs: 0.5rem
  space-sm: 0.75rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2rem
  space-2xl: 3rem
  space-3xl: 4rem
  gutter-desktop: 1.25rem
  margin-desktop: 1.5rem
  sidebar-collapsed-width: 3.5rem
  sidebar-expanded-width: 16rem
  feed-row-height: 2.75rem
---

## Brand & Style

This design system targets elite security engineers, application security teams, and systems architects who demand rigor, rapid telemetry, and uncompromising clarity. The visual language merges high-density productivity with an obsessive level of polish, drawing direct influence from modern technical benchmarks like Linear and Vercel.

The design philosophy balances precision minimalism with utilitarian brutalism. The interface never relies on decorative flash; every pixel, line, and highlight represents actionable data state. The emotional cadence is quiet, authoritative, and impenetrable—evoking the confidence of an air-gapped terminal paired with the fluid micro-interactions of next-generation developer tooling.

## Colors

The palette operates on layered, low-reflection dark tones engineered to minimize ocular fatigue during extended auditing sessions while preserving critical color fidelity.

### Surface System
- **Canvas Base (`#0B0D10`):** The absolute foundational viewport backplane.
- **Surface Level 1 (`#111419`):** Primary paneling, navigation rail backgrounds, and top toolbars.
- **Surface Level 2 (`#171B22`):** Elevated cards, interactive table rows, code diff containers, and popovers.
- **Surface Level 3 (`#212631`):** Dropdown menus, modal sheets, and active focus surfaces.

### Strokes & Borders
- **Subtle Stroke (`rgba(255, 255, 255, 0.08)` / `#2B3240`):** Hairline structure for card dividers, table rows, and input perimeters.
- **Active Stroke (`rgba(255, 255, 255, 0.18)`):** Hover, selection, and keyboard focus states.

### Typography Scales
- **Text Primary (`#F3F4F6`):** View titles, active metrics, code diff additions/deletions, and prominent headings.
- **Text Secondary (`#94A3B8`):** Table column headers, field labels, parameter names, and file path segments.
- **Text Tertiary (`#64748B`):** Timestamps, metadata annotations, line numbers, and deactivated states.

### Security Severity Tokens
Severity signaling is absolute, high-contrast, and strictly paired with tinted backdrop fills to prevent color-only reliance:
- **Critical (`#EF4444`):** Background `rgba(69, 10, 10, 0.40)`, border `rgba(153, 27, 27, 0.50)`, foreground `#F87171`. Used for Remote Code Execution (RCE), token leaks, and active exploits.
- **High (`#F97316`):** Background `rgba(67, 20, 7, 0.40)`, border `rgba(154, 52, 18, 0.50)`, foreground `#FB923C`. Used for privileged access escalation and zero-day dependency exposure.
- **Medium (`#FBBF24`):** Background `rgba(69, 26, 3, 0.30)`, border `rgba(146, 64, 14, 0.40)`, foreground `#FCD34D`. Used for permissive CORS, weak cryptography, or missing rate-limiting.
- **Low / Info (`#38BDF8`):** Background `rgba(8, 47, 73, 0.30)`, border `rgba(7, 89, 133, 0.40)`, foreground `#7DD3FC`. Used for informational AST notes and non-breaking security linting.
- **Passing / Clean (`#10B981`):** Background `rgba(6, 78, 59, 0.40)`, border `rgba(6, 95, 70, 0.50)`, foreground `#34D399`. Used for resolved CVEs, signed commits, and passing posture scans.

## Typography

The type system pairs **Geist** for crisp human-language interfaces with **JetBrains Mono** for machine-generated identifiers, code blocks, and metrics.

- **Proportional Tracking:** All display and title elements employ tightened negative letter-spacing (`-0.01em` to `-0.03em`) to mimic dense, contemporary software packaging.
- **Monospaced Enforcement:** Commit SHAs (`a7f92b0`), CVE identifiers (`CVE-2024-3094`), AST rule IDs (`sec/no-direct-eval`), and numerical runtime deltas (`+14.2ms`) must exclusively render in JetBrains Mono.
- **Tabular Figures:** Font-variant-numeric is configured to `tabular-nums` system-wide to ensure continuous real-time scanning tables and vulnerability count chips stay perfectly aligned during dynamic updates.

## Layout & Spacing

The layout is built on a 4px baseline rhythm optimized for screen density and immediate peripheral orientation.

### Layout Philosophy
- **Collapsible Control Shell:** Persistent left rail (64px collapsed, 256px expanded) framing a fluid, dynamic dashboard canvas that scales up to 1600px max content width before centering.
- **Split Audit Paneling:** For deep inspection workflows (e.g., Code Diff vs. Remediation Suggestion), the viewport uses a strict 55/45 split container divided by an adjustable 1px hairline resizer.
- **Vertical Density:** Dense tabular displays use a locked 44px (`2.75rem`) row height to maximize information density without degrading cursor hit target accessibility.

### Responsive Breakpoints
- **Desktop (`>= 1280px`):** Full dual-pane review panels, side-by-side AST trees, and multi-column telemetry cards.
- **Tablet (`768px - 1279px`):** Single-column stacked diff panels, tabbed remediation sheets, fixed persistent bottom summary bar.
- **Mobile (`< 768px`):** Collapsed navigation drawer, full-width single-metric cards, and horizontally scrolling diff blocks with locked line-number gutters.

## Elevation & Depth

Visual hierarchy is constructed through high-contrast surface tone separation and translucent inner borders, entirely avoiding diffuse ambient dropshadows that muddy dark backgrounds.

### Elevation Architecture
1. **Level 0 (Canvas):** Base viewport `#0B0D10`. No borders or shadows.
2. **Level 1 (Card & Section):** Surface `#111419`. Framed by a 1px uniform stroke: `rgba(255, 255, 255, 0.07)`.
3. **Level 2 (Active Focus & Flyouts):** Surface `#171B22`. Framed by `rgba(255, 255, 255, 0.12)` with an inner top hairline highlight: `inset 0 1px 0 0 rgba(255, 255, 255, 0.08)`.
4. **Level 3 (Modals, Overlays, Command Palettes):** Surface `#212631`. Border: `rgba(255, 255, 255, 0.16)`. Accompanied by a razor-sharp grounding perimeter shadow: `0 16px 36px -8px rgba(0, 0, 0, 0.85)`.

### Optical Highlights
Hoverable cards and interactive rows feature an imperceptible top-edge illumination via CSS pseudo-elements: a single-pixel gradient fading from transparent to `rgba(255, 255, 255, 0.15)` back to transparent, giving hardware-grade physical dimensionality to data containers.

## Shapes

The interface embraces crisp, controlled industrial ergonomics:

- **Tokens & Elements:** Base corner rounding is locked to `0.25rem` (4px). Structural surfaces, cards, and modal dialogs cap at `0.5rem` (8px). 
- **Code & Diff Shells:** Inner code gutters and diff highlights have a strict 2px radius or remain flush (`0px`) against adjacent lines to ensure visual continuity.
- **Badges & Tags:** Severity chips and status pills use a tailored `3px` corner radius—deliberately avoiding organic full-pill geometries to maintain a surgical, technical aesthetic.

## Components

### 1. Buttons
- **Primary Action (e.g., 'Accept Fix', 'Create PR'):** Background `#6366F1`, text `#FFFFFF`, border `1px solid rgba(255, 255, 255, 0.20)`. Hover: `#4F46E5` with `box-shadow: 0 0 12px rgba(99, 102, 241, 0.35)`. Height: 32px (small) or 36px (regular).
- **Secondary (e.g., 'View AST', 'Dismiss'):** Background `#171B22`, text `#F3F4F6`, border `1px solid rgba(255, 255, 255, 0.08)`. Hover: background `#212631`, border `rgba(255, 255, 255, 0.16)`.
- **Destructive:** Background `rgba(69, 10, 10, 0.3)`, text `#F87171`, border `1px solid rgba(153, 27, 27, 0.5)`. Hover: background `rgba(153, 27, 27, 0.4)`.

### 2. Severity Chips & Badges
- Height is fixed at 20px. Font: `JetBrains Mono` 10px / line-height 14px, weight 600, uppercase.
- Contains an optical 5px circular status dot on the leading edge (pulsing on Critical vulnerabilities).
- Inline padding: 6px. Background and border strictly match the security severity color tokens.

### 3. Metric Telemetry Cards
- Surface: `#111419` with a subtle top-border highlight.
- Header: JetBrains Mono uppercase metadata label with an integrated info icon.
- Metric: 36px bold Geist with embedded inline delta tag (e.g., `↓ 12%` in `#10B981` or `↑ 3` in `#EF4444`).
- Footer: Micro sparkline chart (SVG, 36px height) using a monochrome path fading into surface transparency.

### 4. Interactive Code Diff Viewer
- Background: `#0E1116`. Split or unified view with fixed 40px gutter for line numbers.
- **Vulnerable Node Line:** Tinted background `rgba(239, 68, 68, 0.12)` with a 2px left border `#EF4444`. Monospaced strike-through or inline wavy underline on the exact AST offending token.
- **AI Remediation Line:** Tinted background `rgba(16, 185, 129, 0.12)` with a 2px left border `#10B981`. Integrated quick-action button group positioned absolutely on the right margin.

### 5. Repository Security Posture Table
- Striped or bordered rows on `#111419` with alternating hover background `#171B22`.
- Columns: Repository Name (with VCS icon), Security Grade Badge (`A+`, `B`, `F` with color-coded containment rings), Scanned Branch selector dropdown, Open Findings split bar (miniature horizontal stacked segment chart showing critical/high/med ratios), and Last Sync timestamp.

### 6. Form Inputs & Search Command Bar
- Height: 32px or 36px. Background `#0B0D10`, border `1px solid rgba(255, 255, 255, 0.08)`, text `#F3F4F6`.
- Focus State: Border color `#6366F1`, outline `1px solid rgba(99, 102, 241, 0.40)`.
- Global Filter Input includes shortcut tag badge (`⌘K`) right-aligned in `JetBrains Mono` 10px.