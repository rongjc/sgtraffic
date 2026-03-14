# APK Malware Scanner — Design System & Wireframes

> **Audience:** Frontend engineers and designers.
> **Stack:** React + TailwindCSS + shadcn/ui (or plain Tailwind components) + lucide-react icons.
> **Design posture:** Security tooling — dark-first, high-information density, low visual noise.

---

## Table of Contents

1. [Design Tokens](#1-design-tokens)
2. [Typography](#2-typography)
3. [Spacing & Layout](#3-spacing--layout)
4. [Core Components](#4-core-components)
5. [Wireframes](#5-wireframes)
6. [Accessibility](#6-accessibility)

---

## 1. Design Tokens

### 1.1 Color Palette

All colors are Tailwind 950–50 scale values. Dark mode is the **default and only** mode for this product (security tooling audience).

#### Background layers

```
Layer 0 — App chrome:       bg-gray-950   (#030712)
Layer 1 — Cards / surfaces: bg-gray-900   (#111827)
Layer 2 — Nested surface:   bg-gray-800   (#1f2937)
Layer 3 — Elevated/hover:   bg-gray-700   (#374151)
```

#### Text

```
text-primary:    text-gray-100   (#f3f4f6)
text-secondary:  text-gray-400   (#9ca3af)
text-muted:      text-gray-500   (#6b7280)
text-disabled:   text-gray-600   (#4b5563)
text-inverse:    text-gray-950   (on light surfaces)
```

#### Border

```
border-default:  border-gray-800  (#1f2937)
border-subtle:   border-gray-700  (#374151)
border-emphasis: border-gray-600  (#4b5563)
```

#### Brand — Indigo (primary action, focus rings, accents)

```
brand-subtle:    indigo-950/30   (hover state on upload zone)
brand-muted:     indigo-900/50
brand-default:   indigo-600      (#4f46e5)
brand-hover:     indigo-500      (#6366f1)
brand-text:      indigo-400      (#818cf8)
brand-bright:    indigo-300      (#a5b4fc)
```

#### Semantic — Risk / Severity

| Severity   | Background         | Border           | Text             | Badge bg         | Badge text       |
|------------|-------------------|-----------------|-----------------|-----------------|-----------------|
| Critical   | red-900/50        | red-700          | red-300          | red-800          | red-200          |
| High       | orange-900/50     | orange-700       | orange-300       | orange-800       | orange-200       |
| Medium     | yellow-900/50     | yellow-700       | yellow-300       | yellow-800       | yellow-200       |
| Low        | gray-800          | gray-700         | gray-400         | gray-700         | gray-300         |
| Clean/Safe | green-950         | green-800        | green-300        | green-800        | green-200        |

#### Semantic — Status (scan progress)

```
pending:   bg-gray-500
analyzing: bg-indigo-400  (animate-pulse)
done:      bg-green-500
error:     bg-red-500
```

#### Risk score color thresholds

```
score >= 75  →  text-red-400   / bg-red-500   (High risk)
score >= 40  →  text-yellow-400 / bg-yellow-500 (Medium risk)
score < 40   →  text-green-400  / bg-green-500  (Low risk)
```

---

### 1.2 Tailwind Config Extension

Add the following to `tailwind.config.js` to codify the design tokens:

```js
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class', // root element always has class="dark"
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: '#4f46e5', // indigo-600
          hover:   '#6366f1', // indigo-500
          text:    '#818cf8', // indigo-400
          bright:  '#a5b4fc', // indigo-300
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'monospace'],
      },
      borderRadius: {
        card: '0.75rem', // 12px — rounded-xl
      },
    },
  },
  plugins: [],
};
```

---

## 2. Typography

### 2.1 Font Stack

| Role        | Family                                | Tailwind class        |
|-------------|---------------------------------------|-----------------------|
| UI / Body   | Inter → system-ui → sans-serif        | `font-sans`           |
| Code / Hash | JetBrains Mono → Fira Code → mono     | `font-mono`           |

### 2.2 Type Scale

| Role         | Size  | Weight    | Leading    | Tailwind                        |
|--------------|-------|-----------|------------|---------------------------------|
| Display      | 36px  | 700       | tight      | `text-4xl font-bold tracking-tight` |
| H1           | 30px  | 700       | tight      | `text-3xl font-bold tracking-tight` |
| H2           | 24px  | 700       | tight      | `text-2xl font-bold`            |
| H3           | 20px  | 600       | snug       | `text-xl font-semibold`         |
| H4           | 18px  | 600       | snug       | `text-lg font-semibold`         |
| Body lg      | 16px  | 400       | relaxed    | `text-base`                     |
| Body         | 14px  | 400       | relaxed    | `text-sm`                       |
| Caption      | 12px  | 400       | normal     | `text-xs`                       |
| Label        | 12px  | 500 + UC  | wider      | `text-xs font-medium uppercase tracking-wider` |
| Code inline  | 13px  | 400       | —          | `font-mono text-xs`             |
| Code block   | 12px  | 400       | relaxed    | `font-mono text-xs`             |

---

## 3. Spacing & Layout

### 3.1 Spacing Scale

Base unit: **4px (1 Tailwind unit)**. Use multiples of 4.

```
2  →  8px    (tight internal padding, icon gaps)
3  →  12px   (compact gaps)
4  →  16px   (default internal padding)
5  →  20px   (card padding)
6  →  24px   (section gaps)
8  →  32px   (large gaps)
10 →  40px   (page section margins)
12 →  48px   (hero padding)
```

### 3.2 Grid & Breakpoints

Single-column layout on mobile, expanding to constrained content column on desktop.

```
Mobile:   100% width, px-4 padding
sm (640): same
md (768): max-w-3xl  (768px) — detail pages
lg (1024): max-w-4xl (896px) — list pages
xl (1280): max-w-5xl — future multi-panel layouts
```

### 3.3 Page Shell

All pages use:
```
min-h-screen bg-gray-950 text-gray-100
```

Content container: `max-w-{size} mx-auto px-4 py-8`

---

## 4. Core Components

### 4.1 Button

Three variants:

**Primary**
```
bg-indigo-600 hover:bg-indigo-500 text-white
font-medium text-sm px-4 py-2 rounded-lg
transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500
```

**Ghost / Link-style**
```
text-indigo-400 hover:text-indigo-300
underline underline-offset-2
```

**Destructive**
```
bg-red-700 hover:bg-red-600 text-white
font-medium text-sm px-4 py-2 rounded-lg transition-colors
```

**Disabled state** (all variants):
```
opacity-50 cursor-not-allowed pointer-events-none
```

**Loading state**: replace label with `<Loader2 className="w-4 h-4 animate-spin" />`

**Keyboard:** `Enter` and `Space` activate. Focus ring: `ring-2 ring-indigo-500 ring-offset-2 ring-offset-gray-950`.

**ARIA:** `aria-disabled="true"` when disabled. `aria-busy="true"` when loading.

---

### 4.2 Input / Textarea

```
w-full bg-gray-800 border border-gray-700
rounded-lg px-3 py-2 text-sm text-gray-100
placeholder:text-gray-500
focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500
transition-colors
```

Error state: swap `border-gray-700` → `border-red-500`, add `focus:ring-red-500`.

Label: `text-xs font-medium text-gray-400 mb-1 block` above the input.
Helper/error text: `text-xs text-gray-500 mt-1` / `text-xs text-red-400 mt-1`.

---

### 4.3 Badge

Pills used for severity, verdict, categories.

```html
<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold
             bg-{color}-800 text-{color}-200">
  <Icon class="w-3 h-3" /> Label
</span>
```

Size variants:
- **sm** (default): `px-2 py-0.5 text-xs`
- **md**: `px-3 py-1 text-sm`

---

### 4.4 Card

```
bg-gray-900 rounded-xl p-5
```

Optional border: `border border-gray-800`

Card header pattern:
```html
<p class="text-xs text-gray-500 uppercase tracking-wider mb-3">Section Title</p>
```

---

### 4.5 Table

Used in scan history. Full-width inside a card.

```html
<!-- Container -->
<div class="bg-gray-900 rounded-xl overflow-hidden border border-gray-800">

  <!-- Header row -->
  <div class="grid grid-cols-[...] px-5 py-3 border-b border-gray-800
              text-xs text-gray-500 uppercase tracking-wider">
    <span>Column</span>
    ...
  </div>

  <!-- Body rows -->
  <div class="divide-y divide-gray-800">
    <div class="grid grid-cols-[...] px-5 py-4 hover:bg-gray-800/60 transition-colors">
      ...
    </div>
  </div>

</div>
```

**Responsive:** On mobile, collapse to card-list view (stacked `dl` pairs).

**ARIA:** Wrap in `<table role="table">` or use semantic `<table>` for screen readers.

---

### 4.6 Modal / Dialog

```html
<!-- Overlay -->
<div class="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
     role="dialog" aria-modal="true" aria-labelledby="dialog-title">

  <!-- Panel -->
  <div class="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-md p-6 shadow-xl">
    <h2 id="dialog-title" class="text-lg font-semibold mb-4">Title</h2>
    <!-- content -->
    <div class="flex justify-end gap-3 mt-6">
      <button class="/* ghost btn */">Cancel</button>
      <button class="/* primary btn */">Confirm</button>
    </div>
  </div>

</div>
```

**Keyboard:** `Escape` closes. Focus trap inside panel. Return focus to trigger on close.

---

### 4.7 Toast / Notification

Fixed, stacked in bottom-right corner (`fixed bottom-4 right-4 z-50 flex flex-col gap-2`).

```html
<div class="bg-gray-800 border border-gray-700 rounded-xl px-4 py-3
            flex items-start gap-3 shadow-lg max-w-sm w-full
            animate-in slide-in-from-bottom-2">
  <Icon class="w-4 h-4 mt-0.5 shrink-0 text-{semantic}" />
  <div>
    <p class="text-sm font-medium text-gray-100">Title</p>
    <p class="text-xs text-gray-400">Description</p>
  </div>
  <button class="ml-auto text-gray-500 hover:text-gray-300" aria-label="Dismiss">
    <X class="w-4 h-4" />
  </button>
</div>
```

Variants: `success` (green-400), `error` (red-400), `warning` (yellow-400), `info` (indigo-400).

Auto-dismiss after 4s. **ARIA:** `role="alert"` for errors, `role="status"` for success.

---

### 4.8 Progress Bar

Used during upload and scan polling.

```html
<!-- Determinate -->
<div class="w-full bg-gray-800 rounded-full h-2" role="progressbar"
     aria-valuenow="{pct}" aria-valuemin="0" aria-valuemax="100">
  <div class="bg-indigo-500 h-2 rounded-full transition-all duration-200"
       style="width: {pct}%" />
</div>

<!-- Indeterminate (analyzing) -->
<div class="w-full bg-gray-800 rounded-full h-1 overflow-hidden">
  <div class="bg-indigo-500 h-1 rounded-full animate-pulse w-1/2 mx-auto" />
</div>
```

---

### 4.9 Code Block

Used for YARA matches, evidence snippets, API examples.

```html
<pre class="bg-gray-950 border border-gray-800 rounded-lg p-4
            font-mono text-xs text-gray-300
            overflow-x-auto whitespace-pre-wrap break-words">
  <code>{content}</code>
</pre>
```

Add a copy-to-clipboard icon button in the top-right corner:
```html
<div class="relative group">
  <pre ...>{content}</pre>
  <button class="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity
                 text-gray-500 hover:text-gray-300 p-1 rounded"
          aria-label="Copy code">
    <Copy class="w-3.5 h-3.5" />
  </button>
</div>
```

---

### 4.10 Accordion (Collapsible Section)

Used for findings groups and raw details.

```html
<div class="rounded-xl border {severity-border} {severity-bg} mb-4">
  <button class="w-full flex items-center justify-between px-4 py-3 font-semibold"
          aria-expanded="{open}" aria-controls="accordion-body">
    <span>Section header</span>
    {open ? <ChevronUp /> : <ChevronDown />}
  </button>
  <div id="accordion-body" hidden={!open} class="divide-y divide-gray-700/50">
    <!-- items -->
  </div>
</div>
```

---

### 4.11 Drag-and-Drop Upload Zone

```html
<div role="button" tabindex="0"
     aria-label="Drag and drop APK file or click to browse"
     class="w-full max-w-xl border-2 border-dashed rounded-2xl p-12
            flex flex-col items-center gap-4 cursor-pointer transition-colors
            {dragging
              ? 'border-indigo-400 bg-indigo-950/30'
              : 'border-gray-700 hover:border-indigo-500 bg-gray-900'}">
  <Upload class="w-12 h-12 {dragging ? 'text-indigo-400' : 'text-gray-500'}" />
  <p class="text-lg font-medium text-gray-200">Drag & drop your APK here</p>
  <p class="text-sm text-gray-500">or click to browse — max 100 MB</p>
</div>
```

**ARIA:** `role="button"`, `tabindex="0"`, `aria-label` describing action. `aria-live="polite"` on the status region below.

---

### 4.12 Risk Meter

```html
<div class="flex items-center gap-3" role="meter"
     aria-valuenow="{score}" aria-valuemin="0" aria-valuemax="100"
     aria-label="Risk score: {score} out of 100">
  <div class="flex-1 bg-gray-800 rounded-full h-3">
    <div class="h-3 rounded-full transition-all duration-500
                {score >= 75 ? 'bg-red-500' : score >= 40 ? 'bg-yellow-500' : 'bg-green-500'}"
         style="width: {score}%" />
  </div>
  <span class="text-lg font-bold w-10 text-right tabular-nums">{score}</span>
</div>
```

---

### 4.13 Empty State

```html
<div class="text-center py-20 text-gray-500">
  <Icon class="w-12 h-12 mx-auto mb-4 opacity-30" aria-hidden="true" />
  <p class="text-lg font-medium mb-2 text-gray-400">No items yet</p>
  <p class="text-sm">Descriptive helper text.</p>
  <!-- Optional CTA -->
  <a href="/" class="/* primary btn */ mt-4 inline-flex">Get started</a>
</div>
```

---

### 4.14 API Key Row

Used in Settings → API Keys.

```html
<div class="flex items-center gap-3 bg-gray-800 rounded-lg px-4 py-3">
  <code class="flex-1 font-mono text-xs text-gray-300 truncate">{key.prefix}•••••••••••••</code>
  <span class="text-xs text-gray-500">{key.name}</span>
  <button aria-label="Copy API key" class="text-gray-500 hover:text-gray-300 p-1">
    <Copy class="w-4 h-4" />
  </button>
  <button aria-label="Revoke API key" class="text-gray-500 hover:text-red-400 p-1">
    <Trash2 class="w-4 h-4" />
  </button>
</div>
```

---

## 5. Wireframes

> Layout notation:
> `[ ]` = interactive element (button/input/link)
> `|` = column separator
> `---` = horizontal rule / divider
> `(icon)` = lucide icon
> `<<<` = left-aligned  | `>>>` = right-aligned | `^^^` = centered

---

### 5.1 Upload Page (Landing)

**Route:** `/`
**Goal:** Zero-friction APK upload; clear brand + value prop.

```
┌──────────────────────────────────────────────────────────────┐
│  bg-gray-950                      min-h-screen               │
│                                                               │
│                    ^^^                                        │
│           (Shield) APK Malware Scanner                        │
│              text-3xl font-bold                               │
│           text-indigo-400 icon                                │
│                                                               │
│        ┌─────────────────────────────────────┐               │
│        │  border-2 dashed border-gray-700     │               │
│        │  rounded-2xl  bg-gray-900   p-12     │               │
│        │                                      │               │
│        │           (Upload icon)              │               │
│        │       text-gray-500  w-12 h-12       │               │
│        │                                      │               │
│        │   Drag & drop your APK here          │               │
│        │   text-lg font-medium text-gray-200  │               │
│        │                                      │               │
│        │   or click to browse — max 100 MB    │               │
│        │   text-sm text-gray-500              │               │
│        │                                      │               │
│        └─────────────────────────────────────┘               │
│                                                               │
│           [   (AlertCircle) Error message   ]  ← if error    │
│              text-sm text-red-400                             │
│                                                               │
│              View scan history  ←  text-indigo-400 link       │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

**Upload in-progress state (same layout, drop zone inner swap):**

```
│        ┌─────────────────────────────────────┐               │
│        │  opacity-70  cursor-not-allowed      │               │
│        │                                      │               │
│        │   Uploading…  43%                    │               │
│        │   text-sm text-gray-400              │               │
│        │                                      │               │
│        │   ████████████░░░░░░░░░░░░░░░░░░░   │               │
│        │   bg-indigo-500 h-2 rounded-full     │               │
│        │                                      │               │
│        └─────────────────────────────────────┘               │
```

**Scan queued / analyzing state** → redirect to `/scans/{id}` immediately after upload.

---

### 5.2 Scan Results Page

**Route:** `/scans/:id`
**Goal:** Comprehensive threat report; fast signal at top, depth below.

```
┌──────────────────────────────────────────────────────────────┐
│  max-w-3xl mx-auto  px-4  py-8                               │
│                                                               │
│  ← Scan history   (ArrowLeft + indigo-400 link)              │
│                                                               │
│  ┌── HEADER ──────────────────────────────────────────────┐  │
│  │  (Shield)  filename.apk          [MALWARE badge] >>>   │  │
│  │  text-xl font-bold               red-800 / red-200      │  │
│  │  Submitted Mar 13, 2026 · Completed ...                 │  │
│  │  text-xs text-gray-500                                  │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌── ANALYZING STATE (hidden when done) ─────────────────┐   │
│  │  bg-gray-900 rounded-xl p-6                            │   │
│  │  (Loader2 spin indigo)  Analyzing APK…                 │   │
│  │                         This usually takes 20–60s.     │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌── RISK SCORE ──────────────────────────────────────────┐  │
│  │  RISK SCORE  (label)                                   │  │
│  │  ████████████████████░░░░░░░  82                       │  │
│  │  bg-red-500 (score ≥ 75)    font-bold tabular-nums     │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌── PHA CATEGORIES (if any) ─────────────────────────────┐  │
│  │  PHA CATEGORIES DETECTED  (label)                      │  │
│  │  [Trojan] [Spyware] [SMS Fraud]                        │  │
│  │  red-900/50 border-red-700 text-red-300 rounded-full   │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌── APK METADATA ────────────────────────────────────────┐  │
│  │  APK METADATA  (label)                                 │  │
│  │  Filename     | SHA-256                                │  │
│  │  Status       | Completed                              │  │
│  │  text-gray-500 dt / text-gray-200 dd                   │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  FINDINGS (4)  (label)                                       │
│                                                               │
│  ┌── FindingGroup: CRITICAL (open) ───────────────────────┐  │
│  │  [CRITICAL] 2 findings          ∧ (ChevronUp)          │  │
│  │  ─────────────────────────────────────────────────     │  │
│  │  Rule name                      category               │  │
│  │  Description text                                      │  │
│  │  ┌ code block / evidence ─────────────────────────┐   │  │
│  │  │ YARA match evidence...                         │   │  │
│  │  └────────────────────────────────────────────────┘   │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌── FindingGroup: HIGH (collapsed) ──────────────────────┐  │
│  │  [HIGH] 5 findings              ∨ (ChevronDown)         │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌── SHARE / EXPORT (bottom) ─────────────────────────────┐  │
│  │  [ (Link2) Copy share link ]  [ (Download) Export PDF ]│  │
│  │  ghost buttons, right-aligned                           │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

**Clean result (no findings):**
```
│  ┌── FINDINGS (0) ────────────────────────────────────────┐  │
│  │  bg-green-950 border-green-800 rounded-xl p-5          │  │
│  │  (CheckCircle green-300)  No findings detected.        │  │
│  │                           This APK appears clean.      │  │
│  └────────────────────────────────────────────────────────┘  │
```

---

### 5.3 Scan History Page

**Route:** `/scans`
**Goal:** Quickly find, filter, and re-scan past APKs.

```
┌──────────────────────────────────────────────────────────────┐
│  max-w-4xl mx-auto  px-4  py-8                               │
│                                                               │
│  ┌── HEADER ──────────────────────────────────────────────┐  │
│  │  (Shield)  Scan History              [ (Upload) New Scan│  │
│  │            text-2xl font-bold        indigo-600 btn  ]  │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌── FILTER BAR ──────────────────────────────────────────┐  │
│  │  [ 🔍 Search filename… ]   [ Verdict ▾ ]  [ Date ▾ ]   │  │
│  │  bg-gray-800 input         select dropdown              │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌── TABLE ───────────────────────────────────────────────┐  │
│  │  bg-gray-900 rounded-xl overflow-hidden                 │  │
│  │                                                         │  │
│  │  Filename         | Date       | Verdict   | Risk       │  │
│  │  text-xs gray-500 uppercase tracking-wider              │  │
│  │  ─────────────────────────────────────────────────     │  │
│  │  ● filename.apk   | Mar 13     | [Malware] |  82        │  │
│  │  ● another.apk    | Mar 12     | [Clean]   |  12        │  │
│  │  ⟳ pending.apk   | Mar 12     | [Pending] |   —        │  │
│  │                                                         │  │
│  │  Each row: hover:bg-gray-800/60, links to /scans/:id   │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌── PAGINATION ──────────────────────────────────────────┐  │
│  │  <<<  Showing 1–20 of 47 scans  [ < ]  [ > ]  >>>     │  │
│  │       text-xs text-gray-500     gray-800 buttons        │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  Empty state (no scans):                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │           (Shield opacity-30)                          │  │
│  │           No scans yet                                 │  │
│  │           Upload an APK to get started.                │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

**Mobile (< md) row layout — card list:**
```
┌── scan card ───────────────────────────────────────────────┐
│  ● filename.apk                           [Malware]        │
│  Mar 13, 2026                               Risk: 82       │
└────────────────────────────────────────────────────────────┘
```

---

### 5.4 User Settings Page

**Route:** `/settings`
**Goal:** Manage profile, security, and API keys.

**Navigation:** Vertical side tabs on md+, horizontal tabs on mobile.

```
┌──────────────────────────────────────────────────────────────┐
│  max-w-4xl mx-auto  px-4  py-8                               │
│                                                               │
│  ┌── HEADER ──────────────────────────────────────────────┐  │
│  │  (Settings)  Account Settings                          │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌── LAYOUT ──────────────────────────────────────────────┐  │
│  │                                                         │  │
│  │  ┌─ NAV (md+: w-48) ─┐  ┌─ CONTENT ─────────────────┐ │  │
│  │  │ Profile          │  │                             │ │  │
│  │  │ Password         │  │  [active section content]   │ │  │
│  │  │ Two-Factor Auth  │  │                             │ │  │
│  │  │ API Keys         │  │                             │ │  │
│  │  │ Notifications    │  │                             │ │  │
│  │  └──────────────────┘  └─────────────────────────────┘ │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

**Profile tab:**
```
┌── Profile ─────────────────────────────────────────────────┐
│  bg-gray-900 rounded-xl p-6                                 │
│                                                             │
│  PROFILE  (label)                                           │
│                                                             │
│  Display name                                               │
│  [ ________________________ ]  (input)                      │
│                                                             │
│  Email                                                      │
│  [ user@example.com         ]  (input, type=email)          │
│                                                             │
│                              [ Save changes ]  (primary btn)│
└─────────────────────────────────────────────────────────────┘
```

**Password tab:**
```
┌── Password ────────────────────────────────────────────────┐
│  bg-gray-900 rounded-xl p-6                                 │
│                                                             │
│  CHANGE PASSWORD  (label)                                   │
│                                                             │
│  Current password                                           │
│  [ ••••••••••••••           ]                               │
│                                                             │
│  New password                                               │
│  [ ••••••••••••••           ]                               │
│  Password strength: ████░░░░  Moderate  (meter)             │
│                                                             │
│  Confirm new password                                       │
│  [ ••••••••••••••           ]                               │
│                                                             │
│                              [ Update password ]            │
└─────────────────────────────────────────────────────────────┘
```

**Two-Factor Auth tab:**
```
┌── 2FA ─────────────────────────────────────────────────────┐
│  bg-gray-900 rounded-xl p-6                                 │
│                                                             │
│  TWO-FACTOR AUTHENTICATION  (label)                         │
│                                                             │
│  Status: ● Not enabled   or   ● Enabled (green dot)         │
│                                                             │
│  [Disabled state]                                           │
│  (Shield)  Protect your account with an authenticator app   │
│  [ Enable 2FA ]  (primary btn)                              │
│                                                             │
│  [Enabled state]                                            │
│  Using TOTP authenticator.  Last verified: Mar 10, 2026     │
│  [ Disable 2FA ]  (destructive btn)                         │
│  [ View backup codes ]  (ghost btn)                         │
└─────────────────────────────────────────────────────────────┘
```

**API Keys tab:**
```
┌── API Keys ────────────────────────────────────────────────┐
│  bg-gray-900 rounded-xl p-6                                 │
│                                                             │
│  API KEYS  (label)                      [ + Create key ]   │
│                                                             │
│  ─────────────────────────────────────────────────────     │
│  apk-scanner-sk-••••••••  |  production-key  | (Copy)(Del) │
│  apk-scanner-sk-••••••••  |  ci-key          | (Copy)(Del) │
│  ─────────────────────────────────────────────────────     │
│                                                             │
│  text-xs text-gray-500: API keys grant full account access. │
│  Keep them secret. Never share in public repositories.      │
└─────────────────────────────────────────────────────────────┘
```

**Create API Key modal:**
```
┌── Dialog ──────────────────────────────────────────────────┐
│  bg-gray-900 border-gray-700 rounded-2xl p-6 max-w-md      │
│                                                             │
│  Create API Key                                             │
│                                                             │
│  Key name                                                   │
│  [ e.g. ci-pipeline             ]  (input, required)        │
│                                                             │
│  Expiry  (optional)                                         │
│  [ Never ▾ ]  or  [ 30 days / 90 days / 1 year ]           │
│                                                             │
│                 [ Cancel ]  [ Create key ]                  │
└─────────────────────────────────────────────────────────────┘
```

**After creation — show key once modal:**
```
┌── Your new API key ─────────────────────────────────────────┐
│  (AlertTriangle yellow)  Copy this key now.                 │
│  It will not be shown again.                                │
│                                                             │
│  apk-scanner-sk-live-abc123xyz...  [Copy]                   │
│  bg-gray-950 font-mono text-xs                              │
│                                                             │
│                                      [ Done ]               │
└─────────────────────────────────────────────────────────────┘
```

**Notifications tab:**
```
┌── Notifications ───────────────────────────────────────────┐
│  bg-gray-900 rounded-xl p-6                                 │
│                                                             │
│  NOTIFICATION PREFERENCES  (label)                          │
│                                                             │
│  Email notifications                                        │
│  [ toggle ] Scan complete                                   │
│  [ toggle ] Scan failed / error                             │
│  [ toggle ] High-risk detection                             │
│  [ toggle ] Weekly digest                                   │
│                                                             │
│                              [ Save preferences ]           │
└─────────────────────────────────────────────────────────────┘
```

Toggle component:
```html
<button role="switch" aria-checked="{on}" aria-label="Toggle {label}"
        class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors
               {on ? 'bg-indigo-600' : 'bg-gray-700'}">
  <span class="inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform
               {on ? 'translate-x-4.5' : 'translate-x-0.5'}" />
</button>
```

---

### 5.5 API Docs Page

**Route:** `/docs`
**Goal:** Self-serve API reference with runnable examples.

```
┌──────────────────────────────────────────────────────────────┐
│  max-w-5xl mx-auto  px-4  py-8                               │
│                                                               │
│  ┌── HEADER ──────────────────────────────────────────────┐  │
│  │  (Code2)  API Reference                                │  │
│  │  Automate APK scanning via REST.                       │  │
│  │  text-sm text-gray-400                                 │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌── LAYOUT ──────────────────────────────────────────────┐  │
│  │                                                         │  │
│  │  ┌─ NAV sidebar (w-56) ─┐  ┌─ CONTENT ───────────────┐│  │
│  │  │ Authentication       │  │                          ││  │
│  │  │ Endpoints            │  │  [section content]       ││  │
│  │  │   POST /scans        │  │                          ││  │
│  │  │   GET  /scans        │  │                          ││  │
│  │  │   GET  /scans/:id    │  │                          ││  │
│  │  │   GET  /scans/:id/   │  │                          ││  │
│  │  │        findings      │  │                          ││  │
│  │  │ Rate Limits          │  │                          ││  │
│  │  │ Error Codes          │  │                          ││  │
│  │  └──────────────────────┘  └──────────────────────────┘│  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

**Authentication section:**
```
┌── Authentication ───────────────────────────────────────────┐
│  h3: Authentication                                          │
│                                                             │
│  All API requests require a Bearer token in the             │
│  Authorization header.                                      │
│                                                             │
│  ┌─ code block ────────────────────────────────────────┐   │
│  │  Authorization: Bearer apk-scanner-sk-live-...      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  [Go to API Keys →]  (indigo link)                         │
└─────────────────────────────────────────────────────────────┘
```

**Endpoint section (example — POST /scans):**
```
┌── POST /scans ──────────────────────────────────────────────┐
│  [POST badge: bg-green-800 text-green-200]  /v1/scans       │
│  text-lg font-semibold                                      │
│                                                             │
│  Submit an APK file for analysis.                           │
│                                                             │
│  REQUEST                                                    │
│  Content-Type: multipart/form-data                         │
│  [ Body: file (required) — .apk, max 100MB ]               │
│                                                             │
│  RESPONSE  200 OK                                           │
│  ┌─ code block (JSON) ─────────────────────────────────┐   │
│  │  {                                                   │   │
│  │    "id": "scan_abc123",                              │   │
│  │    "status": "pending",                              │   │
│  │    "filename": "myapp.apk",                          │   │
│  │    "createdAt": "2026-03-13T06:00:00Z"               │   │
│  │  }                                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  EXAMPLES                                                   │
│  [curl] [Python] [JavaScript]  ← tab switcher              │
│                                                             │
│  ┌─ curl example ──────────────────────────────────────┐   │
│  │  curl -X POST https://api.apkscanner.io/v1/scans \  │   │
│  │    -H "Authorization: Bearer $API_KEY" \            │   │
│  │    -F "file=@myapp.apk"                              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

HTTP method badge colors:
```
GET:    bg-blue-800  text-blue-200
POST:   bg-green-800 text-green-200
DELETE: bg-red-800   text-red-200
PATCH:  bg-yellow-800 text-yellow-200
```

---

## 6. Accessibility

### 6.1 WCAG 2.1 AA Compliance

All foreground/background color pairs must meet **4.5:1 contrast ratio** (text) or **3:1** (large text ≥ 18px bold / 24px regular).

Key verified pairs:
```
text-gray-100 (#f3f4f6) on bg-gray-950 (#030712) → ≈ 17:1  ✓
text-gray-400 (#9ca3af) on bg-gray-900 (#111827) → ≈ 5.3:1 ✓
text-indigo-400 (#818cf8) on bg-gray-950          → ≈ 5.0:1 ✓
text-red-300 (#fca5a5) on bg-red-900/50           → ≈ 5.5:1 ✓
text-green-300 (#86efac) on bg-green-950          → ≈ 6.7:1 ✓
```

### 6.2 Focus Management

- **Focus ring:** All interactive elements: `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950`
- **Never remove outline** without providing a visible replacement.
- **Skip link:** Include at top of page: `<a href="#main-content" class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 /* primary btn */">Skip to content</a>`

### 6.3 Keyboard Navigation Patterns

| Component         | Key bindings                                              |
|-------------------|-----------------------------------------------------------|
| Button            | `Enter`, `Space`                                          |
| Link              | `Enter`                                                   |
| Modal             | `Escape` closes; focus trap inside; return focus on close |
| Accordion         | `Enter`/`Space` toggle; `Arrow` keys navigate headers     |
| Toggle (switch)   | `Space` to toggle when focused                            |
| Drag-and-drop     | `Enter`/`Space` to open file picker (keyboard alternative) |
| Tab navigation    | `Tab` forward, `Shift+Tab` backward                       |
| Select/Dropdown   | `Arrow` keys navigate, `Enter` selects, `Escape` closes   |

### 6.4 ARIA Labeling Conventions

```html
<!-- Landmark regions -->
<header role="banner">
<nav aria-label="Primary navigation">
<main id="main-content" role="main">
<aside aria-label="Sidebar navigation">
<footer role="contentinfo">

<!-- Dynamic content -->
<div aria-live="polite" aria-atomic="true">  <!-- status updates -->
<div role="alert">  <!-- errors requiring immediate attention -->
<div role="status">  <!-- success toasts -->

<!-- Icons -->
<svg aria-hidden="true" />  <!-- decorative icons -->
<svg role="img" aria-label="Upload" />  <!-- meaningful standalone icons -->

<!-- Progress -->
<div role="progressbar" aria-valuenow="{n}" aria-valuemin="0" aria-valuemax="100" aria-label="Upload progress" />

<!-- Tables -->
<table role="table">
  <thead role="rowgroup">
    <tr role="row">
      <th role="columnheader" scope="col">Filename</th>
    </tr>
  </thead>
  <tbody role="rowgroup">
    <tr role="row">
      <td role="cell">...</td>
    </tr>
  </tbody>
</table>
```

### 6.5 Screen Reader Considerations

- **Loading states:** Use `aria-busy="true"` on containers while fetching; `aria-live="polite"` region announces completion.
- **Risk score:** `aria-label="Risk score: {score} out of 100"` on the meter container.
- **Verdict badges:** Ensure text is readable (not just color). Icon + text is the pattern.
- **Copy buttons:** `aria-label="Copy API key for {name}"`. After copy, announce: `aria-live="polite"` region with "Copied to clipboard."
- **File upload:** Hidden native input. Drop zone has `role="button"`, `tabindex="0"`, `aria-label="Drag and drop APK file, or press Enter to browse"`.
- **Truncated text:** Add `title="{full text}"` attribute on truncated filenames.

### 6.6 Motion & Animation

- Use `prefers-reduced-motion` media query to disable or reduce animations:
  ```css
  @media (prefers-reduced-motion: reduce) {
    .animate-spin, .animate-pulse { animation: none; }
    .transition-all { transition: none; }
  }
  ```
- In Tailwind: apply `motion-safe:animate-spin` instead of bare `animate-spin` where possible.

---

*Design system authored by Product Designer (Paperclip) — March 2026.*
*For questions or revisions, open a subtask or mention @ProductDesigner in the relevant issue.*
