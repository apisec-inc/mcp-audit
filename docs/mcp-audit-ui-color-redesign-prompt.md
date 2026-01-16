# APIsec MCP Audit: UI Color Scheme Redesign

## Overview

Redesign the scan results UI to reduce visual noise and create clear hierarchy. Currently every section uses a different bright color, making nothing stand out. The goal is a clean, professional look where only critical items demand attention.

---

## Design Principle

**Color signals meaning, not decoration.**

| Color | Meaning | Use For |
|-------|---------|---------|
| Red | Critical, immediate action | Secrets detected |
| Orange | Warning, attention needed | Findings & Remediation |
| Gray/Neutral | Informational | Everything else |
| Green | Action/CTA | Export button |

---

## Current State (Problems)

- 6 different saturated colors (red, cyan, purple, blue, orange, green)
- Every section screams for attention
- Stat card numbers are multicolored (red 2, blue 12, green 6)
- No visual hierarchy — user doesn't know where to look first
- Looks like a rainbow dashboard

---

## Target State

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  Scan Results                                                       │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ ⚠️  6 SECRETS DETECTED - IMMEDIATE ACTION REQUIRED        ▼  │ │  ← RED background
│  │                                                               │ │
│  │ 1 critical · 3 high · 2 medium                                │ │
│  │ Rotate ALL exposed credentials before continuing              │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│                                                                     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │
│  │   18    │ │   12    │ │    6    │ │    2    │ │    4    │      │  ← ALL BLACK numbers
│  │  MCPs   │ │  Known  │ │ Unknown │ │Critical │ │ Models  │      │     Gray borders
│  │  Found  │ │  MCPs   │ │  MCPs   │ │  Risk   │ │         │      │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘      │
│                                                                     │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ 📁 MCP DISCOVERY RESULTS - 18 server(s) found             ▼  │ │  ← NEUTRAL (gray/white)
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ 🔗 ENDPOINTS DISCOVERED - 2 connection(s)                 ▼  │ │  ← NEUTRAL
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ 🤖 AI MODELS - 4 model(s) detected                        ▼  │ │  ← NEUTRAL
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ 🔍 FINDINGS & REMEDIATION - 2 critical, 2 high            ▼  │ │  ← ORANGE background
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ 📤 EXPORT & SHARE                                         ▼  │ │  ← NEUTRAL or subtle green
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│                                                                     │
│  [Scan Another Org]                                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Color Specifications

### Section Headers

| Section | Background | Text | Border |
|---------|------------|------|--------|
| **Secrets Detected** | Red (#FEE2E2) | Dark Red (#991B1B) | Red (#DC2626) |
| **Findings & Remediation** | Orange (#FFF7ED) | Dark Orange (#9A3412) | Orange (#EA580C) |
| **MCP Discovery** | White (#FFFFFF) | Dark Gray (#374151) | Gray (#E5E7EB) |
| **Endpoints** | White (#FFFFFF) | Dark Gray (#374151) | Gray (#E5E7EB) |
| **AI Models** | White (#FFFFFF) | Dark Gray (#374151) | Gray (#E5E7EB) |
| **Export & Share** | Light Gray (#F9FAFB) | Dark Gray (#374151) | Gray (#E5E7EB) |

### Stat Cards

| Element | Style |
|---------|-------|
| Number | Black (#111827), bold, large (32-40px) |
| Label | Gray (#6B7280), small (12-14px), uppercase |
| Border | Light gray (#E5E7EB), 1px |
| Background | White (#FFFFFF) |
| Hover | Subtle shadow |

**Remove all colored numbers.** All stat card numbers should be black/dark gray regardless of what they represent.

### Severity Badges (Inside Sections)

When showing severity inline (like "1 critical · 3 high · 2 medium"):

| Severity | Text Color | Background (optional pill) |
|----------|------------|---------------------------|
| Critical | Red (#DC2626) | Red (#FEE2E2) |
| High | Orange (#EA580C) | Orange (#FFF7ED) |
| Medium | Yellow (#CA8A04) | Yellow (#FEF9C3) |
| Low | Green (#16A34A) | Green (#DCFCE7) |

These are small badges/pills, not entire section backgrounds.

---

## Specific Changes

### 1. Secrets Section (Keep Red)
- Background: Light red (#FEE2E2)
- Left border: 4px solid red (#DC2626)
- Icon: Warning triangle ⚠️
- This is the only section that should be red
- Severity breakdown (critical/high/medium) uses colored text, not colored backgrounds

### 2. Stat Cards (Make Neutral)
```css
.stat-card {
  background: white;
  border: 1px solid #E5E7EB;
  border-radius: 8px;
}

.stat-card .number {
  color: #111827;  /* Always black */
  font-size: 32px;
  font-weight: 700;
}

.stat-card .label {
  color: #6B7280;  /* Always gray */
  font-size: 12px;
  text-transform: uppercase;
}
```

**Remove:** All the colored numbers (blue 12, red 2, green 6, etc.)

### 3. MCP Discovery (Make Neutral)
- Change from: Blue background
- Change to: White background, gray border
- Keep the folder icon 📁

### 4. Endpoints Discovered (Make Neutral)
- Change from: Cyan/teal background
- Change to: White background, gray border
- Keep the link icon 🔗

### 5. AI Models (Make Neutral)
- Change from: Purple background
- Change to: White background, gray border
- Keep the robot icon 🤖

### 6. Findings & Remediation (Keep Warning Color)
- Background: Light orange (#FFF7ED)
- Left border: 4px solid orange (#EA580C)
- This needs attention but isn't as urgent as secrets

### 7. Export & Share (Make Neutral or Subtle)
- Change from: Bright green background
- Change to: Light gray (#F9FAFB) or white with gray border
- Green should only be used for the action button inside, not the entire section

---

## Expanded Section Styling

When a section is expanded (clicked), maintain the same color scheme:

| Section | Expanded Background |
|---------|---------------------|
| Secrets | Light red (#FEE2E2) |
| Findings | Light orange (#FFF7ED) |
| All others | White (#FFFFFF) |

---

## Typography

| Element | Font | Size | Weight | Color |
|---------|------|------|--------|-------|
| Section title | System/Inter | 14px | 600 (semibold) | Varies by section |
| Stat number | System/Inter | 32-40px | 700 (bold) | #111827 (black) |
| Stat label | System/Inter | 12px | 500 (medium) | #6B7280 (gray) |
| Body text | System/Inter | 14px | 400 (normal) | #374151 (dark gray) |

---

## Visual Hierarchy (Priority Order)

1. **Secrets (Red)** — User sees this first, takes action
2. **Findings (Orange)** — User sees this second
3. **Stats** — Quick overview at a glance
4. **Other sections (Gray)** — Details when needed
5. **Export** — Final action

---

## Don'ts

- ❌ Don't use more than 2 colored section backgrounds (red + orange)
- ❌ Don't color stat card numbers
- ❌ Don't use purple, cyan, or blue for section backgrounds
- ❌ Don't make every section compete for attention
- ❌ Don't use bright saturated colors for informational content

---

## Do's

- ✅ Use red only for critical (secrets)
- ✅ Use orange only for warnings (findings)
- ✅ Use gray/white/neutral for everything else
- ✅ Use color sparingly for badges and inline severity indicators
- ✅ Keep stat card numbers black
- ✅ Use subtle borders and shadows instead of colored backgrounds

---

## Reference Designs

For visual inspiration, look at:
- **Snyk** dashboard — mostly gray, red only for vulnerabilities
- **GitHub Security** tab — neutral with small colored badges
- **Vercel** dashboard — clean, minimal color
- **Linear** — almost no color, very professional

---

## Definition of Done

- [ ] Secrets section is red (only red section)
- [ ] Findings section is orange (only orange section)
- [ ] MCP Discovery, Endpoints, AI Models are neutral (white/gray)
- [ ] Export section is neutral (not bright green)
- [ ] All stat card numbers are black (no colored numbers)
- [ ] Stat card borders are light gray
- [ ] Severity badges inside sections use appropriate colors
- [ ] Overall look is clean and professional
- [ ] Only 2 sections visually "pop" (Secrets, Findings)
