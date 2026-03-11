## Context

The Promptheus desktop app is an Electron + React application (React 19, Vite 5, Electron 40) that wraps the Promptheus CLI for security scanning. The current UI uses inline React styles with raw HTML elements -- no component library, no design system. The renderer code lives in `apps/desktop/src/App.jsx` (362 lines, single component). The app communicates with the CLI via IPC + child process spawning in `src/scan.js`.

## Goals / Non-Goals

**Goals:**
- Install shadcn/ui via its CLI with Tailwind CSS in the Electron Vite renderer
- Replace all UI elements with shadcn/ui components (Button, Input, RadioGroup, Card, Table, ScrollArea, Badge, etc.)
- Show real-time CLI log output in a terminal-style panel during scanning
- Ensure Cancel button reliably kills subprocess and resets state
- Maintain all existing functionality (3 scan modes, settings persistence, results display)

**Non-Goals:**
- Changing the IPC layer or scan.js subprocess management
- Adding new scan modes or CLI features
- Migrating to TypeScript (keep JSX)
- Dark mode (can be added later)
- Responsive/mobile layout (desktop-only app)

## Decisions

### 1. shadcn/ui with Tailwind CSS v4

**Decision**: Use shadcn CLI (`npx shadcn@latest init`) to scaffold components into `src/components/ui/`.

**Rationale**: shadcn/ui provides copy-paste components that are fully customizable, work with React 19, and have no runtime dependency. Components live in the project so we control them entirely.

**Alternative considered**: Radix UI directly -- more manual styling work. Ant Design / MUI -- heavier bundles, opinionated styling that conflicts with Tailwind.

### 2. Tailwind CSS via PostCSS in Vite

**Decision**: Add Tailwind CSS + PostCSS to the Vite renderer config. The existing `vite.renderer.config.mjs` will get PostCSS plugin configuration.

**Rationale**: Vite has first-class PostCSS support. Tailwind v4 works with the `@tailwindcss/vite` plugin or PostCSS. Since shadcn CLI sets this up, we follow its configuration.

### 3. Component decomposition

**Decision**: Break `App.jsx` into smaller components:
- `App.jsx` -- top-level layout and state
- `ScanModeSelector.jsx` -- mode radio group
- `ScanInputs.jsx` -- mode-specific input forms (URL, Agent, PR)
- `ScanControls.jsx` -- Run/Cancel buttons with loading state
- `LogViewer.jsx` -- terminal-style log output panel
- `ResultsTable.jsx` -- findings/vulnerability results display

**Rationale**: The current 362-line monolith is hard to maintain. Decomposition aligns with shadcn/ui patterns and makes each section independently testable.

### 4. Log viewer as terminal panel

**Decision**: Use a ScrollArea component with monospace font, dark background, auto-scroll to bottom behavior. Both stdout and stderr will be shown, color-coded. The panel is always visible during a scan.

**Rationale**: Users need to see what the CLI is doing in real-time. A terminal-like appearance matches the mental model of running a CLI tool.

### 5. Cancel button implementation

**Decision**: The Cancel button calls `window.electronAPI.cancelScan()` which sends SIGTERM to the child process. On cancel, the UI immediately resets `running` to false and shows a "Scan cancelled" message. The existing `currentScanKill` pattern in main.js is sufficient.

**Rationale**: The existing IPC mechanism works. The fix is ensuring the UI state resets properly on cancel and that the button is always accessible during a scan.

## Risks / Trade-offs

- **[Tailwind + Electron Vite compatibility]** The Vite renderer config uses Electron Forge's plugin-vite. Tailwind CSS needs to be configured in the renderer build only, not main/preload. Mitigation: Only modify `vite.renderer.config.mjs`.
- **[shadcn CLI in non-standard project]** The shadcn init expects a standard Vite/Next project. Mitigation: Run init with manual configuration, pointing to the correct paths (`src/components/ui`, `src/lib/utils`).
- **[Bundle size increase]** Tailwind + shadcn components add to the renderer bundle. Mitigation: Tailwind purges unused styles; shadcn components are tree-shakeable since they're source files.
