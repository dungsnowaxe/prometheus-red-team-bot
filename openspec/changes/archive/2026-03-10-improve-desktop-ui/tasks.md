## 1. Tailwind CSS & shadcn/ui Setup

- [x] 1.1 Install Tailwind CSS and configure it in the Vite renderer build (add tailwindcss, postcss, autoprefixer or @tailwindcss/vite plugin to vite.renderer.config.mjs)
- [x] 1.2 Run `npx shadcn@latest init` in apps/desktop to scaffold shadcn/ui (creates components.json, src/lib/utils.js, updates index.css with Tailwind directives and CSS variables)
- [x] 1.3 Install required shadcn/ui components via CLI: button, input, label, radio-group, card, table, scroll-area, badge, checkbox
- [x] 1.4 Verify Tailwind + shadcn setup works by running `npm start` and confirming styles render correctly in the Electron window

## 2. Component Decomposition

- [x] 2.1 Create ScanModeSelector component using shadcn RadioGroup for mode selection (url, agent, pr)
- [x] 2.2 Create ScanInputs component with mode-specific forms using shadcn Input, Label, Checkbox, and Card
- [x] 2.3 Create LogViewer component with dark terminal-style panel using shadcn ScrollArea, monospace font, and auto-scroll behavior
- [x] 2.4 Create ScanControls component with shadcn Button (Run with loading state, Cancel with destructive variant)
- [x] 2.5 Create ResultsTable component using shadcn Table with Badge for severity, supporting both issue and vulnerability result formats

## 3. App Layout & Integration

- [x] 3.1 Rewrite App.jsx to compose new components, wrapping sections in shadcn Cards with proper layout and spacing
- [x] 3.2 Wire up all state management and IPC calls through the new component tree (maintain existing useState hooks and electronAPI calls)
- [x] 3.3 Implement log panel: show during scan with real-time stderr output, auto-scroll to bottom, clear on new scan, persist after completion

## 4. Cancel Button & Scan State

- [x] 4.1 Ensure Cancel button calls electronAPI.cancelScan() and immediately resets running state to false with "Scan cancelled" message in log
- [x] 4.2 Verify scan state management: idle (inputs enabled, Run enabled, Cancel hidden), running (inputs disabled, Run disabled+loading, Cancel visible), completed/error (inputs re-enabled, results shown)

## 5. Testing with agent-browser

- [x] 5.1 Launch the desktop app and use agent-browser to verify all shadcn/ui components render correctly (cards, buttons, inputs, radio groups)
- [x] 5.2 Test all three scan modes: fill in URL scan form, Agent scan form, and PR review form -- verify inputs work and mode switching is correct
- [x] 5.3 Run an actual scan and verify real-time log output appears in the terminal panel with auto-scroll
- [x] 5.4 Test the Cancel button during a running scan -- verify subprocess is killed, UI resets to idle, and "Scan cancelled" appears in log
- [x] 5.5 Verify results table renders correctly after scan completion with proper severity badges and all columns
