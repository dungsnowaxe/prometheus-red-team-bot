## Why

The Promptheus desktop app currently uses raw inline-styled HTML elements with no component library, resulting in a basic, utilitarian UI. Adopting shadcn/ui will provide a polished, accessible, and consistent design system. Additionally, the CLI log output during scanning needs better visibility and the Cancel button must reliably terminate running scans.

## What Changes

- Replace all inline-styled HTML elements (buttons, inputs, radio groups, tables, text areas) with shadcn/ui components installed via the shadcn CLI
- Add Tailwind CSS as the styling foundation required by shadcn/ui
- Redesign the scan output area to display real-time CLI log output in a scrollable, styled terminal-like panel during scanning
- Ensure the Cancel button properly kills the running subprocess and resets UI state
- Improve overall layout with cards, proper spacing, and visual hierarchy

## Capabilities

### New Capabilities
- `shadcn-ui-setup`: Install and configure shadcn/ui with Tailwind CSS in the Electron Vite + React renderer
- `scan-log-viewer`: Real-time CLI log output display during scanning with auto-scroll, styled as a terminal panel
- `scan-controls`: Reliable scan execution and cancellation with proper state management and visual feedback

### Modified Capabilities

## Impact

- **Dependencies**: Adds tailwindcss, postcss, autoprefixer, shadcn/ui component packages, class-variance-authority, clsx, tailwind-merge, lucide-react
- **Code**: Complete rewrite of `App.jsx` to use shadcn/ui components; new `index.css` with Tailwind directives; new `components/ui/` directory for shadcn components; `lib/utils.ts` for cn() helper
- **Build**: Vite renderer config may need PostCSS/Tailwind plugin configuration
- **No breaking changes to IPC or CLI integration** - backend communication layer remains the same
