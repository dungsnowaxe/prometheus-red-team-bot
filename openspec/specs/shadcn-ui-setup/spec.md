## ADDED Requirements

### Requirement: Tailwind CSS configured in renderer
The Electron Vite renderer build SHALL include Tailwind CSS configured via PostCSS or the Tailwind Vite plugin, so that utility classes are available in all renderer components.

#### Scenario: Tailwind classes applied in renderer
- **WHEN** a React component uses Tailwind utility classes (e.g., `className="bg-white p-4"`)
- **THEN** the styles are correctly applied in the rendered Electron window

#### Scenario: Tailwind does not affect main or preload
- **WHEN** the main process or preload script is built
- **THEN** no Tailwind processing is applied to those builds

### Requirement: shadcn/ui components installed via CLI
The project SHALL use the shadcn CLI (`npx shadcn@latest init` and `npx shadcn@latest add <component>`) to install UI components into `src/components/ui/`.

#### Scenario: shadcn init creates project scaffold
- **WHEN** `npx shadcn@latest init` is run in the desktop app directory
- **THEN** it creates `components.json`, `src/components/ui/` directory, `src/lib/utils.js` with the `cn()` helper, and configures Tailwind CSS

#### Scenario: Adding a shadcn component
- **WHEN** `npx shadcn@latest add button` is run
- **THEN** a `src/components/ui/button.jsx` file is created with the Button component ready to import

### Requirement: All UI elements use shadcn/ui components
The app SHALL replace all inline-styled HTML elements with shadcn/ui equivalents: Button, Input, RadioGroup, Card, Table, ScrollArea, Badge, Label, and Checkbox.

#### Scenario: Buttons use shadcn Button
- **WHEN** the Run or Cancel action is rendered
- **THEN** it uses the shadcn `<Button>` component with appropriate variant (default, destructive)

#### Scenario: Form inputs use shadcn Input and Label
- **WHEN** a text input field is rendered (URL, path, commit range, etc.)
- **THEN** it uses shadcn `<Input>` with an associated `<Label>` component

#### Scenario: Mode selection uses shadcn RadioGroup
- **WHEN** the scan mode selector is rendered
- **THEN** it uses shadcn `<RadioGroup>` and `<RadioGroupItem>` components

#### Scenario: Results use shadcn Table
- **WHEN** scan results are displayed
- **THEN** they use shadcn `<Table>`, `<TableHeader>`, `<TableRow>`, `<TableCell>` components

#### Scenario: Layout sections use shadcn Card
- **WHEN** the settings, scan configuration, or results sections are rendered
- **THEN** each section is wrapped in a shadcn `<Card>` with `<CardHeader>` and `<CardContent>`
