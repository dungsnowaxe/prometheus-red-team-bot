## ADDED Requirements

### Requirement: Build produces installable artifact with electron-forge

The desktop app SHALL be buildable using **electron-forge** into a single installable artifact for at least one supported operating system (e.g. macOS .app/.dmg or Windows .exe/installer). The build process SHALL be documented.

#### Scenario: Developer runs build command

- **WHEN** a developer runs the documented electron-forge build command from the desktop app project (e.g. `apps/desktop/`)
- **THEN** the build SHALL produce an artifact (e.g. .app bundle or installer) that can be moved or installed on the target OS

#### Scenario: End user runs the built app

- **WHEN** an end user installs and launches the built application on the supported OS
- **THEN** the app SHALL start and function (run scan via CLI, show results) as specified for the desktop-app capability

### Requirement: Packaged app bundles Promptheus CLI

The packaged desktop app SHALL include a bundled Promptheus CLI executable suitable for the target OS/architecture so that end users are not required to install Promptheus (or Python) separately.

#### Scenario: End user runs a scan without installing CLI

- **WHEN** an end user installs and launches the built application on the supported OS without having Promptheus installed on PATH
- **THEN** the app SHALL still be able to run scans by invoking the bundled CLI executable

### Requirement: Build and run documentation

The project SHALL document how to build the desktop app with electron-forge and how to run it in development and after packaging. Documentation SHALL state that the packaged app includes a bundled Promptheus CLI, and SHALL describe any developer-only prerequisites for building that bundled CLI.

#### Scenario: New developer builds desktop app

- **WHEN** a developer follows the README or docs for `apps/desktop/`
- **THEN** they SHALL be able to install dependencies, run the app in development, and run the electron-forge build to produce a packaged artifact

#### Scenario: User runs desktop app

- **WHEN** a user wants to use the desktop app
- **THEN** the documentation SHALL state that the packaged app includes the Promptheus CLI and does not require a separate CLI installation
