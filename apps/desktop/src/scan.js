/**
 * Spawn Promptheus CLI for URL scan, agent scan, or PR review (main process).
 * Resolves CLI path from override or bundled; captures stdout, stderr, exit code.
 */
import { spawn } from 'node:child_process';
import path from 'node:path';
import { app } from 'electron';

const isPackaged = app.isPackaged;
const platform = process.platform;
const isWindows = platform === 'win32';

// Event type constants for output streaming
export const OUTPUT_EVENTS = { STDOUT: 'stdout', STDERR: 'stderr' };

/**
 * Get the path to the Promptheus CLI executable.
 * @param {string | undefined} override - User override from store (or undefined to use default)
 * @returns {string} Executable path (command name for PATH or absolute path)
 */
export function getCliPath(override) {
  if (override && override.trim() !== '') {
    return override.trim();
  }
  if (isPackaged) {
    const resourcesPath = process.resourcesPath;
    const binName = isWindows ? 'promptheus.exe' : 'promptheus';
    // extraResource copies our "resources" folder into app Resources
    return path.join(resourcesPath, 'resources', 'bin', binName);
  }
  return 'promptheus';
}

/**
 * Parse stdout JSON and extract results.
 * @param {string} stdout - Raw stdout string
 * @param {(parsed: object) => Array | undefined} parseStdout - Optional custom parser
 * @returns {Array | undefined} Parsed results or undefined
 */
function parseStdoutOutput(stdout, parseStdout) {
  if (!stdout.trim()) return undefined;
  try {
    const parsed = JSON.parse(stdout);
    return parseStdout ? parseStdout(parsed) : parsed.results ?? parsed.issues;
  } catch {
    return undefined;
  }
}

/**
 * Run a subprocess and return a promise that resolves with { code, stdout, stderr } and an optional kill function.
 * @param {string} cliPath - CLI executable path
 * @param {string[]} args - CLI arguments
 * @param {(event: 'stdout'|'stderr', data: string) => void} onOutput - Optional callback for streamed output
 * @param {(parsed: object) => Array | undefined} parseStdout - Optional: given parsed JSON, return results array (e.g. results or issues)
 * @returns {{ promise: Promise<{ code: number, stdout: string, stderr: string, results?: Array }>, kill: () => void }}
 */
function runCliSubprocess(cliPath, args, onOutput, parseStdout) {
  let child = null;
  const promise = new Promise((resolve) => {
    child = spawn(cliPath, args, {
      shell: isWindows,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      const s = data.toString();
      stdout += s;
      onOutput?.(OUTPUT_EVENTS.STDOUT, s);
    });
    child.stderr?.on('data', (data) => {
      const s = data.toString();
      stderr += s;
      onOutput?.(OUTPUT_EVENTS.STDERR, s);
    });

    child.on('error', (err) => {
      resolve({
        code: -1,
        stdout: '',
        stderr: err.message || String(err),
        results: undefined,
      });
    });

    child.on('close', (code, signal) => {
      const exitCode = code ?? (signal ? -1 : 0);
      const results = exitCode === 0 ? parseStdoutOutput(stdout, parseStdout) : undefined;
      resolve({
        code: exitCode,
        stdout,
        stderr,
        results,
      });
    });
  });
  return {
    promise,
    kill: () => {
      if (child && child.kill) {
        child.kill('SIGTERM');
      }
    },
  };
}

/**
 * Run a legacy URL scan via the CLI.
 * @param {string} cliPath - Path to promptheus executable (or 'promptheus' for PATH)
 * @param {string} targetUrl - Target URL to scan
 * @param {(event: 'stdout'|'stderr', data: string) => void} onOutput - Optional callback for streamed output
 * @returns {Promise<{ code: number, stdout: string, stderr: string, results?: Array }>}
 */
export function runScan(cliPath, targetUrl, onOutput) {
  const args = ['scan', '--target-url', targetUrl, '--output', 'json'];
  const { promise } = runCliSubprocess(cliPath, args, onOutput, (p) => p.results ?? []);
  return promise;
}

/**
 * Run an agent-mode scan via the CLI.
 * @param {string} cliPath - Path to promptheus executable
 * @param {object} options - { targetPath, model?, dast?, dastUrl?, confirmLargeScan? }
 * @param {(event: 'stdout'|'stderr', data: string) => void} onOutput - Optional callback for streamed output
 * @returns {{ promise: Promise<{ code: number, stdout: string, stderr: string, results?: Array }>, kill: () => void }}
 */
export function runAgentScan(cliPath, options, onOutput) {
  const args = [
    'scan',
    '--mode', 'agent',
    '--target-path', options.targetPath,
    '--output', 'json',
  ];
  if (options.model) args.push('--model', options.model);
  if (options.dast) {
    args.push('--dast');
    if (options.dastUrl) args.push('--dast-url', options.dastUrl);
  }
  if (options.confirmLargeScan) args.push('--confirm-large-scan');
  return runCliSubprocess(cliPath, args, onOutput, (p) => p.issues ?? []);
}

/**
 * Run a PR review via the CLI.
 * @param {string} cliPath - Path to promptheus executable
 * @param {object} options - { path, range?: string, lastN?: number }
 * @param {(event: 'stdout'|'stderr', data: string) => void} onOutput - Optional callback for streamed output
 * @returns {{ promise: Promise<{ code: number, stdout: string, stderr: string, results?: Array }>, kill: () => void }}
 */
export function runPrReview(cliPath, options, onOutput) {
  const args = ['pr-review', '--path', options.path, '--output', 'json'];
  if (options.range != null && options.range.trim() !== '') {
    args.push('--range', options.range.trim());
  } else {
    const n = options.lastN != null && options.lastN > 0 ? options.lastN : 1;
    args.push('--last', String(n));
  }
  return runCliSubprocess(cliPath, args, onOutput, (p) => p.issues ?? []);
}
