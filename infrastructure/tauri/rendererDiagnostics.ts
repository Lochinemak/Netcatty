/**
 * Forwards renderer failures (uncaught errors, unhandled promise rejections,
 * `console.error`) to the Rust backend so they appear next to the backend
 * logs in the terminal running `tauri:dev`. The Tauri webview has no
 * attached console by default, which made a blank window hard to diagnose.
 *
 * Fire-and-forget: a failing invoke is swallowed (and never re-reported) so
 * diagnostics can never recurse or break the page.
 */
import { invoke, isTauri } from './tauriApi';

let installed = false;
let reporting = false;

const describe = (value: unknown): string => {
  if (value instanceof Error) return `${value.name}: ${value.message}${value.stack ? `\n${value.stack}` : ''}`;
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
};

const report = (level: 'error' | 'warn' | 'info', message: string, source: string): void => {
  if (reporting) return;
  reporting = true;
  try {
    void invoke('app_renderer_log', { level, message, source }).catch(() => undefined);
  } finally {
    reporting = false;
  }
};

export function installRendererDiagnostics(): boolean {
  if (installed || typeof window === 'undefined' || !isTauri()) return false;
  installed = true;

  window.addEventListener('error', (event) => {
    const where = event.filename ? ` (${event.filename}:${event.lineno}:${event.colno})` : '';
    report('error', `${describe(event.error ?? event.message)}${where}`, 'window.onerror');
  });
  window.addEventListener('unhandledrejection', (event) => {
    report('error', describe(event.reason), 'unhandledrejection');
  });

  const originalError = console.error.bind(console);
  console.error = (...args: unknown[]) => {
    originalError(...args);
    report('error', args.map(describe).join(' '), 'console.error');
  };

  const tauriKeys = Object.keys((window as unknown as { __TAURI__?: object }).__TAURI__ ?? {}).join(',');
  report('info', `renderer booted (${window.location.href}) tauri=[${tauriKeys}]`, 'bootstrap');
  return true;
}
