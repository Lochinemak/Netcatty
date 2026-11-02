import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig, type Plugin } from 'vite';

// Custom plugin to suppress monaco-editor source map warnings
const suppressMonacoSourcemapWarning = () => ({
  name: 'suppress-monaco-sourcemap-warning',
  apply: 'serve' as const,
  configResolved(config: { logger: { warn: (msg: string, options?: { timestamp?: boolean }) => void } }) {
    const originalWarn = config.logger.warn;
    config.logger.warn = (msg: string, options?: { timestamp?: boolean }) => {
      // Suppress monaco-editor source map warnings
      if (msg.includes('monaco-editor') && msg.includes('source map')) return;
      if (msg.includes('loader.js.map')) return;
      originalWarn(msg, options);
    };
  },
});

const devContentSecurityPolicy = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'",
  "worker-src 'self' blob:",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self' data:",
  "connect-src 'self' data: blob: ws: wss: https: http://localhost:5173",
  "img-src 'self' data: https:",
].join("; ");

const devContentSecurityPolicyPlugin = () => ({
  name: 'dev-content-security-policy',
  apply: 'serve' as const,
  transformIndexHtml(html: string) {
    return html.replace(
      /content="default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self' data: blob: ws: wss: https:; img-src 'self' data: https:;"/,
      `content="${devContentSecurityPolicy}"`,
    );
  },
});

/**
 * Tauri CLI sets TAURI_ENV_PLATFORM for beforeDevCommand / beforeBuildCommand.
 * Everything below only kicks in then, so the Electron build is untouched.
 */
const isTauriEnv = Boolean(process.env.TAURI_ENV_PLATFORM);

// Tauri's IPC and asset protocols (custom schemes on macOS/Linux, http://*.localhost on Windows).
const tauriCspAdditions: Record<string, string[]> = {
  'default-src': ['tauri:', 'asset:', 'http://asset.localhost'],
  'connect-src': ['ipc:', 'http://ipc.localhost', 'tauri:', 'asset:', 'http://asset.localhost'],
  'img-src': ['asset:', 'http://asset.localhost'],
  'font-src': ['asset:', 'http://asset.localhost'],
};

/** Append sources to the named directives of a CSP string, keeping everything else verbatim. */
const addTauriCspSources = (csp: string, additions: Record<string, string[]> = tauriCspAdditions): string => {
  const directives = csp
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const [name, ...sources] = part.split(/\s+/);
      return { name, sources };
    });
  for (const [name, extra] of Object.entries(additions)) {
    const directive = directives.find((entry) => entry.name === name);
    if (!directive) continue;
    for (const source of extra) {
      if (!directive.sources.includes(source)) directive.sources.push(source);
    }
  }
  return directives.map(({ name, sources }) => [name, ...sources].join(' ')).join('; ');
};

/**
 * Runs in both `serve` and `build` (after the dev CSP plugin) and only under
 * Tauri: widens the <meta> CSP so invoke/listen and asset:// loads are allowed.
 */
const tauriContentSecurityPolicyPlugin = (): Plugin => ({
  name: 'tauri-content-security-policy',
  transformIndexHtml: {
    order: 'post',
    handler(html: string) {
      return html.replace(
        /(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]*)(")/,
        (_match, open: string, csp: string, close: string) => `${open}${addTauriCspSources(csp)}${close}`,
      );
    },
  },
});

/**
 * Stale pre-bundles return 504 after git pull / npm install. Vite retries the
 * module once optimize finishes — do not full-reload the Electron window.
 * Opening the lazy AI panel pulls `ai` / streamdown; a 504 there used to flash
 * the boot splash and wipe renderer state.
 */
const warnOnOutdatedOptimizeDep = (): Plugin => ({
  name: 'warn-on-outdated-optimize-dep',
  apply: 'serve',
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      res.on('finish', () => {
        if (
          res.statusCode === 504
          && req.url?.includes('/node_modules/.vite/deps/')
        ) {
          server.config.logger.warn(
            `[vite] stale optimize dep 504 for ${req.url} (not reloading the app)`,
          );
        }
      });
      next();
    });
  },
});

export default defineConfig(() => {
    return {
      base: "./",
      // Keep the Tauri CLI's own output visible; expose TAURI_ENV_* to the renderer.
      ...(isTauriEnv ? { clearScreen: false, envPrefix: ['VITE_', 'TAURI_ENV_*'] } : {}),
      server: {
        port: 5173,
        host: 'localhost',
        headers: {
          // Required for SharedArrayBuffer and WASM in some browsers
          'Cross-Origin-Opener-Policy': 'same-origin',
          // Use credentialless to allow loading cross-origin images (e.g. Google avatars)
          // while still enabling crossOriginIsolated.
          'Cross-Origin-Embedder-Policy': 'credentialless',
        },
        hmr: {
          overlay: true,
        },
      },
      build: {
        // The shared runtime is also required by Electron; convert it for browser builds.
        commonjsOptions: {
          include: [/node_modules/, /domain\/systemManager\/containerRuntime\.shared\.cjs$/, /domain\/plugin(?:RuntimePolicy|PermissionDescriptions|ThemePack|RemoteTreePolicy|ViewStylePolicy)\.cjs$/],
        },
        chunkSizeWarningLimit: 3000,
        target: 'esnext', // Required for top-level await in WASM modules
        sourcemap: false, // Disable source maps to avoid missing map file warnings
        // Optimize chunk splitting for faster initial load
        rollupOptions: {
          output: {
            manualChunks: {
              // Vendor chunks - rarely change, can be cached aggressively
              'vendor-radix': [
                '@radix-ui/react-collapsible',
                '@radix-ui/react-context-menu',
                '@radix-ui/react-dialog',
                '@radix-ui/react-popover',
                '@radix-ui/react-scroll-area',
                '@radix-ui/react-select',
                '@radix-ui/react-tabs',
              ],
              'vendor-xterm': [
                '@xterm/xterm',
                '@xterm/addon-fit',
                '@xterm/addon-image',
                '@xterm/addon-ligatures',
                '@xterm/addon-search',
                '@xterm/addon-serialize',
                '@xterm/addon-web-links',
                '@xterm/addon-webgl',
              ],
              'vendor-ai': [
                'ai',
                '@ai-sdk/openai',
                '@ai-sdk/anthropic',
                '@ai-sdk/google',
                'zod',
              ],
            },
          },
        },
      },
      plugins: [
        suppressMonacoSourcemapWarning(),
        devContentSecurityPolicyPlugin(),
        ...(isTauriEnv ? [tauriContentSecurityPolicyPlugin()] : []),
        warnOnOutdatedOptimizeDep(),
        tailwindcss(),
        react(),
      ],
      optimizeDeps: {
        include: [
          // Keep the renderer alias pre-bundled so dev serves ESM instead of raw CommonJS.
          '@/domain/systemManager/containerRuntime.shared.cjs',
          '@/domain/pluginRuntimePolicy.cjs',
          '@/domain/pluginPermissionDescriptions.cjs',
          '@/domain/pluginThemePack.cjs',
          '@/domain/pluginRemoteTreePolicy.cjs',
          '@/domain/pluginViewStylePolicy.cjs',
          'ai',
          '@ai-sdk/openai',
          '@ai-sdk/anthropic',
          '@ai-sdk/google',
          'streamdown',
          '@streamdown/cjk',
          '@streamdown/code',
          'zod',
        ],
      },
      resolve: {
        alias: {
          '@': path.resolve(__dirname, '.'),
          // The ligatures addon pulls lru-cache's node:diagnostics_channel import
          // into the renderer bundle. Stub it; the cache never publishes metrics.
          'node:diagnostics_channel': path.resolve(__dirname, 'infrastructure/shims/nodeDiagnosticsChannel.ts'),
          'diagnostics_channel': path.resolve(__dirname, 'infrastructure/shims/nodeDiagnosticsChannel.ts'),
        }
      }
    };
});
