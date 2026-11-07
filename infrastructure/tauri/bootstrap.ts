/**
 * Side-effect module: imported first by `index.tsx` so the Tauri bridge is on
 * `window.netcatty` before any other renderer module evaluates. (ES imports
 * are hoisted, so a plain function call in `index.tsx` would run too late.)
 * Under Electron `isTauri()` is false and this is a no-op.
 */
import { installTauriBridge } from './installTauriBridge';
import { installClipboardPolyfill } from './clipboardPolyfill';
import { installDragRegions } from './dragRegion';
import { installRendererDiagnostics } from './rendererDiagnostics';

installRendererDiagnostics();
installClipboardPolyfill();
installTauriBridge();
installDragRegions();
