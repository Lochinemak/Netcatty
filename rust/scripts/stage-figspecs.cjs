#!/usr/bin/env node
/**
 * Stage the terminal autocomplete (Fig) specs as Tauri resources.
 *
 * Electron ships `node_modules/@withfig/autocomplete/build` (minus the heavy
 * aws / gcloud / az specs, see electron-builder.config.cjs) and
 * `electron/specs`. The Tauri backend reads the same files from
 * `<resource_dir>/figspecs/withfig` and `<resource_dir>/figspecs/local`
 * (`commands/terminal.rs`); this script copies them there.
 *
 * Usage: node rust/scripts/stage-figspecs.cjs [outDir]   (default: resources/figspecs)
 * The build workflow then maps `resources/figspecs/` to `figspecs/` in
 * `bundle.resources`.
 */
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const repo = path.resolve(__dirname, "..", "..");
const outDir = path.resolve(repo, process.argv[2] || path.join("resources", "figspecs"));
const withfigSrc = path.join(repo, "node_modules", "@withfig", "autocomplete", "build");
const localSrc = path.join(repo, "electron", "specs");

const EXCLUDED = new Set(["aws", "gcloud", "az"]);

function isExcluded(relative) {
  const first = relative.split(path.sep)[0].replace(/\.js$/, "");
  return EXCLUDED.has(first);
}

function copyTree(src, dest, filter) {
  let count = 0;
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const from = path.join(src, entry.name);
    const to = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      count += copyTree(from, to, (rel) => filter(path.join(entry.name, rel)));
      continue;
    }
    if (!entry.name.endsWith(".js") || !filter(entry.name)) continue;
    fs.mkdirSync(dest, { recursive: true });
    fs.copyFileSync(from, to);
    count += 1;
  }
  return count;
}

if (!fs.existsSync(withfigSrc)) {
  console.error(`stage-figspecs: ${withfigSrc} not found (run npm ci first)`);
  process.exit(1);
}
fs.rmSync(outDir, { recursive: true, force: true });
const withfig = copyTree(withfigSrc, path.join(outDir, "withfig"), (rel) => !isExcluded(rel));
const local = fs.existsSync(localSrc) ? copyTree(localSrc, path.join(outDir, "local"), () => true) : 0;
console.log(`stage-figspecs: ${withfig} @withfig specs, ${local} local specs → ${path.relative(repo, outDir)}`);
