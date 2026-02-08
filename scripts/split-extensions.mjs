#!/usr/bin/env node

import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

const srcPath = join(root, "apps", "ext", "data", "extensions.json");
const outDir = join(root, "apps", "web", "public", "extensions");

// Ensure output directory exists
mkdirSync(outDir, { recursive: true });

// Read source data
const extensions = JSON.parse(readFileSync(srcPath, "utf-8"));
const ids = Object.keys(extensions);

// Write one file per extension: {id}.json containing the report object
for (const id of ids) {
  const outPath = join(outDir, `${id}.json`);
  writeFileSync(outPath, JSON.stringify(extensions[id], null, 2) + "\n");
}

// Write index.json containing an array of all extension IDs
writeFileSync(join(outDir, "index.json"), JSON.stringify(ids, null, 2) + "\n");

console.log(`Wrote ${ids.length} extension files + index.json to ${outDir}`);
