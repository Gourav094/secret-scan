#!/usr/bin/env node
'use strict';

const path = require('path');
const { scan } = require('../src/scanner');
const { formatText, formatJSON } = require('../src/formatter');

// Parse CLI arguments
const args = process.argv.slice(2);
const flags = {
  json: false,
  dir: process.cwd(),
  help: false,
};

for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case '--json':
      flags.json = true;
      break;
    case '--dir':
      if (args[i + 1]) {
        flags.dir = path.resolve(args[++i]);
      } else {
        console.error('Error: --dir requires a path argument');
        process.exit(2);
      }
      break;
    case '--help':
    case '-h':
      flags.help = true;
      break;
    default:
      console.error(`Unknown option: ${args[i]}`);
      process.exit(2);
  }
}

if (flags.help) {
  console.log(`
  secret-scan - Scan for hardcoded secrets in your codebase

  Usage:
    npx secret-scan [options]

  Options:
    --dir <path>   Directory to scan (default: current directory)
    --json         Output results as JSON
    -h, --help     Show this help message

  Ignore files:
    Create a .scanignore file (same syntax as .gitignore) to exclude
    files or directories from scanning. .gitignore is also respected.

  Exit codes:
    0  No secrets found
    1  Secrets found
    2  Invalid arguments
`);
  process.exit(0);
}

// Run the scan
const { findings, filesScanned, elapsed } = scan(flags.dir);

// Output results
if (flags.json) {
  console.log(formatJSON(findings, filesScanned, elapsed));
} else {
  console.log(formatText(findings, filesScanned, elapsed));
}

// Exit with appropriate code
process.exit(findings.length > 0 ? 1 : 0);
