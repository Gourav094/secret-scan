'use strict';

const fs = require('fs');
const path = require('path');
const { BINARY_EXTENSIONS, DEFAULT_IGNORE_DIRS, IGNORE_FILES, IGNORE_FILE_PATTERNS, MAX_FILE_SIZE } = require('./constants');
const { IgnoreMatcher } = require('./ignore');

/**
 * Recursively discover files to scan.
 * Returns an array of absolute file paths.
 */
function walkFiles(rootDir) {
  const matcher = new IgnoreMatcher(rootDir);

  // Load root .gitignore and .scanignore
  const rootGitignore = path.join(rootDir, '.gitignore');
  const rootScanignore = path.join(rootDir, '.scanignore');
  matcher.addFile(rootGitignore);
  matcher.addFile(rootScanignore);

  const files = [];

  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // Skip unreadable directories
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        // Skip default ignore dirs
        if (DEFAULT_IGNORE_DIRS.has(entry.name)) continue;

        // Skip if matched by ignore patterns
        if (matcher.isIgnored(fullPath, true)) continue;

        // Load nested .gitignore if present
        const nestedGitignore = path.join(fullPath, '.gitignore');
        if (fs.existsSync(nestedGitignore)) {
          matcher.addFile(nestedGitignore);
        }

        walk(fullPath);
      } else if (entry.isFile()) {
        // Skip binary files
        const ext = path.extname(entry.name).toLowerCase();
        if (BINARY_EXTENSIONS.has(ext)) continue;

        // Skip known non-secret files (lock files, etc.)
        if (IGNORE_FILES.has(entry.name)) continue;

        // Skip files matching ignore patterns (.env*, .example, etc.)
        if (IGNORE_FILE_PATTERNS.some((re) => re.test(entry.name))) continue;

        // Skip if matched by ignore patterns
        if (matcher.isIgnored(fullPath, false)) continue;

        // Skip files over size limit
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size > MAX_FILE_SIZE) continue;
          if (stat.size === 0) continue;
        } catch {
          continue;
        }

        files.push(fullPath);
      }
    }
  }

  walk(rootDir);
  return files;
}

module.exports = { walkFiles };
