'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Parse a .gitignore-style file into an array of pattern objects.
 * Supports: comments (#), negation (!), directory markers (/), wildcards (*, **).
 */
function parseIgnoreFile(filePath) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }

  const patterns = [];
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    let pattern = line;
    let negated = false;

    if (pattern.startsWith('!')) {
      negated = true;
      pattern = pattern.slice(1);
    }

    // Remove trailing spaces (unless escaped)
    pattern = pattern.replace(/(?<!\\)\s+$/, '');

    const dirOnly = pattern.endsWith('/');
    if (dirOnly) {
      pattern = pattern.slice(0, -1);
    }

    patterns.push({ pattern, negated, dirOnly });
  }

  return patterns;
}

/**
 * Convert a gitignore glob pattern to a RegExp.
 */
function patternToRegex(pattern) {
  // If pattern doesn't contain /, it matches any path component
  const anchored = pattern.includes('/');

  let regex = '';
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i];

    if (ch === '*' && pattern[i + 1] === '*') {
      // **/ or ** matches everything
      if (pattern[i + 2] === '/') {
        regex += '(?:.+/)?';
        i += 3;
      } else {
        regex += '.*';
        i += 2;
      }
    } else if (ch === '*') {
      regex += '[^/]*';
      i++;
    } else if (ch === '?') {
      regex += '[^/]';
      i++;
    } else if (ch === '[') {
      const close = pattern.indexOf(']', i + 1);
      if (close !== -1) {
        regex += pattern.slice(i, close + 1);
        i = close + 1;
      } else {
        regex += '\\[';
        i++;
      }
    } else if ('.+^${}()|\\'.includes(ch)) {
      regex += '\\' + ch;
      i++;
    } else {
      regex += ch;
      i++;
    }
  }

  if (anchored) {
    return new RegExp('^' + regex + '(?:/|$)');
  }
  return new RegExp('(?:^|/)' + regex + '(?:/|$)');
}

class IgnoreMatcher {
  constructor(baseDir) {
    this.baseDir = baseDir;
    this.rules = []; // { regex, negated, dirOnly, base }
  }

  /**
   * Load patterns from a file (e.g. .gitignore, .scanignore).
   * `base` is the directory the ignore file lives in (for relative matching).
   */
  addFile(filePath) {
    const base = path.dirname(filePath);
    const patterns = parseIgnoreFile(filePath);
    for (const { pattern, negated, dirOnly } of patterns) {
      this.rules.push({
        regex: patternToRegex(pattern),
        negated,
        dirOnly,
        base,
      });
    }
  }

  /**
   * Add raw patterns (e.g. from defaults).
   */
  addPatterns(patterns, base) {
    for (const pattern of patterns) {
      this.rules.push({
        regex: patternToRegex(pattern),
        negated: false,
        dirOnly: false,
        base: base || this.baseDir,
      });
    }
  }

  /**
   * Check if a path should be ignored.
   * `filePath` is absolute. `isDirectory` indicates if it's a directory.
   */
  isIgnored(filePath, isDirectory = false) {
    const relPath = path.relative(this.baseDir, filePath);
    if (!relPath || relPath.startsWith('..')) return false;

    let ignored = false;

    for (const rule of this.rules) {
      if (rule.dirOnly && !isDirectory) continue;

      const testPath = path.relative(rule.base, filePath);
      if (testPath.startsWith('..')) continue;

      if (rule.regex.test(testPath)) {
        ignored = !rule.negated;
      }
    }

    return ignored;
  }
}

module.exports = { IgnoreMatcher, parseIgnoreFile };
