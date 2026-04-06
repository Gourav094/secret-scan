'use strict';

const fs = require('fs');
const path = require('path');
const { SEVERITY, SEVERITY_ORDER } = require('./constants');
const { isHighEntropy } = require('./entropy');
const { walkFiles } = require('./walker');
const { RULES } = require('./rules');

/**
 * Scan a single line against all rules.
 * Returns an array of findings for this line.
 */
function scanLine(line, lineNumber, filePath, relPath) {
  const findings = [];
  const matchedRanges = []; // Track which parts of the line matched specific rules

  for (const rule of RULES) {
    const match = rule.regex.exec(line);
    if (!match) continue;

    // Run validation if present
    if (rule.validate && !rule.validate(match)) continue;

    const secret = rule.extract ? rule.extract(match) : match[0];
    const col = match.index + 1;

    matchedRanges.push({ start: match.index, end: match.index + match[0].length });

    findings.push({
      file: relPath,
      absPath: filePath,
      line: lineNumber,
      col,
      severity: rule.severity,
      description: rule.description,
      ruleId: rule.id,
      secret,
    });
  }

  return findings;
}

/**
 * Check a line for high-entropy strings that weren't caught by specific rules.
 * Looks for quoted strings and assignment values.
 */
function scanLineEntropy(line, lineNumber, filePath, relPath, existingFindings) {
  const findings = [];

  // Look for quoted strings that might be secrets
  const stringPatterns = [
    /['"]([A-Za-z0-9+/=_-]{20,})['"]/g,
  ];

  for (const pattern of stringPatterns) {
    let match;
    while ((match = pattern.exec(line)) !== null) {
      const value = match[1];

      // Skip if already caught by a specific rule on this line
      const alreadyFound = existingFindings.some(
        (f) => f.line === lineNumber && Math.abs(f.col - 1 - match.index) < match[0].length
      );
      if (alreadyFound) continue;

      if (isHighEntropy(value)) {
        findings.push({
          file: relPath,
          absPath: filePath,
          line: lineNumber,
          col: match.index + 1,
          severity: SEVERITY.LOW,
          description: 'High-Entropy String',
          ruleId: 'high-entropy-string',
          secret: value,
        });
      }
    }
  }

  return findings;
}

/**
 * Scan a single file for secrets.
 */
function scanFile(filePath, rootDir) {
  const relPath = path.relative(rootDir, filePath);

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }

  // Quick check: skip files that look like binary
  if (content.includes('\0')) return [];

  const lines = content.split('\n');
  const fileFindings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNumber = i + 1;

    // Skip very long lines (likely minified / generated)
    if (line.length > 5000) continue;

    // Skip comment-only lines that look like documentation
    const trimmed = line.trim();
    if (trimmed.startsWith('//') && trimmed.includes('example')) continue;
    if (trimmed.startsWith('#') && trimmed.includes('example')) continue;

    const lineFindings = scanLine(line, lineNumber, filePath, relPath);
    fileFindings.push(...lineFindings);

    // Entropy scan for strings not caught by rules
    const entropyFindings = scanLineEntropy(line, lineNumber, filePath, relPath, lineFindings);
    fileFindings.push(...entropyFindings);
  }

  return fileFindings;
}

/**
 * Scan a directory for secrets.
 * Returns { findings, filesScanned, elapsed }.
 */
function scan(rootDir) {
  const start = Date.now();
  const files = walkFiles(rootDir);

  const allFindings = [];
  for (const filePath of files) {
    const findings = scanFile(filePath, rootDir);
    allFindings.push(...findings);
  }

  // Sort findings: by file, then line, then severity
  allFindings.sort((a, b) => {
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    if (a.line !== b.line) return a.line - b.line;
    return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
  });

  return {
    findings: allFindings,
    filesScanned: files.length,
    elapsed: Date.now() - start,
  };
}

module.exports = { scan, scanFile, scanLine };
