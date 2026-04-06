'use strict';

const { SEVERITY, SEVERITY_ORDER } = require('./constants');

// Color helpers using ANSI escape codes (no dependencies)
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const WHITE = '\x1b[37m';
const BG_RED = '\x1b[41m';
const MAGENTA = '\x1b[35m';
const UNDERLINE = '\x1b[4m';

const SEVERITY_COLORS = {
  [SEVERITY.CRITICAL]: `${BG_RED}${WHITE}${BOLD}`,
  [SEVERITY.HIGH]: `${RED}${BOLD}`,
  [SEVERITY.MEDIUM]: `${YELLOW}`,
  [SEVERITY.LOW]: `${DIM}`,
};

const SEVERITY_LABELS = {
  [SEVERITY.CRITICAL]: 'critical',
  [SEVERITY.HIGH]: 'high    ',
  [SEVERITY.MEDIUM]: 'medium  ',
  [SEVERITY.LOW]: 'low     ',
};

/**
 * Redact a secret value for display.
 */
function redact(secret) {
  if (!secret || secret.length < 8) return '***';
  const showChars = Math.min(4, Math.floor(secret.length / 4));
  return secret.slice(0, showChars) + '…' + '*'.repeat(Math.min(8, secret.length - showChars));
}

/**
 * Format findings in ESLint-style for terminal output.
 */
function formatText(findings, filesScanned, elapsed) {
  if (findings.length === 0) {
    return `\n  ${BOLD}✔ No secrets found${RESET} ${DIM}(scanned ${filesScanned} files in ${elapsed}ms)${RESET}\n`;
  }

  const lines = [''];

  // Group by file
  const byFile = new Map();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }

  for (const [file, fileFindings] of byFile) {
    lines.push(`  ${UNDERLINE}${file}${RESET}`);

    for (const f of fileFindings) {
      const loc = `${f.line}:${f.col}`.padEnd(10);
      const sevColor = SEVERITY_COLORS[f.severity];
      const sevLabel = SEVERITY_LABELS[f.severity];
      const desc = f.description.padEnd(35);
      const redacted = redact(f.secret);

      lines.push(
        `     ${DIM}${loc}${RESET}${sevColor}${sevLabel}${RESET}  ${desc} ${DIM}${f.ruleId}${RESET}  ${MAGENTA}${redacted}${RESET}`
      );
    }

    lines.push('');
  }

  const fileCount = byFile.size;
  const summary = `  ${RED}${BOLD}✖ ${findings.length} secret${findings.length === 1 ? '' : 's'} found in ${fileCount} file${fileCount === 1 ? '' : 's'}${RESET} ${DIM}(scanned ${filesScanned} files in ${elapsed}ms)${RESET}`;
  lines.push(summary);
  lines.push('');

  // Severity breakdown
  const counts = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }
  const breakdown = Object.entries(counts)
    .sort((a, b) => SEVERITY_ORDER[a[0]] - SEVERITY_ORDER[b[0]])
    .map(([sev, count]) => `${SEVERITY_COLORS[sev]}${count} ${sev}${RESET}`)
    .join(DIM + ', ' + RESET);
  lines.push(`  ${breakdown}`);
  lines.push('');

  return lines.join('\n');
}

/**
 * Format findings as JSON.
 */
function formatJSON(findings, filesScanned, elapsed) {
  return JSON.stringify(
    {
      summary: {
        secretsFound: findings.length,
        filesScanned,
        elapsedMs: elapsed,
      },
      findings: findings.map((f) => ({
        file: f.file,
        line: f.line,
        col: f.col,
        severity: f.severity,
        description: f.description,
        ruleId: f.ruleId,
        secret: redact(f.secret),
      })),
    },
    null,
    2
  );
}

module.exports = { formatText, formatJSON, redact };
