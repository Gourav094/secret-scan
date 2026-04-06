'use strict';

const { SEVERITY } = require('./constants');

/**
 * Validate that a matched secret value is not a placeholder.
 * Returns false for common placeholders, template vars, and test values.
 */
function isNotPlaceholder(value) {
  const lower = value.toLowerCase();

  // Template variables
  if (/\$\{.+\}/.test(value)) return false;
  if (/\{\{.+\}\}/.test(value)) return false;
  if (/<[a-z_-]+>/i.test(value)) return false;

  // Common placeholder words
  const placeholders = [
    'changeme', 'change_me', 'change-me',
    'your_', 'your-', 'yourapikey', 'your_api_key',
    'xxxx', 'xxx', 'sample', 'example', 'test',
    'placeholder', 'dummy', 'fake', 'todo',
    'replace', 'insert', 'enter_', 'put_',
    'fill_in', 'update_this',
  ];
  for (const p of placeholders) {
    if (lower.includes(p)) return false;
  }

  // All same char repeated
  if (/^(.)\1+$/.test(value)) return false;

  // Very short values
  if (value.length < 8) return false;

  return true;
}

/**
 * Build the rules array. Each rule has:
 *   id, description, severity, regex, extract (optional function to get the secret value)
 */
const RULES = [
  // ═══════════════════════════════════════════════
  // Private Keys
  // ═══════════════════════════════════════════════
  {
    id: 'private-key-rsa',
    description: 'RSA Private Key',
    severity: SEVERITY.CRITICAL,
    regex: /-----BEGIN RSA PRIVATE KEY-----/,
  },
  {
    id: 'private-key-openssh',
    description: 'OpenSSH Private Key',
    severity: SEVERITY.CRITICAL,
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/,
  },
  {
    id: 'private-key-dsa',
    description: 'DSA Private Key',
    severity: SEVERITY.CRITICAL,
    regex: /-----BEGIN DSA PRIVATE KEY-----/,
  },
  {
    id: 'private-key-ec',
    description: 'EC Private Key',
    severity: SEVERITY.CRITICAL,
    regex: /-----BEGIN EC PRIVATE KEY-----/,
  },
  {
    id: 'private-key-pgp',
    description: 'PGP Private Key Block',
    severity: SEVERITY.CRITICAL,
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
  },
  {
    id: 'private-key-encrypted',
    description: 'Encrypted Private Key',
    severity: SEVERITY.HIGH,
    regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----/,
  },
  {
    id: 'private-key-generic',
    description: 'Generic Private Key',
    severity: SEVERITY.CRITICAL,
    regex: /-----BEGIN PRIVATE KEY-----/,
  },

  // ═══════════════════════════════════════════════
  // AWS
  // ═══════════════════════════════════════════════
  {
    id: 'aws-access-key',
    description: 'AWS Access Key ID',
    severity: SEVERITY.HIGH,
    regex: /(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])/,
    extract: (m) => m[1],
  },
  {
    id: 'aws-secret-key',
    description: 'AWS Secret Access Key',
    severity: SEVERITY.CRITICAL,
    regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i,
    extract: (m) => m[1],
    validate: (m) => isNotPlaceholder(m[1]),
  },
  {
    id: 'aws-mws-key',
    description: 'AWS MWS Key',
    severity: SEVERITY.HIGH,
    regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/,
  },

  // ═══════════════════════════════════════════════
  // GCP
  // ═══════════════════════════════════════════════
  {
    id: 'gcp-api-key',
    description: 'Google Cloud API Key',
    severity: SEVERITY.HIGH,
    regex: /AIza[0-9A-Za-z_-]{35}/,
  },
  {
    id: 'gcp-service-account',
    description: 'GCP Service Account Key',
    severity: SEVERITY.CRITICAL,
    regex: /"type"\s*:\s*"service_account"/,
  },

  // ═══════════════════════════════════════════════
  // Azure
  // ═══════════════════════════════════════════════
  {
    id: 'azure-storage-key',
    description: 'Azure Storage Account Key',
    severity: SEVERITY.HIGH,
    regex: /AccountKey\s*=\s*([A-Za-z0-9+/=]{88})/,
    extract: (m) => m[1],
  },
  {
    id: 'azure-connection-string',
    description: 'Azure Connection String',
    severity: SEVERITY.HIGH,
    regex: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+/,
  },

  // ═══════════════════════════════════════════════
  // GitHub
  // ═══════════════════════════════════════════════
  {
    id: 'github-pat-fine',
    description: 'GitHub Fine-Grained PAT',
    severity: SEVERITY.HIGH,
    regex: /github_pat_[0-9a-zA-Z_]{82}/,
  },
  {
    id: 'github-pat-classic',
    description: 'GitHub Classic PAT',
    severity: SEVERITY.HIGH,
    regex: /ghp_[0-9a-zA-Z]{36}/,
  },
  {
    id: 'github-oauth',
    description: 'GitHub OAuth Access Token',
    severity: SEVERITY.HIGH,
    regex: /gho_[0-9a-zA-Z]{36}/,
  },
  {
    id: 'github-app-token',
    description: 'GitHub App Token',
    severity: SEVERITY.HIGH,
    regex: /(?:ghu|ghs)_[0-9a-zA-Z]{36}/,
  },
  {
    id: 'github-refresh-token',
    description: 'GitHub Refresh Token',
    severity: SEVERITY.HIGH,
    regex: /ghr_[0-9a-zA-Z]{36}/,
  },

  // ═══════════════════════════════════════════════
  // npm / PyPI
  // ═══════════════════════════════════════════════
  {
    id: 'npm-token',
    description: 'npm Access Token',
    severity: SEVERITY.HIGH,
    regex: /npm_[0-9a-zA-Z]{36}/,
  },
  {
    id: 'pypi-token',
    description: 'PyPI API Token',
    severity: SEVERITY.HIGH,
    regex: /pypi-[A-Za-z0-9_-]{50,}/,
  },

  // ═══════════════════════════════════════════════
  // Stripe
  // ═══════════════════════════════════════════════
  {
    id: 'stripe-secret-key',
    description: 'Stripe Secret Key',
    severity: SEVERITY.CRITICAL,
    regex: /sk_live_[0-9a-zA-Z]{24,}/,
  },
  {
    id: 'stripe-publishable-key',
    description: 'Stripe Publishable Key',
    severity: SEVERITY.MEDIUM,
    regex: /pk_live_[0-9a-zA-Z]{24,}/,
  },
  {
    id: 'stripe-restricted-key',
    description: 'Stripe Restricted Key',
    severity: SEVERITY.HIGH,
    regex: /rk_live_[0-9a-zA-Z]{24,}/,
  },

  // ═══════════════════════════════════════════════
  // Twilio
  // ═══════════════════════════════════════════════
  {
    id: 'twilio-api-key',
    description: 'Twilio API Key',
    severity: SEVERITY.HIGH,
    regex: /SK[0-9a-fA-F]{32}/,
  },
  {
    id: 'twilio-account-sid',
    description: 'Twilio Account SID',
    severity: SEVERITY.MEDIUM,
    regex: /AC[0-9a-fA-F]{32}/,
  },

  // ═══════════════════════════════════════════════
  // SendGrid
  // ═══════════════════════════════════════════════
  {
    id: 'sendgrid-api-key',
    description: 'SendGrid API Key',
    severity: SEVERITY.HIGH,
    regex: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/,
  },

  // ═══════════════════════════════════════════════
  // Mailgun
  // ═══════════════════════════════════════════════
  {
    id: 'mailgun-api-key',
    description: 'Mailgun API Key',
    severity: SEVERITY.HIGH,
    regex: /key-[0-9a-zA-Z]{32}/,
  },

  // ═══════════════════════════════════════════════
  // Slack
  // ═══════════════════════════════════════════════
  {
    id: 'slack-token',
    description: 'Slack Token',
    severity: SEVERITY.HIGH,
    regex: /xox[bporas]-[0-9]{10,13}-[0-9a-zA-Z-]{20,}/,
  },
  {
    id: 'slack-webhook',
    description: 'Slack Webhook URL',
    severity: SEVERITY.MEDIUM,
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24}/,
  },

  // ═══════════════════════════════════════════════
  // OpenAI
  // ═══════════════════════════════════════════════
  {
    id: 'openai-api-key',
    description: 'OpenAI API Key',
    severity: SEVERITY.HIGH,
    regex: /sk-[0-9a-zA-Z]{20}T3BlbkFJ[0-9a-zA-Z]{20}/,
  },
  {
    id: 'openai-api-key-proj',
    description: 'OpenAI Project API Key',
    severity: SEVERITY.HIGH,
    regex: /sk-proj-[0-9a-zA-Z_-]{40,}/,
  },

  // ═══════════════════════════════════════════════
  // JWT / Bearer
  // ═══════════════════════════════════════════════
  {
    id: 'jwt-token',
    description: 'JSON Web Token',
    severity: SEVERITY.MEDIUM,
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  },
  {
    id: 'bearer-token',
    description: 'Bearer Token (hardcoded)',
    severity: SEVERITY.MEDIUM,
    regex: /['"]Bearer\s+(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})['"]/,
    extract: (m) => m[1],
  },

  // ═══════════════════════════════════════════════
  // Database Connection Strings
  // ═══════════════════════════════════════════════
  {
    id: 'mongodb-uri',
    description: 'MongoDB Connection String',
    severity: SEVERITY.HIGH,
    regex: /mongodb(?:\+srv)?:\/\/[^\s'"<>]+:[^\s'"<>]+@[^\s'"<>]+/,
    validate: (m) => {
      const val = m[0];
      return !val.includes('<') && !val.includes('${') && !val.includes('{{');
    },
  },
  {
    id: 'postgres-uri',
    description: 'PostgreSQL Connection String',
    severity: SEVERITY.HIGH,
    regex: /postgres(?:ql)?:\/\/[^\s'"<>]+:[^\s'"<>]+@[^\s'"<>]+/,
    validate: (m) => {
      const val = m[0];
      return !val.includes('<') && !val.includes('${') && !val.includes('{{');
    },
  },
  {
    id: 'mysql-uri',
    description: 'MySQL Connection String',
    severity: SEVERITY.HIGH,
    regex: /mysql:\/\/[^\s'"<>]+:[^\s'"<>]+@[^\s'"<>]+/,
    validate: (m) => {
      const val = m[0];
      return !val.includes('<') && !val.includes('${') && !val.includes('{{');
    },
  },
  {
    id: 'redis-uri',
    description: 'Redis Connection String',
    severity: SEVERITY.HIGH,
    regex: /redis(?:s)?:\/\/[^\s'"<>]*:[^\s'"<>]+@[^\s'"<>]+/,
    validate: (m) => {
      const val = m[0];
      return !val.includes('<') && !val.includes('${') && !val.includes('{{');
    },
  },

  // ═══════════════════════════════════════════════
  // Generic Patterns (password=, secret=, etc.)
  // ═══════════════════════════════════════════════
  {
    id: 'generic-password',
    description: 'Hardcoded Password',
    severity: SEVERITY.MEDIUM,
    regex: /(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]/i,
    extract: (m) => m[1],
    validate: (m) => isNotPlaceholder(m[1]),
  },
  {
    id: 'generic-secret',
    description: 'Hardcoded Secret',
    severity: SEVERITY.MEDIUM,
    regex: /(?:secret|secret_key|secretkey)\s*[=:]\s*['"]([^'"]{8,})['"]/i,
    extract: (m) => m[1],
    validate: (m) => isNotPlaceholder(m[1]),
  },
  {
    id: 'generic-api-key',
    description: 'Hardcoded API Key',
    severity: SEVERITY.MEDIUM,
    regex: /(?:api_key|apikey|api-key)\s*[=:]\s*['"]([^'"]{8,})['"]/i,
    extract: (m) => m[1],
    validate: (m) => isNotPlaceholder(m[1]),
  },
  {
    id: 'generic-token',
    description: 'Hardcoded Token',
    severity: SEVERITY.MEDIUM,
    regex: /(?:access_token|auth_token|token)\s*[=:]\s*['"]([^'"]{16,})['"]/i,
    extract: (m) => m[1],
    validate: (m) => isNotPlaceholder(m[1]),
  },
  {
    id: 'generic-private-key-var',
    description: 'Hardcoded Private Key Value',
    severity: SEVERITY.MEDIUM,
    regex: /(?:private_key|privatekey|private-key)\s*[=:]\s*['"]([^'"]{16,})['"]/i,
    extract: (m) => m[1],
    validate: (m) => isNotPlaceholder(m[1]),
  },
  {
    id: 'generic-credentials',
    description: 'Hardcoded Credentials',
    severity: SEVERITY.MEDIUM,
    regex: /(?:credentials|credential|creds)\s*[=:]\s*['"]([^'"]{8,})['"]/i,
    extract: (m) => m[1],
    validate: (m) => isNotPlaceholder(m[1]),
  },
  {
    id: 'generic-auth-header',
    description: 'Hardcoded Authorization Header',
    severity: SEVERITY.MEDIUM,
    regex: /['"]Authorization['"]\s*:\s*['"](?:Basic|Bearer)\s+([A-Za-z0-9+/=_-]{20,})['"]/i,
    extract: (m) => m[1],
    validate: (m) => isNotPlaceholder(m[1]),
  },
];

module.exports = { RULES, isNotPlaceholder };
