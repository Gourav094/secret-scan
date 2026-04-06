# secret-scan

A zero-dependency Node.js CLI tool that scans your codebase for hardcoded secrets, API keys, tokens, and passwords. CI-friendly — exits with code 1 if secrets are found.

## Features

- **40+ detection rules** covering all major providers and patterns
- **Zero external dependencies** — uses only Node.js built-ins
- **ESLint-style output** with colored severity levels and redacted secrets
- **JSON output mode** for CI/CD pipelines
- **Respects `.gitignore` and `.scanignore`** including nested `.gitignore` files
- **False positive reduction** — rejects placeholders like `changeme`, `<token>`, `${VAR}`
- **High-entropy catch-all** — Shannon entropy analysis detects random strings
- **Fast** — synchronous I/O, skips binary files, 1 MB file size limit

## What It Detects

| Category | Examples |
|----------|----------|
| **Cloud Providers** | AWS access keys, secret keys, MWS keys, GCP API keys, GCP service accounts, Azure storage keys, Azure connection strings |
| **Code Platforms** | GitHub PATs (classic + fine-grained), GitHub OAuth/App/Refresh tokens, npm tokens, PyPI tokens |
| **Payment & SaaS** | Stripe secret/publishable/restricted keys, Twilio API keys/Account SIDs, SendGrid, Mailgun, Slack tokens/webhooks |
| **AI Services** | OpenAI API keys (standard + project) |
| **Private Keys** | RSA, OpenSSH, DSA, EC, PGP, generic, encrypted |
| **Tokens** | JWT, Bearer tokens |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis connection strings with embedded passwords |
| **Generic Patterns** | `password=`, `secret=`, `api_key=`, `token=`, `credentials=`, `Authorization` headers |
| **High-Entropy Strings** | Shannon entropy analysis on unmatched quoted strings |

## Installation

No installation needed. Just clone and run:

```bash
git clone <repo-url>
cd secret-scan
```

Or use it in any project:

```bash
# Copy the secret-scan directory into your project, then:
node path/to/secret-scan/bin/secret-scan.js
```

## Usage

```bash
# Scan current directory
npm run scan

# Scan a specific directory
node bin/secret-scan.js --dir ./src

# JSON output (for CI pipelines)
node bin/secret-scan.js --json

# Show help
node bin/secret-scan.js --help
```

> **Note:** When using `npm run scan`, pass flags after `--` so npm forwards them to the script:
> ```bash
> npm run scan -- --json
> npm run scan -- --dir ./src
> ```
> Or call the script directly to avoid this:
> ```bash
> node bin/secret-scan.js --json
> ```

## Output Format

### Terminal (default)

```
  src/config.js
     12:5   critical  RSA Private Key           private-key-rsa      ----…********
     45:10  high      AWS Access Key ID         aws-access-key       AKIA…********

  ✖ 2 secrets found in 1 file (scanned 156 files in 45ms)

  2 critical, 1 high
```

### JSON (`--json`)

```json
{
  "summary": {
    "secretsFound": 2,
    "filesScanned": 156,
    "elapsedMs": 45
  },
  "findings": [
    {
      "file": "src/config.js",
      "line": 12,
      "col": 5,
      "severity": "critical",
      "description": "RSA Private Key",
      "ruleId": "private-key-rsa",
      "secret": "----…********"
    }
  ]
}
```

## Severity Levels

| Level | Description |
|-------|-------------|
| **critical** | Private keys, AWS secret keys, Stripe secret keys |
| **high** | API keys, access tokens, database connection strings |
| **medium** | Generic password/secret/token assignments, JWTs, publishable keys |
| **low** | High-entropy strings (potential secrets detected by entropy analysis) |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No secrets found |
| `1` | Secrets found |
| `2` | Invalid arguments |

## Ignoring Files

The scanner respects both `.gitignore` and `.scanignore` files. The `.scanignore` file uses the same syntax as `.gitignore`:

```gitignore
# .scanignore

# Ignore test fixtures with intentional fake secrets
test/fixtures/

# Ignore generated files
*.min.js
*.generated.js

# Ignore specific files
config.example.js
```

A `.scanignore.example` file is included for reference.

### Automatically Skipped

- Directories: `node_modules`, `.git`, `dist`, `build`, `vendor`, `__pycache__`, and more
- Binary files: images, videos, archives, fonts, compiled files, etc.
- Files larger than 1 MB
- Empty files

## False Positive Handling

The scanner filters out common placeholders and non-secret values:

- Template variables: `${VAR}`, `{{var}}`, `<placeholder>`
- Common words: `changeme`, `your_api_key`, `example`, `test`, `placeholder`, `dummy`
- Repeated characters: `aaaaaaaaaa`
- Short values: anything under 8 characters

Specific rules always take priority over generic pattern matches.

## Project Structure

```
secret-scan/
├── package.json          # Project config, npm run scan
├── bin/
│   └── secret-scan.js    # CLI entry point
├── src/
│   ├── constants.js      # Binary extensions, default ignores, severity levels
│   ├── entropy.js        # Shannon entropy for high-entropy string detection
│   ├── ignore.js         # .gitignore / .scanignore parser
│   ├── walker.js         # Recursive file discovery
│   ├── rules.js          # 40+ detection regex patterns
│   ├── scanner.js        # Orchestrator: walk → scan → collect
│   └── formatter.js      # Terminal + JSON output formatting
├── .scanignore           # Files to exclude from scanning
└── .scanignore.example   # Example ignore file
```

## Requirements

- Node.js >= 16.0.0
- No external dependencies

## License

MIT
