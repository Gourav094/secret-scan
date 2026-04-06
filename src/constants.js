'use strict';

const SEVERITY = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
});

const SEVERITY_ORDER = Object.freeze({
  [SEVERITY.CRITICAL]: 0,
  [SEVERITY.HIGH]: 1,
  [SEVERITY.MEDIUM]: 2,
  [SEVERITY.LOW]: 3,
});

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp', '.avif',
  '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.flac', '.wav', '.ogg', '.webm',
  '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.zst',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.exe', '.dll', '.so', '.dylib', '.o', '.a', '.lib',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.pyc', '.pyo', '.class', '.jar', '.war',
  '.sqlite', '.db', '.sqlite3',
  '.lock', '.wasm',
]);

const DEFAULT_IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'vendor',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  '__pycache__',
  '.venv',
  'venv',
  '.tox',
  'coverage',
  '.nyc_output',
  '.cache',
  '.parcel-cache',
  '.turbo',
]);

const IGNORE_FILES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'composer.lock',
  'Gemfile.lock',
  'Pipfile.lock',
  'poetry.lock',
  'Cargo.lock',
  'go.sum',
  'flake.lock',
  'packages.lock.json',
]);

// File patterns to skip — env files (should be in .gitignore), example configs
const IGNORE_FILE_PATTERNS = [
  /^\.env(\..*)?$/,        // .env, .env.local, .env.example, .env.production, etc.
  /\.example$/,            // anything.example
  /\.sample$/,             // anything.sample
  /\.template$/,           // anything.template
];

const MAX_FILE_SIZE = 1024 * 1024; // 1 MB

module.exports = {
  SEVERITY,
  SEVERITY_ORDER,
  BINARY_EXTENSIONS,
  DEFAULT_IGNORE_DIRS,
  IGNORE_FILES,
  IGNORE_FILE_PATTERNS,
  MAX_FILE_SIZE,
};
