'use strict';

/**
 * Calculate Shannon entropy of a string.
 * Higher entropy suggests more randomness (potential secret).
 */
function shannonEntropy(str) {
  if (str.length === 0) return 0;

  const freq = new Map();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const HEX_RE = /^[0-9a-fA-F]+$/;
const BASE64_RE = /^[A-Za-z0-9+/=_-]+$/;

/**
 * Check if a token appears to be a high-entropy secret.
 * Returns true if the string has sufficient entropy to be suspicious.
 */
function isHighEntropy(str) {
  if (str.length < 16) return false;
  if (str.length > 256) return false;

  const entropy = shannonEntropy(str);

  // Hex strings need lower threshold (charset of 16)
  if (HEX_RE.test(str)) {
    return entropy > 3.0;
  }

  // Base64/alphanumeric strings
  if (BASE64_RE.test(str)) {
    return entropy > 4.0;
  }

  return entropy > 4.5;
}

module.exports = { shannonEntropy, isHighEntropy };
