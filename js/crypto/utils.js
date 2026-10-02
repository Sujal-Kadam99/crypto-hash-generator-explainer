/**
 * CryptoAgentic Utility Functions
 * Bit-accurate operations, 32-bit and 64-bit modular math, rotations, formatters.
 */

// 32-bit Bitwise Operations & Rotations
export function rotr32(n, b) {
  n >>>= 0;
  b %= 32;
  return ((n >>> b) | (n << (32 - b))) >>> 0;
}

export function rotl32(n, b) {
  n >>>= 0;
  b %= 32;
  return ((n << b) | (n >>> (32 - b))) >>> 0;
}

export function shr32(n, b) {
  return (n >>> b) >>> 0;
}

export function add32(...args) {
  let sum = 0;
  for (let i = 0; i < args.length; i++) {
    sum = (sum + (args[i] >>> 0)) >>> 0;
  }
  return sum >>> 0;
}

// 64-bit (BigInt) Operations & Rotations for SHA-512
export const MASK_64 = 0xFFFFFFFFFFFFFFFFn;

export function rotr64(n, b) {
  n = BigInt(n) & MASK_64;
  b = BigInt(b) % 64n;
  return ((n >> b) | (n << (64n - b))) & MASK_64;
}

export function rotl64(n, b) {
  n = BigInt(n) & MASK_64;
  b = BigInt(b) % 64n;
  return ((n << b) | (n >> (64n - b))) & MASK_64;
}

export function shr64(n, b) {
  n = BigInt(n) & MASK_64;
  b = BigInt(b);
  return (n >> b) & MASK_64;
}

export function add64(...args) {
  let sum = 0n;
  for (let i = 0; i < args.length; i++) {
    sum = (sum + (BigInt(args[i]) & MASK_64)) & MASK_64;
  }
  return sum;
}

// String & Byte Conversion
export function stringToUtf8Bytes(str) {
  const encoder = new TextEncoder();
  return Array.from(encoder.encode(str));
}

export function bytesToHexString(bytes) {
  return bytes.map(b => (b >>> 0).toString(16).padStart(2, '0')).join('');
}

export function hexStringToBytes(hex) {
  const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
  const bytes = [];
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes.push(parseInt(cleanHex.substr(i, 2), 16) || 0);
  }
  return bytes;
}

export function byteToBinaryString(b) {
  return (b >>> 0).toString(2).padStart(8, '0');
}

export function u32ToHex(val) {
  return (val >>> 0).toString(16).padStart(8, '0');
}

export function u32ToBinary(val) {
  return (val >>> 0).toString(2).padStart(32, '0');
}

export function u64ToHex(val) {
  return (BigInt(val) & MASK_64).toString(16).padStart(16, '0');
}

export function u64ToBinary(val) {
  return (BigInt(val) & MASK_64).toString(2).padStart(64, '0');
}

// Endianness Helpers
export function bytesToWords32BE(bytes) {
  const words = [];
  for (let i = 0; i < bytes.length; i += 4) {
    const w = ((bytes[i] || 0) << 24) |
              ((bytes[i + 1] || 0) << 16) |
              ((bytes[i + 2] || 0) << 8) |
              (bytes[i + 3] || 0);
    words.push(w >>> 0);
  }
  return words;
}

export function bytesToWords32LE(bytes) {
  const words = [];
  for (let i = 0; i < bytes.length; i += 4) {
    const w = (bytes[i] || 0) |
              ((bytes[i + 1] || 0) << 8) |
              ((bytes[i + 2] || 0) << 16) |
              ((bytes[i + 3] || 0) << 24);
    words.push(w >>> 0);
  }
  return words;
}

export function words32ToBytesBE(words) {
  const bytes = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i] >>> 0;
    bytes.push((w >>> 24) & 0xFF);
    bytes.push((w >>> 16) & 0xFF);
    bytes.push((w >>> 8) & 0xFF);
    bytes.push(w & 0xFF);
  }
  return bytes;
}

export function words32ToBytesLE(words) {
  const bytes = [];
  for (let i = 0; i < words.length; i++) {
    const w = words[i] >>> 0;
    bytes.push(w & 0xFF);
    bytes.push((w >>> 8) & 0xFF);
    bytes.push((w >>> 16) & 0xFF);
    bytes.push((w >>> 24) & 0xFF);
  }
  return bytes;
}

export function bytesToWords64BE(bytes) {
  const words = [];
  for (let i = 0; i < bytes.length; i += 8) {
    let w = 0n;
    for (let j = 0; j < 8; j++) {
      w = (w << 8n) | BigInt(bytes[i + j] || 0);
    }
    words.push(w & MASK_64);
  }
  return words;
}

export function words64ToBytesBE(words) {
  const bytes = [];
  for (let i = 0; i < words.length; i++) {
    const w = BigInt(words[i]) & MASK_64;
    for (let j = 7; j >= 0; j--) {
      bytes.push(Number((w >> BigInt(j * 8)) & 0xFFn));
    }
  }
  return bytes;
}

// Hamming Distance & Bit Difference Calculator
export function hammingDistance32(a, b) {
  let diff = ((a ^ b) >>> 0);
  let count = 0;
  while (diff) {
    count += diff & 1;
    diff >>>= 1;
  }
  return count;
}

export function hammingDistance64(a, b) {
  let diff = (BigInt(a) ^ BigInt(b)) & MASK_64;
  let count = 0;
  while (diff > 0n) {
    if (diff & 1n) count++;
    diff >>= 1n;
  }
  return count;
}

// Format binary string with spaces every 4 or 8 bits for readability
export function formatBinarySpaced(binStr, groupSize = 8) {
  const chunks = [];
  for (let i = 0; i < binStr.length; i += groupSize) {
    chunks.push(binStr.substr(i, groupSize));
  }
  return chunks.join(' ');
}
