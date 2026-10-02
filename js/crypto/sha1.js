/**
 * SHA-1 (Secure Hash Algorithm 1) - FIPS 180-1 / FIPS 180-4
 * Bit-accurate implementation with step-by-step trace generation
 */
import { rotl32, add32, bytesToWords32BE, words32ToBytesBE, bytesToHexString } from './utils.js';

// Initial hash values (constants)
export const SHA1_INIT = [
  0x67452301 >>> 0, // H0
  0xEFCDAB89 >>> 0, // H1
  0x98BADCFE >>> 0, // H2
  0x10325476 >>> 0, // H3
  0xC3D2E1F0 >>> 0  // H4
];

// Stage constants
export const SHA1_K = [
  0x5A827999 >>> 0, // 0 <= t <= 19 (Round 1: 2^30 * sqrt(2))
  0x6ED9EBA1 >>> 0, // 20 <= t <= 39 (Round 2: 2^30 * sqrt(3))
  0x8F1BBCDC >>> 0, // 40 <= t <= 59 (Round 3: 2^30 * sqrt(5))
  0xCA62C1D6 >>> 0  // 60 <= t <= 79 (Round 4: 2^30 * sqrt(10))
];

/**
 * Pads the input byte array according to FIPS 180-4 (512-bit block, 64-bit length in Big-Endian)
 */
export function padSHA1(inputBytes) {
  const origLen = inputBytes.length;
  const bitLen = BigInt(origLen) * 8n;
  const padded = [...inputBytes];

  // 1. Append '1' bit followed by seven '0' bits (0x80)
  padded.push(0x80);

  // 2. Pad with zeros until length % 64 === 56
  while (padded.length % 64 !== 56) {
    padded.push(0x00);
  }

  // 3. Append original length as 64-bit Big-Endian integer
  for (let i = 7; i >= 0; i--) {
    padded.push(Number((bitLen >> BigInt(i * 8)) & 0xFFn));
  }

  return new Uint8Array(padded);
}

/**
 * Computes SHA-1 with detailed step tracing
 */
export function sha1(inputBytes) {
  const paddedBytes = padSHA1(inputBytes);
  const blockCount = paddedBytes.length / 64;

  let H = [...SHA1_INIT];
  const traces = [];
  const blocks = [];

  for (let b = 0; b < blockCount; b++) {
    const blockBytes = paddedBytes.slice(b * 64, (b + 1) * 64);
    const M = bytesToWords32BE(Array.from(blockBytes));

    // Message schedule expansion: 80 words W_0 to W_79
    const W = new Uint32Array(80);
    const wExpansionSteps = [];

    for (let t = 0; t < 16; t++) {
      W[t] = M[t] >>> 0;
      wExpansionSteps.push({
        t,
        val: W[t],
        isDirect: true,
        formula: `W[${t}] = M[${t}] = 0x${W[t].toString(16).padStart(8, '0')}`
      });
    }

    for (let t = 16; t < 80; t++) {
      const xor = (W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]) >>> 0;
      W[t] = rotl32(xor, 1);
      wExpansionSteps.push({
        t,
        val: W[t],
        isDirect: false,
        xor,
        t3: W[t - 3],
        t8: W[t - 8],
        t14: W[t - 14],
        t16: W[t - 16],
        formula: `W[${t}] = (W[${t-3}] ^ W[${t-8}] ^ W[${t-14}] ^ W[${t-16}]) <<< 1`
      });
    }

    blocks.push({
      index: b,
      rawBytes: Array.from(blockBytes),
      words: M.map(w => w >>> 0),
      expandedSchedule: Array.from(W),
      wExpansionSteps
    });

    let [a, b_reg, c, d, e] = H;
    const startState = [a, b_reg, c, d, e];
    const blockSteps = [];

    for (let t = 0; t < 80; t++) {
      const prevA = a, prevB = b_reg, prevC = c, prevD = d, prevE = e;
      let f = 0, k = 0, fnName = '';

      if (t < 20) {
        // Stage 1: Ch(B, C, D) = (B & C) | (~B & D)
        f = ((b_reg & c) | ((~b_reg) & d)) >>> 0;
        k = SHA1_K[0];
        fnName = 'Ch(Choice)';
      } else if (t < 40) {
        // Stage 2: Parity(B, C, D) = B ^ C ^ D
        f = (b_reg ^ c ^ d) >>> 0;
        k = SHA1_K[1];
        fnName = 'Parity(XOR)';
      } else if (t < 60) {
        // Stage 3: Maj(B, C, D) = (B & C) | (B & D) | (C & D)
        f = ((b_reg & c) | (b_reg & d) | (c & d)) >>> 0;
        k = SHA1_K[2];
        fnName = 'Maj(Majority)';
      } else {
        // Stage 4: Parity(B, C, D) = B ^ C ^ D
        f = (b_reg ^ c ^ d) >>> 0;
        k = SHA1_K[3];
        fnName = 'Parity(XOR)';
      }

      const rotA5 = rotl32(a, 5);
      const wt = W[t];
      const temp = add32(rotA5, f, e, k, wt);
      const rotB30 = rotl32(b_reg, 30);

      // Register shift: E = D, D = C, C = rotl(B, 30), B = A, A = temp
      e = prevD;
      d = prevC;
      c = rotB30;
      b_reg = prevA;
      a = temp;

      blockSteps.push({
        step: t,
        stage: Math.floor(t / 20) + 1,
        fnName,
        fVal: f >>> 0,
        kVal: k >>> 0,
        wVal: wt >>> 0,
        rotA5: rotA5 >>> 0,
        rotB30: rotB30 >>> 0,
        temp: temp >>> 0,
        stateBefore: { A: prevA, B: prevB, C: prevC, D: prevD, E: prevE },
        stateAfter: { A: a, B: b_reg, C: c, D: d, E: e },
        formula: `TEMP = (A <<< 5) + ${fnName.split('(')[0]}(B,C,D) + E + W[${t}] + K[${Math.floor(t/20)}]`
      });
    }

    // Add block results to state vector
    H[0] = add32(H[0], a);
    H[1] = add32(H[1], b_reg);
    H[2] = add32(H[2], c);
    H[3] = add32(H[3], d);
    H[4] = add32(H[4], e);

    traces.push({
      blockIndex: b,
      startState,
      endState: [a, b_reg, c, d, e],
      accumulated: [...H],
      steps: blockSteps
    });
  }

  // Format digest (Big-Endian words to bytes)
  const digestBytes = words32ToBytesBE(H);
  const digestHex = bytesToHexString(digestBytes);

  return {
    algorithm: 'SHA-1',
    digestHex,
    digestBytes,
    paddedBytes: Array.from(paddedBytes),
    originalLength: inputBytes.length,
    paddedLength: paddedBytes.length,
    blockCount,
    blocks,
    traces,
    initialState: [...SHA1_INIT],
    finalRegisters: [...H]
  };
}
