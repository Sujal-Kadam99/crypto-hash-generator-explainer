/**
 * SHA-256 (Secure Hash Algorithm 256) - FIPS 180-4
 * Bit-accurate implementation with step-by-step trace generation
 */
import { rotr32, shr32, add32, bytesToWords32BE, words32ToBytesBE, bytesToHexString } from './utils.js';

// Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
export const SHA256_INIT = [
  0x6a09e667 >>> 0, // sqrt(2)
  0xbb67ae85 >>> 0, // sqrt(3)
  0x3c6ef372 >>> 0, // sqrt(5)
  0xa54ff53a >>> 0, // sqrt(7)
  0x510e527f >>> 0, // sqrt(11)
  0x9b05688c >>> 0, // sqrt(13)
  0x1f83d9ab >>> 0, // sqrt(17)
  0x5be0cd19 >>> 0  // sqrt(19)
];

// Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
export const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
].map(k => k >>> 0);

// SHA-256 Helper functions
export function sigma0_256(x) {
  return (rotr32(x, 7) ^ rotr32(x, 18) ^ shr32(x, 3)) >>> 0;
}

export function sigma1_256(x) {
  return (rotr32(x, 17) ^ rotr32(x, 19) ^ shr32(x, 10)) >>> 0;
}

export function bigSigma0_256(x) {
  return (rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)) >>> 0;
}

export function bigSigma1_256(x) {
  return (rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)) >>> 0;
}

export function ch_256(x, y, z) {
  return ((x & y) ^ ((~x) & z)) >>> 0;
}

export function maj_256(x, y, z) {
  return ((x & y) ^ (x & z) ^ (y & z)) >>> 0;
}

/**
 * Pads the input byte array according to FIPS 180-4 (512-bit block, 64-bit length in Big-Endian)
 */
export function padSHA256(inputBytes) {
  const origLen = inputBytes.length;
  const bitLen = BigInt(origLen) * 8n;
  const padded = [...inputBytes];

  padded.push(0x80);

  while (padded.length % 64 !== 56) {
    padded.push(0x00);
  }

  for (let i = 7; i >= 0; i--) {
    padded.push(Number((bitLen >> BigInt(i * 8)) & 0xFFn));
  }

  return new Uint8Array(padded);
}

/**
 * Computes SHA-256 with step-by-step tracing
 */
export function sha256(inputBytes) {
  const paddedBytes = padSHA256(inputBytes);
  const blockCount = paddedBytes.length / 64;

  let H = [...SHA256_INIT];
  const traces = [];
  const blocks = [];

  for (let b = 0; b < blockCount; b++) {
    const blockBytes = paddedBytes.slice(b * 64, (b + 1) * 64);
    const M = bytesToWords32BE(Array.from(blockBytes));

    // Message schedule expansion: 64 words W_0 to W_63
    const W = new Uint32Array(64);
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

    for (let t = 16; t < 64; t++) {
      const s0 = sigma0_256(W[t - 15]);
      const s1 = sigma1_256(W[t - 2]);
      W[t] = add32(W[t - 16], s0, W[t - 7], s1);
      wExpansionSteps.push({
        t,
        val: W[t],
        isDirect: false,
        s0,
        s1,
        wMinus16: W[t - 16],
        wMinus7: W[t - 7],
        formula: `W[${t}] = W[${t-16}] + σ0(W[${t-15}]) + W[${t-7}] + σ1(W[${t-2}])`
      });
    }

    blocks.push({
      index: b,
      rawBytes: Array.from(blockBytes),
      words: M.map(w => w >>> 0),
      expandedSchedule: Array.from(W),
      wExpansionSteps
    });

    let [a, b_reg, c, d, e, f, g, h] = H;
    const startState = [a, b_reg, c, d, e, f, g, h];
    const blockSteps = [];

    for (let t = 0; t < 64; t++) {
      const prevA = a, prevB = b_reg, prevC = c, prevD = d;
      const prevE = e, prevF = f, prevG = g, prevH = h;

      const s1 = bigSigma1_256(e);
      const ch = ch_256(e, f, g);
      const kt = SHA256_K[t];
      const wt = W[t];
      const t1 = add32(h, s1, ch, kt, wt);

      const s0 = bigSigma0_256(a);
      const maj = maj_256(a, b_reg, c);
      const t2 = add32(s0, maj);

      // Register updates
      h = prevG;
      g = prevF;
      f = prevE;
      e = add32(prevD, t1);
      d = prevC;
      c = prevB;
      b_reg = prevA;
      a = add32(t1, t2);

      blockSteps.push({
        step: t,
        kVal: kt >>> 0,
        wVal: wt >>> 0,
        s1: s1 >>> 0,
        ch: ch >>> 0,
        t1: t1 >>> 0,
        s0: s0 >>> 0,
        maj: maj >>> 0,
        t2: t2 >>> 0,
        stateBefore: { A: prevA, B: prevB, C: prevC, D: prevD, E: prevE, F: prevF, G: prevG, H: prevH },
        stateAfter: { A: a, B: b_reg, C: c, D: d, E: e, F: f, G: g, H: h },
        formulaT1: `T1 = H + Σ1(E) + Ch(E,F,G) + K[${t}] + W[${t}]`,
        formulaT2: `T2 = Σ0(A) + Maj(A,B,C)`
      });
    }

    // Add block results to state vector
    H[0] = add32(H[0], a);
    H[1] = add32(H[1], b_reg);
    H[2] = add32(H[2], c);
    H[3] = add32(H[3], d);
    H[4] = add32(H[4], e);
    H[5] = add32(H[5], f);
    H[6] = add32(H[6], g);
    H[7] = add32(H[7], h);

    traces.push({
      blockIndex: b,
      startState,
      endState: [a, b_reg, c, d, e, f, g, h],
      accumulated: [...H],
      steps: blockSteps
    });
  }

  // Format digest
  const digestBytes = words32ToBytesBE(H);
  const digestHex = bytesToHexString(digestBytes);

  return {
    algorithm: 'SHA-256',
    digestHex,
    digestBytes,
    paddedBytes: Array.from(paddedBytes),
    originalLength: inputBytes.length,
    paddedLength: paddedBytes.length,
    blockCount,
    blocks,
    traces,
    initialState: [...SHA256_INIT],
    finalRegisters: [...H]
  };
}
