/**
 * SHA-512 (Secure Hash Algorithm 512) - FIPS 180-4
 * Bit-accurate 64-bit implementation using BigInt with step-by-step trace generation
 */
import { rotr64, shr64, add64, bytesToWords64BE, words64ToBytesBE, bytesToHexString, MASK_64 } from './utils.js';

// Initial hash values (first 64 bits of fractional parts of square roots of first 8 primes)
export const SHA512_INIT = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n
];

// 80 64-bit round constants (first 64 bits of cube roots of first 80 primes)
export const SHA512_K = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
  0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
  0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n
];

// SHA-512 Helper functions (64-bit BigInt)
export function sigma0_512(x) {
  x = BigInt(x) & MASK_64;
  return (rotr64(x, 1n) ^ rotr64(x, 8n) ^ shr64(x, 7n)) & MASK_64;
}

export function sigma1_512(x) {
  x = BigInt(x) & MASK_64;
  return (rotr64(x, 19n) ^ rotr64(x, 61n) ^ shr64(x, 6n)) & MASK_64;
}

export function bigSigma0_512(x) {
  x = BigInt(x) & MASK_64;
  return (rotr64(x, 28n) ^ rotr64(x, 34n) ^ rotr64(x, 39n)) & MASK_64;
}

export function bigSigma1_512(x) {
  x = BigInt(x) & MASK_64;
  return (rotr64(x, 14n) ^ rotr64(x, 18n) ^ rotr64(x, 41n)) & MASK_64;
}

export function ch_512(x, y, z) {
  x = BigInt(x) & MASK_64;
  y = BigInt(y) & MASK_64;
  z = BigInt(z) & MASK_64;
  return ((x & y) ^ ((~x & MASK_64) & z)) & MASK_64;
}

export function maj_512(x, y, z) {
  x = BigInt(x) & MASK_64;
  y = BigInt(y) & MASK_64;
  z = BigInt(z) & MASK_64;
  return ((x & y) ^ (x & z) ^ (y & z)) & MASK_64;
}

/**
 * Pads the input byte array according to FIPS 180-4 (1024-bit block, 128-bit length in Big-Endian)
 */
export function padSHA512(inputBytes) {
  const origLen = inputBytes.length;
  const bitLen = BigInt(origLen) * 8n;
  const padded = [...inputBytes];

  padded.push(0x80);

  // Pad with 0s until length % 128 === 112 (128 bytes - 16 bytes length = 112)
  while (padded.length % 128 !== 112) {
    padded.push(0x00);
  }

  // 128-bit length (16 bytes Big-Endian)
  for (let i = 15; i >= 0; i--) {
    padded.push(Number((bitLen >> BigInt(i * 8)) & 0xFFn));
  }

  return new Uint8Array(padded);
}

/**
 * Computes SHA-512 with step-by-step tracing
 */
export function sha512(inputBytes) {
  const paddedBytes = padSHA512(inputBytes);
  const blockCount = paddedBytes.length / 128;

  let H = [...SHA512_INIT];
  const traces = [];
  const blocks = [];

  for (let b = 0; b < blockCount; b++) {
    const blockBytes = paddedBytes.slice(b * 128, (b + 1) * 128);
    const M = bytesToWords64BE(Array.from(blockBytes));

    // Message schedule expansion: 80 64-bit words W_0 to W_79
    const W = new Array(80);
    const wExpansionSteps = [];

    for (let t = 0; t < 16; t++) {
      W[t] = M[t] & MASK_64;
      wExpansionSteps.push({
        t,
        val: W[t],
        isDirect: true,
        formula: `W[${t}] = M[${t}] = 0x${W[t].toString(16).padStart(16, '0')}`
      });
    }

    for (let t = 16; t < 80; t++) {
      const s0 = sigma0_512(W[t - 15]);
      const s1 = sigma1_512(W[t - 2]);
      W[t] = add64(W[t - 16], s0, W[t - 7], s1);
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
      words: M.map(w => w & MASK_64),
      expandedSchedule: Array.from(W),
      wExpansionSteps
    });

    let [a, b_reg, c, d, e, f, g, h] = H;
    const startState = [a, b_reg, c, d, e, f, g, h];
    const blockSteps = [];

    for (let t = 0; t < 80; t++) {
      const prevA = a, prevB = b_reg, prevC = c, prevD = d;
      const prevE = e, prevF = f, prevG = g, prevH = h;

      const s1 = bigSigma1_512(e);
      const ch = ch_512(e, f, g);
      const kt = SHA512_K[t];
      const wt = W[t];
      const t1 = add64(h, s1, ch, kt, wt);

      const s0 = bigSigma0_512(a);
      const maj = maj_512(a, b_reg, c);
      const t2 = add64(s0, maj);

      // Register updates
      h = prevG;
      g = prevF;
      f = prevE;
      e = add64(prevD, t1);
      d = prevC;
      c = prevB;
      b_reg = prevA;
      a = add64(t1, t2);

      blockSteps.push({
        step: t,
        kVal: kt,
        wVal: wt,
        s1,
        ch,
        t1,
        s0,
        maj,
        t2,
        stateBefore: { A: prevA, B: prevB, C: prevC, D: prevD, E: prevE, F: prevF, G: prevG, H: prevH },
        stateAfter: { A: a, B: b_reg, C: c, D: d, E: e, F: f, G: g, H: h },
        formulaT1: `T1 = H + Σ1(E) + Ch(E,F,G) + K[${t}] + W[${t}]`,
        formulaT2: `T2 = Σ0(A) + Maj(A,B,C)`
      });
    }

    // Add block results to state vector
    H[0] = add64(H[0], a);
    H[1] = add64(H[1], b_reg);
    H[2] = add64(H[2], c);
    H[3] = add64(H[3], d);
    H[4] = add64(H[4], e);
    H[5] = add64(H[5], f);
    H[6] = add64(H[6], g);
    H[7] = add64(H[7], h);

    traces.push({
      blockIndex: b,
      startState,
      endState: [a, b_reg, c, d, e, f, g, h],
      accumulated: [...H],
      steps: blockSteps
    });
  }

  // Format digest
  const digestBytes = words64ToBytesBE(H);
  const digestHex = bytesToHexString(digestBytes);

  return {
    algorithm: 'SHA-512',
    digestHex,
    digestBytes,
    paddedBytes: Array.from(paddedBytes),
    originalLength: inputBytes.length,
    paddedLength: paddedBytes.length,
    blockCount,
    blocks,
    traces,
    initialState: [...SHA512_INIT],
    finalRegisters: [...H]
  };
}
