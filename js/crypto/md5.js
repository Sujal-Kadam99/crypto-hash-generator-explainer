/**
 * MD5 (Message Digest Algorithm 5) - RFC 1321
 * Bit-accurate implementation with step-by-step trace generation
 */
import { rotl32, add32, bytesToWords32LE, words32ToBytesLE, bytesToHexString, u32ToHex } from './utils.js';

// Precomputed T[i] constants: floor(2^32 * abs(sin(i + 1)))
export const MD5_K = new Uint32Array(64);
for (let i = 0; i < 64; i++) {
  MD5_K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
}

// Per-round shift constants
export const MD5_S = [
  // Round 1
  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
  // Round 2
  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
  // Round 3
  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
  // Round 4
  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
];

// Initial state vectors
export const MD5_INIT = [
  0x67452301 >>> 0, // A
  0xefcdab89 >>> 0, // B
  0x98badcfe >>> 0, // C
  0x10325476 >>> 0  // D
];

/**
 * Pads the input byte array according to RFC 1321 (512-bit block, 64-bit length in Little-Endian)
 */
export function padMD5(inputBytes) {
  const origLen = inputBytes.length;
  const bitLen = origLen * 8;
  const padded = [...inputBytes];

  // 1. Append single 1 bit followed by 7 zero bits (0x80)
  padded.push(0x80);

  // 2. Pad with zeros until length % 64 === 56
  while (padded.length % 64 !== 56) {
    padded.push(0x00);
  }

  // 3. Append original length in bits as 64-bit Little-Endian integer
  for (let i = 0; i < 8; i++) {
    padded.push(Number((BigInt(bitLen) >> BigInt(i * 8)) & 0xFFn));
  }

  return new Uint8Array(padded);
}

/**
 * Computes MD5 with detailed step tracing for educational visualization
 */
export function md5(inputBytes) {
  const paddedBytes = padMD5(inputBytes);
  const blockCount = paddedBytes.length / 64;

  let H = [...MD5_INIT];
  const traces = [];
  const blocks = [];

  for (let b = 0; b < blockCount; b++) {
    const blockBytes = paddedBytes.slice(b * 64, (b + 1) * 64);
    const M = bytesToWords32LE(Array.from(blockBytes));

    blocks.push({
      index: b,
      rawBytes: Array.from(blockBytes),
      words: M.map(w => w >>> 0)
    });

    let [a, b_reg, c, d] = H;
    const startState = [a, b_reg, c, d];
    const blockSteps = [];

    for (let i = 0; i < 64; i++) {
      const prevA = a, prevB = b_reg, prevC = c, prevD = d;
      let f = 0, g = 0, fnName = '';

      if (i < 16) {
        // Round 1: F(b, c, d) = (b & c) | (~b & d)
        f = ((b_reg & c) | ((~b_reg) & d)) >>> 0;
        g = i;
        fnName = 'F (Choice)';
      } else if (i < 32) {
        // Round 2: G(b, c, d) = (b & d) | (c & ~d)
        f = ((b_reg & d) | (c & (~d))) >>> 0;
        g = (5 * i + 1) % 16;
        fnName = 'G (Maj/Select)';
      } else if (i < 48) {
        // Round 3: H(b, c, d) = b ^ c ^ d
        f = (b_reg ^ c ^ d) >>> 0;
        g = (3 * i + 5) % 16;
        fnName = 'H (Parity/XOR)';
      } else {
        // Round 4: I(b, c, d) = c ^ (b | ~d)
        f = (c ^ (b_reg | (~d))) >>> 0;
        g = (7 * i) % 16;
        fnName = 'I (Nonlinear)';
      }

      const k = MD5_K[i];
      const s = MD5_S[i];
      const mVal = M[g];

      const sumBeforeShift = add32(a, f, k, mVal);
      const rotated = rotl32(sumBeforeShift, s);
      const newB = add32(b_reg, rotated);

      // Register shifts: A = D, D = C, C = B, B = newB
      a = prevD;
      d = prevC;
      c = prevB;
      b_reg = newB;

      blockSteps.push({
        step: i,
        round: Math.floor(i / 16) + 1,
        fnName,
        fVal: f >>> 0,
        gIndex: g,
        mVal: mVal >>> 0,
        kVal: k >>> 0,
        shift: s,
        sumBeforeShift: sumBeforeShift >>> 0,
        rotated: rotated >>> 0,
        stateBefore: { A: prevA, B: prevB, C: prevC, D: prevD },
        stateAfter: { A: a, B: b_reg, C: c, D: d },
        formula: `B_next = B + ((A + ${fnName.charAt(0)}(B,C,D) + M[${g}] + K[${i}]) <<< ${s})`
      });
    }

    // Add block results back to accumulator
    H[0] = add32(H[0], a);
    H[1] = add32(H[1], b_reg);
    H[2] = add32(H[2], c);
    H[3] = add32(H[3], d);

    traces.push({
      blockIndex: b,
      startState,
      endState: [a, b_reg, c, d],
      accumulated: [...H],
      steps: blockSteps
    });
  }

  // Format digest (Little-Endian words to bytes)
  const digestBytes = words32ToBytesLE(H);
  const digestHex = bytesToHexString(digestBytes);

  return {
    algorithm: 'MD5',
    digestHex,
    digestBytes,
    paddedBytes: Array.from(paddedBytes),
    originalLength: inputBytes.length,
    paddedLength: paddedBytes.length,
    blockCount,
    blocks,
    traces,
    initialState: [...MD5_INIT],
    finalRegisters: [...H]
  };
}
