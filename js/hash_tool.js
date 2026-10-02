/**
 * Crypto Hash Generator & Explainer & Non-Tech Friendly Cryptographic Explainer
 * Self-contained pure JavaScript with 100% bit-accurate math, trace logging & visualizer.
 * Compatible with offline file:// and http:// environments.
 */
(function(window) {
  'use strict';

  // ==========================================
  // 1. BITWISE MATH & UTILITY FUNCTIONS
  // ==========================================
  const MASK_64 = 0xFFFFFFFFFFFFFFFFn;

  function rotr32(n, b) {
    n >>>= 0;
    b %= 32;
    return ((n >>> b) | (n << (32 - b))) >>> 0;
  }

  function rotl32(n, b) {
    n >>>= 0;
    b %= 32;
    return ((n << b) | (n >>> (32 - b))) >>> 0;
  }

  function shr32(n, b) {
    return (n >>> b) >>> 0;
  }

  function add32() {
    let sum = 0;
    for (let i = 0; i < arguments.length; i++) {
      sum = (sum + (arguments[i] >>> 0)) >>> 0;
    }
    return sum >>> 0;
  }

  function rotr64(n, b) {
    n = BigInt(n) & MASK_64;
    b = BigInt(b) % 64n;
    return ((n >> b) | (n << (64n - b))) & MASK_64;
  }

  function shr64(n, b) {
    n = BigInt(n) & MASK_64;
    b = BigInt(b);
    return (n >> b) & MASK_64;
  }

  function add64() {
    let sum = 0n;
    for (let i = 0; i < arguments.length; i++) {
      sum = (sum + (BigInt(arguments[i]) & MASK_64)) & MASK_64;
    }
    return sum;
  }

  function stringToUtf8Bytes(str) {
    if (typeof TextEncoder !== 'undefined') {
      return Array.from(new TextEncoder().encode(str));
    }
    const utf8 = [];
    for (let i = 0; i < str.length; i++) {
      let charcode = str.charCodeAt(i);
      if (charcode < 0x80) utf8.push(charcode);
      else if (charcode < 0x800) {
        utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
      } else if (charcode < 0xd800 || charcode >= 0xe000) {
        utf8.push(0xe0 | (charcode >> 12), 0x80 | ((charcode >> 6) & 0x3f), 0x80 | (charcode & 0x3f));
      } else {
        i++;
        charcode = 0x10000 + (((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
        utf8.push(0xf0 | (charcode >> 18), 0x80 | ((charcode >> 12) & 0x3f), 0x80 | ((charcode >> 6) & 0x3f), 0x80 | (charcode & 0x3f));
      }
    }
    return utf8;
  }

  function bytesToHexString(bytes) {
    return Array.from(bytes).map(b => (b >>> 0).toString(16).padStart(2, '0')).join('');
  }

  function byteToBinaryString(b) {
    return (b >>> 0).toString(2).padStart(8, '0');
  }

  function u32ToHex(val) {
    return (val >>> 0).toString(16).padStart(8, '0');
  }

  function u64ToHex(val) {
    return (BigInt(val) & MASK_64).toString(16).padStart(16, '0');
  }

  function bytesToWords32BE(bytes) {
    const words = [];
    for (let i = 0; i < bytes.length; i += 4) {
      words.push((((bytes[i] || 0) << 24) | ((bytes[i + 1] || 0) << 16) | ((bytes[i + 2] || 0) << 8) | (bytes[i + 3] || 0)) >>> 0);
    }
    return words;
  }

  function bytesToWords32LE(bytes) {
    const words = [];
    for (let i = 0; i < bytes.length; i += 4) {
      words.push(((bytes[i] || 0) | ((bytes[i + 1] || 0) << 8) | ((bytes[i + 2] || 0) << 16) | ((bytes[i + 3] || 0) << 24)) >>> 0);
    }
    return words;
  }

  function words32ToBytesBE(words) {
    const bytes = [];
    for (let i = 0; i < words.length; i++) {
      const w = words[i] >>> 0;
      bytes.push((w >>> 24) & 0xFF, (w >>> 16) & 0xFF, (w >>> 8) & 0xFF, w & 0xFF);
    }
    return bytes;
  }

  function words32ToBytesLE(words) {
    const bytes = [];
    for (let i = 0; i < words.length; i++) {
      const w = words[i] >>> 0;
      bytes.push(w & 0xFF, (w >>> 8) & 0xFF, (w >>> 16) & 0xFF, (w >>> 24) & 0xFF);
    }
    return bytes;
  }

  function bytesToWords64BE(bytes) {
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

  function words64ToBytesBE(words) {
    const bytes = [];
    for (let i = 0; i < words.length; i++) {
      const w = BigInt(words[i]) & MASK_64;
      for (let j = 7; j >= 0; j--) {
        bytes.push(Number((w >> BigInt(j * 8)) & 0xFFn));
      }
    }
    return bytes;
  }

  // ==========================================
  // 2. ENGINES: MD5, SHA-1, SHA-256, SHA-512
  // ==========================================
  const MD5_K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) {
    MD5_K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  }
  const MD5_S = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
  ];
  const MD5_INIT = [0x67452301 >>> 0, 0xefcdab89 >>> 0, 0x98badcfe >>> 0, 0x10325476 >>> 0];

  function runMD5(inputBytes) {
    const origLen = inputBytes.length;
    const bitLen = BigInt(origLen) * 8n;
    const padded = [...inputBytes, 0x80];
    while (padded.length % 64 !== 56) padded.push(0x00);
    for (let i = 0; i < 8; i++) {
      padded.push(Number((bitLen >> BigInt(i * 8)) & 0xFFn));
    }

    let H = [...MD5_INIT];
    const blockCount = padded.length / 64;
    const blocks = [];
    const traces = [];

    for (let b = 0; b < blockCount; b++) {
      const blockBytes = padded.slice(b * 64, (b + 1) * 64);
      const M = bytesToWords32LE(blockBytes);
      const steps = [];

      blocks.push({
        index: b,
        rawBytes: Array.from(blockBytes),
        words: M.map(w => w >>> 0),
        expandedSchedule: M.map(w => w >>> 0),
        wExpansionSteps: M.map((w, idx) => ({ t: idx, val: w >>> 0, isDirect: true, formula: `M[${idx}] = 0x${u32ToHex(w)}` }))
      });

      let [a, b_reg, c, d] = H;
      const startState = [a, b_reg, c, d];

      for (let i = 0; i < 64; i++) {
        const prevA = a, prevB = b_reg, prevC = c, prevD = d;
        let f, g, fnName;
        if (i < 16) {
          f = (b_reg & c) | ((~b_reg) & d);
          g = i;
          fnName = 'F = (B & C) | (~B & D)';
        } else if (i < 32) {
          f = (b_reg & d) | (c & (~d));
          g = (5 * i + 1) % 16;
          fnName = 'G = (B & D) | (C & ~D)';
        } else if (i < 48) {
          f = b_reg ^ c ^ d;
          g = (3 * i + 5) % 16;
          fnName = 'H = B ^ C ^ D';
        } else {
          f = c ^ (b_reg | (~d));
          g = (7 * i) % 16;
          fnName = 'I = C ^ (B | ~D)';
        }

        const sum = add32(a, f, MD5_K[i], M[g]);
        const rotated = rotl32(sum, MD5_S[i]);
        const newB = add32(b_reg, rotated);

        a = d;
        d = c;
        c = b_reg;
        b_reg = newB;

        steps.push({
          step: i,
          round: Math.floor(i / 16) + 1,
          fnName,
          kVal: MD5_K[i],
          wVal: M[g],
          gIndex: g,
          shift: MD5_S[i],
          stateBefore: { A: prevA, B: prevB, C: prevC, D: prevD },
          stateAfter: { A: a, B: b_reg, C: c, D: d },
          formula: `newB = B + ((A + fn(B,C,D) + M[${g}] + K[${i}]) <<< ${MD5_S[i]})`
        });
      }

      H[0] = add32(H[0], a);
      H[1] = add32(H[1], b_reg);
      H[2] = add32(H[2], c);
      H[3] = add32(H[3], d);

      traces.push({
        blockIndex: b,
        startState,
        endState: [a, b_reg, c, d],
        accumulated: [...H],
        steps
      });
    }

    const digestBytes = words32ToBytesLE(H);
    return {
      algorithm: 'MD5',
      digestHex: bytesToHexString(digestBytes),
      digestBytes,
      paddedBytes: Array.from(padded),
      originalLength: origLen,
      paddedLength: padded.length,
      blockCount,
      blocks,
      traces,
      initialState: [...MD5_INIT],
      finalRegisters: [...H]
    };
  }

  const SHA1_INIT = [0x67452301 >>> 0, 0xEFCDAB89 >>> 0, 0x98BADCFE >>> 0, 0x10325476 >>> 0, 0xC3D2E1F0 >>> 0];
  const SHA1_K = [0x5A827999 >>> 0, 0x6ED9EBA1 >>> 0, 0x8F1BBCDC >>> 0, 0xCA62C1D6 >>> 0];

  function runSHA1(inputBytes) {
    const origLen = inputBytes.length;
    const bitLen = BigInt(origLen) * 8n;
    const padded = [...inputBytes, 0x80];
    while (padded.length % 64 !== 56) padded.push(0x00);
    for (let i = 7; i >= 0; i--) {
      padded.push(Number((bitLen >> BigInt(i * 8)) & 0xFFn));
    }

    let H = [...SHA1_INIT];
    const blockCount = padded.length / 64;
    const blocks = [];
    const traces = [];

    for (let b = 0; b < blockCount; b++) {
      const blockBytes = padded.slice(b * 64, (b + 1) * 64);
      const M = bytesToWords32BE(blockBytes);
      const W = new Uint32Array(80);
      const wSteps = [];

      for (let t = 0; t < 16; t++) {
        W[t] = M[t] >>> 0;
        wSteps.push({ t, val: W[t], isDirect: true, formula: `W[${t}] = M[${t}] = 0x${u32ToHex(W[t])}` });
      }
      for (let t = 16; t < 80; t++) {
        W[t] = rotl32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
        wSteps.push({ t, val: W[t], isDirect: false, formula: `W[${t}] = (W[${t-3}] ^ W[${t-8}] ^ W[${t-14}] ^ W[${t-16}]) <<< 1` });
      }

      blocks.push({
        index: b,
        rawBytes: Array.from(blockBytes),
        words: M.map(w => w >>> 0),
        expandedSchedule: Array.from(W),
        wExpansionSteps: wSteps
      });

      let [a, b_reg, c, d, e] = H;
      const startState = [a, b_reg, c, d, e];
      const steps = [];

      for (let t = 0; t < 80; t++) {
        const prevA = a, prevB = b_reg, prevC = c, prevD = d, prevE = e;
        let f, k, fnName;
        if (t < 20) {
          f = (b_reg & c) | ((~b_reg) & d);
          k = SHA1_K[0];
          fnName = 'Ch = (B & C) | (~B & D)';
        } else if (t < 40) {
          f = b_reg ^ c ^ d;
          k = SHA1_K[1];
          fnName = 'Parity = B ^ C ^ D';
        } else if (t < 60) {
          f = (b_reg & c) | (b_reg & d) | (c & d);
          k = SHA1_K[2];
          fnName = 'Maj = (B & C) | (B & D) | (C & D)';
        } else {
          f = b_reg ^ c ^ d;
          k = SHA1_K[3];
          fnName = 'Parity = B ^ C ^ D';
        }

        const rotA5 = rotl32(a, 5);
        const temp = add32(rotA5, f, e, k, W[t]);
        e = d;
        d = c;
        c = rotl32(b_reg, 30);
        b_reg = a;
        a = temp;

        steps.push({
          step: t,
          round: Math.floor(t / 20) + 1,
          fnName,
          kVal: k,
          wVal: W[t],
          stateBefore: { A: prevA, B: prevB, C: prevC, D: prevD, E: prevE },
          stateAfter: { A: a, B: b_reg, C: c, D: d, E: e },
          formula: `TEMP = (A <<< 5) + fn(B,C,D) + E + W[${t}] + K[${Math.floor(t/20)}]`
        });
      }

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
        steps
      });
    }

    const digestBytes = words32ToBytesBE(H);
    return {
      algorithm: 'SHA-1',
      digestHex: bytesToHexString(digestBytes),
      digestBytes,
      paddedBytes: Array.from(padded),
      originalLength: origLen,
      paddedLength: padded.length,
      blockCount,
      blocks,
      traces,
      initialState: [...SHA1_INIT],
      finalRegisters: [...H]
    };
  }

  const SHA256_INIT = [
    0x6a09e667 >>> 0, 0xbb67ae85 >>> 0, 0x3c6ef372 >>> 0, 0xa54ff53a >>> 0,
    0x510e527f >>> 0, 0x9b05688c >>> 0, 0x1f83d9ab >>> 0, 0x5be0cd19 >>> 0
  ];
  const SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ].map(k => k >>> 0);

  function runSHA256(inputBytes) {
    const origLen = inputBytes.length;
    const bitLen = BigInt(origLen) * 8n;
    const padded = [...inputBytes, 0x80];
    while (padded.length % 64 !== 56) padded.push(0x00);
    for (let i = 7; i >= 0; i--) {
      padded.push(Number((bitLen >> BigInt(i * 8)) & 0xFFn));
    }

    let H = [...SHA256_INIT];
    const blockCount = padded.length / 64;
    const blocks = [];
    const traces = [];

    for (let b = 0; b < blockCount; b++) {
      const blockBytes = padded.slice(b * 64, (b + 1) * 64);
      const M = bytesToWords32BE(blockBytes);
      const W = new Uint32Array(64);
      const wSteps = [];

      for (let t = 0; t < 16; t++) {
        W[t] = M[t] >>> 0;
        wSteps.push({ t, val: W[t], isDirect: true, formula: `W[${t}] = M[${t}] = 0x${u32ToHex(W[t])}` });
      }
      for (let t = 16; t < 64; t++) {
        const s0 = (rotr32(W[t - 15], 7) ^ rotr32(W[t - 15], 18) ^ shr32(W[t - 15], 3)) >>> 0;
        const s1 = (rotr32(W[t - 2], 17) ^ rotr32(W[t - 2], 19) ^ shr32(W[t - 2], 10)) >>> 0;
        W[t] = add32(W[t - 16], s0, W[t - 7], s1);
        wSteps.push({ t, val: W[t], isDirect: false, formula: `W[${t}] = W[${t-16}] + σ0(W[${t-15}]) + W[${t-7}] + σ1(W[${t-2}])` });
      }

      blocks.push({
        index: b,
        rawBytes: Array.from(blockBytes),
        words: M.map(w => w >>> 0),
        expandedSchedule: Array.from(W),
        wExpansionSteps: wSteps
      });

      let [a, b_reg, c, d, e, f, g, h] = H;
      const startState = [a, b_reg, c, d, e, f, g, h];
      const steps = [];

      for (let t = 0; t < 64; t++) {
        const prevA = a, prevB = b_reg, prevC = c, prevD = d;
        const prevE = e, prevF = f, prevG = g, prevH = h;

        const s1 = (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) >>> 0;
        const ch = ((e & f) ^ ((~e) & g)) >>> 0;
        const t1 = add32(h, s1, ch, SHA256_K[t], W[t]);

        const s0 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) >>> 0;
        const maj = ((a & b_reg) ^ (a & c) ^ (b_reg & c)) >>> 0;
        const t2 = add32(s0, maj);

        h = g;
        g = f;
        f = e;
        e = add32(d, t1);
        d = c;
        c = b_reg;
        b_reg = a;
        a = add32(t1, t2);

        steps.push({
          step: t,
          round: t + 1,
          kVal: SHA256_K[t],
          wVal: W[t],
          s1, ch, t1, s0, maj, t2,
          stateBefore: { A: prevA, B: prevB, C: prevC, D: prevD, E: prevE, F: prevF, G: prevG, H: prevH },
          stateAfter: { A: a, B: b_reg, C: c, D: d, E: e, F: f, G: g, H: h },
          formula: `T1 = H + Σ1(E) + Ch(E,F,G) + K[${t}] + W[${t}];  T2 = Σ0(A) + Maj(A,B,C)`
        });
      }

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
        steps
      });
    }

    const digestBytes = words32ToBytesBE(H);
    return {
      algorithm: 'SHA-256',
      digestHex: bytesToHexString(digestBytes),
      digestBytes,
      paddedBytes: Array.from(padded),
      originalLength: origLen,
      paddedLength: padded.length,
      blockCount,
      blocks,
      traces,
      initialState: [...SHA256_INIT],
      finalRegisters: [...H]
    };
  }

  const SHA512_INIT = [
    0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
  ];
  const SHA512_K = [
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

  function runSHA512(inputBytes) {
    const origLen = inputBytes.length;
    const bitLen = BigInt(origLen) * 8n;
    const padded = [...inputBytes, 0x80];
    while (padded.length % 128 !== 112) padded.push(0x00);
    for (let i = 15; i >= 0; i--) {
      padded.push(Number((bitLen >> BigInt(i * 8)) & 0xFFn));
    }

    let H = [...SHA512_INIT];
    const blockCount = padded.length / 128;
    const blocks = [];
    const traces = [];

    for (let b = 0; b < blockCount; b++) {
      const blockBytes = padded.slice(b * 128, (b + 1) * 128);
      const M = bytesToWords64BE(blockBytes);
      const W = new Array(80);
      const wSteps = [];

      for (let t = 0; t < 16; t++) {
        W[t] = M[t] & MASK_64;
        wSteps.push({ t, val: W[t], isDirect: true, formula: `W[${t}] = M[${t}] = 0x${u64ToHex(W[t])}` });
      }
      for (let t = 16; t < 80; t++) {
        const s0 = (rotr64(W[t - 15], 1n) ^ rotr64(W[t - 15], 8n) ^ shr64(W[t - 15], 7n)) & MASK_64;
        const s1 = (rotr64(W[t - 2], 19n) ^ rotr64(W[t - 2], 61n) ^ shr64(W[t - 2], 6n)) & MASK_64;
        W[t] = add64(W[t - 16], s0, W[t - 7], s1);
        wSteps.push({ t, val: W[t], isDirect: false, formula: `W[${t}] = W[${t-16}] + σ0(W[${t-15}]) + W[${t-7}] + σ1(W[${t-2}])` });
      }

      blocks.push({
        index: b,
        rawBytes: Array.from(blockBytes),
        words: M.map(w => w & MASK_64),
        expandedSchedule: Array.from(W),
        wExpansionSteps: wSteps
      });

      let [a, b_reg, c, d, e, f, g, h] = H;
      const startState = [a, b_reg, c, d, e, f, g, h];
      const steps = [];

      for (let t = 0; t < 80; t++) {
        const prevA = a, prevB = b_reg, prevC = c, prevD = d;
        const prevE = e, prevF = f, prevG = g, prevH = h;

        const s1 = (rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n)) & MASK_64;
        const ch = ((e & f) ^ ((~e & MASK_64) & g)) & MASK_64;
        const t1 = add64(h, s1, ch, SHA512_K[t], W[t]);

        const s0 = (rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n)) & MASK_64;
        const maj = ((a & b_reg) ^ (a & c) ^ (b_reg & c)) & MASK_64;
        const t2 = add64(s0, maj);

        h = g;
        g = f;
        f = e;
        e = add64(d, t1);
        d = c;
        c = b_reg;
        b_reg = a;
        a = add64(t1, t2);

        steps.push({
          step: t,
          round: t + 1,
          kVal: SHA512_K[t],
          wVal: W[t],
          s1, ch, t1, s0, maj, t2,
          stateBefore: { A: prevA, B: prevB, C: prevC, D: prevD, E: prevE, F: prevF, G: prevG, H: prevH },
          stateAfter: { A: a, B: b_reg, C: c, D: d, E: e, F: f, G: g, H: h },
          formula: `T1 = H + Σ1(E) + Ch(E,F,G) + K[${t}] + W[${t}];  T2 = Σ0(A) + Maj(A,B,C)`
        });
      }

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
        steps
      });
    }

    const digestBytes = words64ToBytesBE(H);
    return {
      algorithm: 'SHA-512',
      digestHex: bytesToHexString(digestBytes),
      digestBytes,
      paddedBytes: Array.from(padded),
      originalLength: origLen,
      paddedLength: padded.length,
      blockCount,
      blocks,
      traces,
      initialState: [...SHA512_INIT],
      finalRegisters: [...H]
    };
  }

  // ==========================================
  // 3. STORY MODE RENDERER (NON-TECH FRIENDLY)
  // ==========================================
  function renderStoryMode(container, result, inputText) {
    const { algorithm, digestHex, originalLength } = result;
    const sampleText = inputText || 'hey';
    const chars = Array.from(sampleText).slice(0, 10);

    container.innerHTML = `
      <div class="story-mode-wrap">
        <!-- Big Analogy Hero Banner -->
        <div class="glass-panel" style="padding: 1.5rem; margin-bottom: 1.5rem; background: linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.7)); border-left: 4px solid var(--accent-cyan);">
          <div style="display:flex; align-items:center; gap:0.75rem; margin-bottom:0.75rem;">
            <span style="font-size: 2rem;">🍹</span>
            <div>
              <h3 style="font-size: 1.25rem; margin-bottom: 0.15rem;">The Simple Analogy: A "Digital Fruit Smoothie Blender"</h3>
              <p style="color: var(--text-muted); font-size: 0.88rem;">How plain text becomes an unbreakable, unique digital fingerprint.</p>
            </div>
          </div>
          <p style="font-size: 0.92rem; line-height: 1.6; color: #cbd5e1;">
            Think of a cryptographic hash function like a high-tech <strong>smoothie blender</strong>. You throw in your raw ingredients (letters like <em>"${sampleText.slice(0, 20)}"</em>). The machine chops, mixes, rotates, and blends them with mathematical spices through <strong>${algorithm === 'MD5' || algorithm === 'SHA-256' ? '64' : '80'} fast spin cycles</strong>. At the end, you get a unique colored smoothie (<strong>${digestHex.slice(0, 16)}...</strong>). 
            <br/><br/>
            <strong>The Magic Rule:</strong> You can <em>always</em> blend fruit into a smoothie in 1 millisecond. But <strong>no one in the world can un-blend a smoothie</strong> back into whole fruit! That is why hashes are completely one-way and safe for passwords.
          </p>
        </div>

        <!-- 4 Simple Illustrated Stages -->
        <h3 style="font-size: 1.15rem; margin-bottom: 1rem; display:flex; align-items:center; gap:0.5rem;">
          <span>📋 The 4-Step Recipe (What Just Happened To Your Text):</span>
        </h3>

        <div style="display: grid; grid-template-columns: 1fr; gap: 1rem; margin-bottom: 1.5rem;">
          
          <!-- Stage 1 -->
          <div class="glass-panel" style="padding: 1.25rem; border-left: 3px solid #00d2ff;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
              <h4 style="color: #00d2ff; font-size: 1rem; display:flex; align-items:center; gap:0.4rem;">
                <span>1️⃣ Stage 1: Translating Letters into Digital Numbers</span>
              </h4>
              <span class="badge badge-cyan">Plain English Step</span>
            </div>
            <p style="font-size: 0.88rem; color: #94a3b8; margin-bottom: 0.75rem;">
              Computers don't understand human letters like "a", "b", or "c". So the first thing the algorithm does is look up the universal ID number for every character you typed:
            </p>
            <div style="display:flex; flex-wrap:wrap; gap:0.6rem; background:rgba(0,0,0,0.3); padding:0.75rem; border-radius:8px;">
              ${chars.map(ch => {
                const code = ch.charCodeAt(0);
                const hex = code.toString(16).padStart(2,'0').toUpperCase();
                return `
                  <div style="background:rgba(0,210,255,0.1); border:1px solid rgba(0,210,255,0.3); border-radius:6px; padding:0.4rem 0.6rem; text-align:center;">
                    <div style="font-size:1.1rem; font-weight:700; color:#fff;">'${ch}'</div>
                    <div style="font-size:0.75rem; color:#38bdf8; font-family:var(--font-mono);">Number ${code}</div>
                    <div style="font-size:0.7rem; color:#94a3b8; font-family:var(--font-mono);">(Hex 0x${hex})</div>
                  </div>
                `;
              }).join('')}
              ${originalLength > 10 ? `<div style="display:flex; align-items:center; color:var(--text-muted); font-size:0.8rem;">+ ${originalLength - 10} more characters...</div>` : ''}
            </div>
          </div>

          <!-- Stage 2 -->
          <div class="glass-panel" style="padding: 1.25rem; border-left: 3px solid #a855f7;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
              <h4 style="color: #c084fc; font-size: 1rem; display:flex; align-items:center; gap:0.4rem;">
                <span>2️⃣ Stage 2: Packaging into Standard Delivery Boxes (Padding)</span>
              </h4>
              <span class="badge badge-purple">Standardization</span>
            </div>
            <p style="font-size: 0.88rem; color: #94a3b8; margin-bottom: 0.5rem;">
              The blender algorithm is picky: it only accepts standard cargo containers of exactly <strong>${algorithm === 'SHA-512' ? '1024 bits' : '512 bits'}</strong>. If your message is short (like "${sampleText.slice(0, 10)}"), the algorithm:
            </p>
            <ul style="font-size: 0.85rem; color: #cbd5e1; padding-left: 1.25rem; line-height: 1.6;">
              <li>Puts a separator pin (a single <code>1</code> bit) right after your text.</li>
              <li>Packs the empty space with digital bubble wrap (a bunch of <code>0</code> zeros).</li>
              <li>Stamps the exact original size of your message (<strong>${originalLength * 8} bits</strong>) on the shipping label at the very end of the box.</li>
            </ul>
          </div>

          <!-- Stage 3 -->
          <div class="glass-panel" style="padding: 1.25rem; border-left: 3px solid #10b981;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
              <h4 style="color: #34d399; font-size: 1rem; display:flex; align-items:center; gap:0.4rem;">
                <span>3️⃣ Stage 3: The ${algorithm === 'MD5' || algorithm === 'SHA-256' ? '64' : '80'}-Cycle Blender Spin (Compression Rounds)</span>
              </h4>
              <span class="badge badge-emerald">The Mixing Core</span>
            </div>
            <p style="font-size: 0.88rem; color: #94a3b8; margin-bottom: 0.75rem;">
              Your packaged box is poured into 8 mixing bowls labeled <strong>A, B, C, D, E, F, G, H</strong>. The algorithm runs <strong>${algorithm === 'MD5' || algorithm === 'SHA-256' ? '64' : '80'} blender cycles</strong>:
            </p>
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:0.6rem; font-size:0.83rem;">
              <div style="background:rgba(0,0,0,0.3); padding:0.6rem 0.8rem; border-radius:6px;">
                <strong class="text-amber">🔄 Rotations:</strong> Bits are spun around like a roulette wheel.
              </div>
              <div style="background:rgba(0,0,0,0.3); padding:0.6rem 0.8rem; border-radius:6px;">
                <strong class="text-cyan">🌿 Constant Spices:</strong> Unique prime-number constants ($K_t$) are poured in.
              </div>
              <div style="background:rgba(0,0,0,0.3); padding:0.6rem 0.8rem; border-radius:6px;">
                <strong class="text-purple">🔀 Bowl Shuffling:</strong> The liquid from Bowl A is poured into B, B into C, and so on.
              </div>
            </div>
          </div>

          <!-- Stage 4 -->
          <div class="glass-panel" style="padding: 1.25rem; border-left: 3px solid #f59e0b;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
              <h4 style="color: #fbbf24; font-size: 1rem; display:flex; align-items:center; gap:0.4rem;">
                <span>4️⃣ Stage 4: Reading the Final Fingerprint</span>
              </h4>
              <span class="badge badge-amber">Finished Output</span>
            </div>
            <p style="font-size: 0.88rem; color: #94a3b8; margin-bottom: 0.6rem;">
              When the blender stops after all rounds, the numbers left in the bowls are glued together side-by-side to form your final hash:
            </p>
            <div style="background:rgba(0,0,0,0.4); padding:0.75rem 1rem; border-radius:6px; font-family:var(--font-mono); font-size:0.92rem; word-break:break-all;" class="text-cyan">
              ${digestHex}
            </div>
          </div>

        </div>

        <!-- 3 Big Questions Answered for Non-Tech Users -->
        <div class="glass-panel" style="padding: 1.5rem;">
          <h3 style="font-size: 1.1rem; margin-bottom: 1rem;">🤔 3 Questions You Might Be Wondering:</h3>
          <div style="display:flex; flex-direction:column; gap:1rem; font-size:0.88rem; line-height:1.6;">
            <div>
              <strong style="color:var(--accent-cyan);">Q1: If two people type "hey", do they get the exact same hash?</strong>
              <p style="color:#cbd5e1;">Yes! The algorithm is 100% deterministic. Every single person on Earth who hashes "hey" with ${algorithm} will get <code>${digestHex.slice(0, 16)}...</code> every single time.</p>
            </div>
            <div>
              <strong style="color:var(--accent-purple);">Q2: What happens if I change just a tiny dot or letter (e.g., "hey" ➡️ "hey.")?</strong>
              <p style="color:#cbd5e1;">Because of the 64 blender spins, changing even one tiny letter completely shuffles the entire output! (Check out the <em>"🌊 Live Avalanche Lab"</em> tab to see this in real time!).</p>
            </div>
            <div>
              <strong style="color:var(--accent-emerald);">Q3: Why can't a supercomputer reverse the hash back into plain text?</strong>
              <p style="color:#cbd5e1;">Because during the blender additions, whenever a number gets too large, the overflow numbers are thrown away (modular math). If someone tells you <em>"two numbers added together end in 4"</em>, was it 2+2? 1+3? 7+7? 10+4? There are infinite possibilities, making reversing mathematically impossible.</p>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // ==========================================
  // 4. AVALANCHE LAB RENDERER
  // ==========================================
  function renderAvalancheLab(container, baseText, algorithm) {
    const input1 = baseText || 'The quick brown fox jumps over the lazy dog';
    const input2 = baseText ? (baseText.endsWith('.') ? baseText.slice(0, -1) : baseText + '!') : 'The quick brown fox jumps over the lazy dog.';

    const calcHash = (txt) => {
      const b = stringToUtf8Bytes(txt);
      if (algorithm === 'MD5') return runMD5(b).digestHex;
      if (algorithm === 'SHA-1') return runSHA1(b).digestHex;
      if (algorithm === 'SHA-512') return runSHA512(b).digestHex;
      return runSHA256(b).digestHex;
    };

    const hash1 = calcHash(input1);
    const hash2 = calcHash(input2);

    let diffCount = 0;
    const len = Math.max(hash1.length, hash2.length);
    for (let i = 0; i < len; i++) {
      if (hash1[i] !== hash2[i]) diffCount++;
    }
    const diffPct = ((diffCount / len) * 100).toFixed(1);

    container.innerHTML = `
      <div class="glass-panel" style="padding: 1.5rem;">
        <h3 style="font-size: 1.2rem; display:flex; align-items:center; gap:0.5rem; margin-bottom:0.5rem;">
          <span>🌊 The Avalanche Effect: 1 Tiny Change ➡️ Total Chaos</span>
        </h3>
        <p style="color:var(--text-muted); font-size:0.88rem; margin-bottom:1.25rem;">
          A cornerstone of cryptographic security: If you change even <strong>1 character</strong>, more than 50% of the entire output hash flips into completely random new characters!
        </p>

        <div style="display:grid; grid-template-columns: 1fr; gap:1rem; margin-bottom:1.25rem;">
          <!-- Input 1 -->
          <div class="glass-panel" style="padding:1rem; background:rgba(15,23,42,0.8);">
            <div style="font-size:0.8rem; color:#94a3b8; margin-bottom:0.25rem; font-weight:700;">MESSAGE #1:</div>
            <input type="text" id="avalanche-input-1" value="${input1.replace(/"/g, '&quot;')}" style="width:100%; background:rgba(0,0,0,0.4); border:1px solid rgba(255,255,255,0.1); border-radius:6px; color:#fff; padding:0.5rem; font-family:var(--font-mono); font-size:0.88rem;" />
            <div style="margin-top:0.6rem; font-size:0.8rem; color:var(--text-muted);">
              Hash #1: <span class="font-mono text-cyan" style="word-break:break-all;">${hash1}</span>
            </div>
          </div>

          <!-- Input 2 -->
          <div class="glass-panel" style="padding:1rem; background:rgba(15,23,42,0.8);">
            <div style="font-size:0.8rem; color:#94a3b8; margin-bottom:0.25rem; font-weight:700;">MESSAGE #2 (Only 1 character different):</div>
            <input type="text" id="avalanche-input-2" value="${input2.replace(/"/g, '&quot;')}" style="width:100%; background:rgba(0,0,0,0.4); border:1px solid rgba(255,255,255,0.1); border-radius:6px; color:#fff; padding:0.5rem; font-family:var(--font-mono); font-size:0.88rem;" />
            <div style="margin-top:0.6rem; font-size:0.8rem; color:var(--text-muted);">
              Hash #2: <span class="font-mono text-purple" style="word-break:break-all;">${hash2}</span>
            </div>
          </div>
        </div>

        <!-- Metric Counter Banner -->
        <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:1rem; background:rgba(0,210,255,0.08); border:1px solid rgba(0,210,255,0.25); border-radius:8px; padding:1rem;">
          <div>
            <div style="font-size:0.8rem; color:#94a3b8;">Hash Character Differences:</div>
            <div style="font-size:1.4rem; font-weight:700;" class="text-cyan">${diffCount} / ${len} characters changed (${diffPct}%)</div>
          </div>
          <span class="badge badge-emerald" style="font-size:0.85rem; padding:0.4rem 0.8rem;">✓ Strong Avalanche Effect Active</span>
        </div>
      </div>
    `;

    // Live binding for avalanche inputs
    const inp1 = container.querySelector('#avalanche-input-1');
    const inp2 = container.querySelector('#avalanche-input-2');
    if (inp1 && inp2) {
      const updateAvalanche = () => {
        renderAvalancheLab(container, inp1.value, algorithm);
      };
      inp1.oninput = updateAvalanche;
      inp2.oninput = updateAvalanche;
    }
  }

  // ==========================================
  // 5. TECHNICAL WORKFLOW & STEPPER RENDERERS
  // ==========================================
  function renderWorkflow(container, result) {
    const { originalLength, paddedLength, blockCount, blocks, algorithm } = result;
    const is64 = algorithm === 'SHA-512';
    const endianness = algorithm === 'MD5' ? 'Little-Endian' : 'Big-Endian';
    const origBits = originalLength * 8;
    const padBits = paddedLength * 8;
    const kZeros = padBits - origBits - (is64 ? 128 : 64) - 8;

    container.innerHTML = `
      <div class="workflow-view-wrap">
        <div style="margin-bottom: 1.25rem;">
          <h3 style="font-size: 1.2rem; display:flex; align-items:center; gap:0.5rem;">
            <span>🔬 Complete Bit & Byte Transformation Pipeline</span>
            <span class="badge badge-cyan">${algorithm}</span>
            <span class="badge badge-purple">${endianness}</span>
            <span class="badge badge-emerald">${is64 ? '64-bit Word' : '32-bit Word'}</span>
          </h3>
          <p style="color: var(--text-muted); font-size: 0.88rem;">
            Precise mathematical dataflow: ASCII encoding, block bit-padding layout, word slicing, and message schedule expansion.
          </p>
        </div>

        <!-- Step 1: Plaintext to Byte Stream -->
        <div class="glass-panel" style="padding: 1.25rem; margin-bottom: 1rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
            <h4 style="color:var(--accent-cyan); font-size: 1rem;">Step 1: Character & Byte Encoding (UTF-8 / ASCII)</h4>
            <span class="badge badge-slate font-mono">${originalLength} Bytes (${origBits} Bits)</span>
          </div>
          ${originalLength === 0 ? '<div style="color:var(--text-dim); font-style:italic;">(Empty string input: 0 bytes)</div>' : `
            <div style="overflow-x:auto;">
              <table class="comparison-table" style="font-size:0.85rem;">
                <thead>
                  <tr>
                    <th>Index</th>
                    <th>Character</th>
                    <th>Decimal</th>
                    <th>Hexadecimal Byte</th>
                    <th>8-Bit Binary Pattern</th>
                  </tr>
                </thead>
                <tbody>
                  ${blocks[0].rawBytes.slice(0, originalLength).map((b, i) => {
                    const ch = (b >= 32 && b <= 126) ? String.fromCharCode(b) : '•';
                    return `
                      <tr>
                        <td class="font-mono text-cyan">[${i}]</td>
                        <td class="font-mono font-bold text-amber">"${ch}"</td>
                        <td class="font-mono">${b}</td>
                        <td class="font-mono text-purple font-bold">0x${b.toString(16).padStart(2,'0').toUpperCase()}</td>
                        <td class="font-mono text-cyan">${byteToBinaryString(b)}</td>
                      </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            </div>
          `}
        </div>

        <!-- Step 2: Bit Padding Pipeline -->
        <div class="glass-panel" style="padding: 1.25rem; margin-bottom: 1rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
            <h4 style="color:var(--accent-purple); font-size: 1rem;">Step 2: Bit Padding & Length Append (Merkle–Damgård Standard)</h4>
            <span class="badge badge-purple font-mono">${paddedLength} Bytes (${padBits} Bits) = ${blockCount} Block(s)</span>
          </div>
          <p style="font-size:0.85rem; color:var(--text-muted); margin-bottom:0.75rem;">
            The message is padded with a single <code>1</code> bit (<code>0x80</code>), followed by <code>${Math.max(0, kZeros)}</code> zero bits, and the original bit-length (<code>${origBits}</code>) encoded as a ${is64 ? '128' : '64'}-bit ${endianness} integer.
          </p>

          <div style="display:flex; flex-wrap:wrap; gap:0.35rem; margin-top:0.75rem; background:rgba(0,0,0,0.3); padding:0.75rem; border-radius:8px; font-family:var(--font-mono); font-size:0.75rem;">
            ${blocks[0].rawBytes.map((b, i) => {
              let color = '#94a3b8';
              let bg = 'rgba(255,255,255,0.05)';
              let label = 'Msg';
              if (i < originalLength) {
                color = '#00d2ff';
                bg = 'rgba(0,210,255,0.15)';
              } else if (i === originalLength) {
                color = '#f59e0b';
                bg = 'rgba(245,158,11,0.2)';
                label = '0x80 (1-bit)';
              } else if (i < paddedLength - (is64 ? 16 : 8)) {
                color = '#64748b';
                bg = 'rgba(100,116,139,0.1)';
                label = '0x00';
              } else {
                color = '#10b981';
                bg = 'rgba(16,185,129,0.2)';
                label = 'Length';
              }
              return `<span style="background:${bg}; color:${color}; padding:3px 6px; border-radius:4px;" title="Byte [${i}]: 0x${b.toString(16).padStart(2,'0').toUpperCase()} (${label})">0x${b.toString(16).padStart(2,'0').toUpperCase()}</span>`;
            }).join('')}
          </div>
          <div style="display:flex; gap:1.25rem; font-size:0.78rem; margin-top:0.6rem; color:var(--text-muted);">
            <span><strong class="text-cyan">■ Message Bytes</strong></span>
            <span><strong class="text-amber">■ 0x80 ('1' bit)</strong></span>
            <span><strong style="color:#64748b">■ Zero Padding (0x00)</strong></span>
            <span><strong class="text-emerald">➕ Length Append (${is64 ? 128 : 64}-bit)</strong></span>
          </div>
        </div>

        <!-- Step 3: Message Schedule Expansion -->
        <div class="glass-panel" style="padding: 1.25rem; margin-bottom: 1rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
            <h4 style="color:var(--accent-emerald); font-size: 1rem;">Step 3: Message Schedule Expansion (W₀ to W_${blocks[0].expandedSchedule.length - 1})</h4>
            <span class="badge badge-emerald font-mono">${blocks[0].expandedSchedule.length} Words Total</span>
          </div>

          <div style="max-height: 250px; overflow-y: auto; overflow-x: auto; border: 1px solid rgba(255,255,255,0.08); border-radius: 8px;">
            <table class="comparison-table" style="font-size:0.82rem;">
              <thead>
                <tr>
                  <th>Word Index</th>
                  <th>Classification</th>
                  <th>Hex Value</th>
                  <th>Calculation Formula</th>
                </tr>
              </thead>
              <tbody>
                ${blocks[0].wExpansionSteps.map(step => {
                  const hex = is64 ? u64ToHex(step.val) : u32ToHex(step.val);
                  return `
                    <tr>
                      <td class="font-mono text-cyan">W[${step.t}]</td>
                      <td><span class="badge ${step.isDirect ? 'badge-blue' : 'badge-purple'}">${step.isDirect ? 'Direct Input' : 'Expanded'}</span></td>
                      <td class="font-mono font-bold text-amber">0x${hex.toUpperCase()}</td>
                      <td class="font-mono text-slate-300">${step.formula}</td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  function renderRoundsViewer(container, result, currentStepIdx, onStepChange) {
    const { algorithm, traces } = result;
    if (!traces || !traces[0] || !traces[0].steps) {
      container.innerHTML = '<div style="padding:1rem;">No round trace available.</div>';
      return;
    }

    const steps = traces[0].steps;
    const totalSteps = steps.length;
    const stepIdx = Math.max(0, Math.min(totalSteps - 1, currentStepIdx || 0));
    const stepData = steps[stepIdx];
    const is64 = algorithm === 'SHA-512';

    container.innerHTML = `
      <div class="round-viewer-wrap">
        <div class="glass-panel" style="padding: 1.25rem; margin-bottom: 1.25rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem; margin-bottom:1rem;">
            <div>
              <h3 style="font-size: 1.15rem; display:flex; align-items:center; gap:0.5rem;">
                <span>⚡ Round Compression Stepper</span>
                <span class="badge badge-purple">${algorithm}</span>
                <span class="badge badge-cyan">Round ${stepIdx + 1} of ${totalSteps}</span>
              </h3>
              <p style="color:var(--text-muted); font-size:0.85rem;">
                Inspect working register values ($A \\dots H$), constants ($K_t$), and bit-mixing formulas at any specific round.
              </p>
            </div>

            <!-- Controls -->
            <div style="display:flex; align-items:center; gap:0.5rem;">
              <button class="btn btn-sm btn-slate" id="btn-step-prev" ${stepIdx === 0 ? 'disabled' : ''}>◀ Prev</button>
              <button class="btn btn-sm btn-cyan" id="btn-step-play">▶ Auto Step</button>
              <button class="btn btn-sm btn-slate" id="btn-step-next" ${stepIdx === totalSteps - 1 ? 'disabled' : ''}>Next ▶</button>
            </div>
          </div>

          <!-- Slider -->
          <div style="display:flex; align-items:center; gap:1rem; margin-bottom:1rem;">
            <span class="font-mono text-xs text-slate-400">Round 1</span>
            <input type="range" id="round-slider" min="0" max="${totalSteps - 1}" value="${stepIdx}" style="flex-grow:1; cursor:pointer;" />
            <span class="font-mono text-xs text-slate-400">Round ${totalSteps}</span>
          </div>

          <!-- Formula & Constants Box -->
          <div style="background:rgba(0,0,0,0.3); padding:0.85rem 1rem; border-radius:8px; border:1px solid rgba(255,255,255,0.08); margin-bottom:1rem; font-family:var(--font-mono); font-size:0.85rem;">
            <div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:0.5rem; margin-bottom:0.4rem;">
              <span class="text-amber"><strong>Constant K[${stepIdx}]:</strong> 0x${is64 ? u64ToHex(stepData.kVal).toUpperCase() : u32ToHex(stepData.kVal).toUpperCase()}</span>
              <span class="text-purple"><strong>Word W[${stepIdx}]:</strong> 0x${is64 ? u64ToHex(stepData.wVal).toUpperCase() : u32ToHex(stepData.wVal).toUpperCase()}</span>
              ${stepData.fnName ? `<span class="text-cyan"><strong>Logic:</strong> ${stepData.fnName}</span>` : ''}
            </div>
            <div style="color:var(--text-muted); font-size:0.8rem;">
              ${stepData.formula || ''}
            </div>
          </div>

          <!-- Registers State Table -->
          <h4 style="font-size:0.9rem; margin-bottom:0.6rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em;">
            Working Registers After Round ${stepIdx + 1}:
          </h4>
          <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:0.75rem;">
            ${Object.entries(stepData.stateAfter).map(([reg, val]) => {
              const hexVal = is64 ? u64ToHex(val).toUpperCase() : u32ToHex(val).toUpperCase();
              return `
                <div class="glass-panel" style="padding:0.75rem 1rem; border:1px solid rgba(255,255,255,0.08);">
                  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
                    <span class="font-bold text-cyan" style="font-size:1.05rem;">Register ${reg}</span>
                    <span class="badge badge-slate font-mono" style="font-size:0.7rem;">${is64 ? '64-bit' : '32-bit'}</span>
                  </div>
                  <div class="font-mono font-bold text-amber" style="font-size:0.95rem; word-break:break-all;">0x${hexVal}</div>
                </div>
              `;
            }).join('')}
          </div>
        </div>
      </div>
    `;

    const slider = container.querySelector('#round-slider');
    const prevBtn = container.querySelector('#btn-step-prev');
    const nextBtn = container.querySelector('#btn-step-next');
    const playBtn = container.querySelector('#btn-step-play');

    if (slider) slider.oninput = (e) => onStepChange(parseInt(e.target.value, 10));
    if (prevBtn) prevBtn.onclick = () => onStepChange(stepIdx - 1);
    if (nextBtn) nextBtn.onclick = () => onStepChange(stepIdx + 1);
    if (playBtn) {
      if (window.__stepPlayInterval) {
        clearInterval(window.__stepPlayInterval);
        window.__stepPlayInterval = null;
        playBtn.textContent = '▶ Auto Step';
        playBtn.classList.remove('btn-amber');
        playBtn.classList.add('btn-cyan');
      } else {
        playBtn.textContent = '⏸ Pause';
        playBtn.classList.add('btn-amber');
        playBtn.classList.remove('btn-cyan');
        window.__stepPlayInterval = setInterval(() => {
          let next = (parseInt(slider.value, 10) + 1) % totalSteps;
          onStepChange(next);
        }, 800);
      }
    }
  }

  function renderSecurityMatrix(container) {
    container.innerHTML = `
      <div class="security-view-wrap">
        <!-- 3 Big Real World Stories -->
        <h3 style="font-size: 1.15rem; margin-bottom: 1rem;">🌍 Where are Hashes Used in Everyday Life?</h3>
        
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap:1rem; margin-bottom:1.5rem;">
          <div class="glass-panel" style="padding:1.25rem;">
            <div style="font-size:1.6rem; margin-bottom:0.5rem;">🔑</div>
            <h4 style="font-size:1rem; margin-bottom:0.35rem;" class="text-cyan">1. Password Protection</h4>
            <p style="font-size:0.85rem; color:#cbd5e1; line-height:1.5;">
              Websites never store your actual password in their database. They only save its hash! When you sign in, they hash what you typed and compare the hashes. Even if hackers breach the database, they only see garbled hash strings.
            </p>
          </div>

          <div class="glass-panel" style="padding:1.25rem;">
            <div style="font-size:1.6rem; margin-bottom:0.5rem;">🪙</div>
            <h4 style="font-size:1rem; margin-bottom:0.35rem;" class="text-amber">2. Bitcoin & Proof-of-Work</h4>
            <p style="font-size:0.85rem; color:#cbd5e1; line-height:1.5;">
              Bitcoin mining is a global lottery using SHA-256. Miners repeatedly hash the block data combined with a random number (nonce) trillions of times per second until they find a hash that starts with a required number of zeroes.
            </p>
          </div>

          <div class="glass-panel" style="padding:1.25rem;">
            <div style="font-size:1.6rem; margin-bottom:0.5rem;">🛡️</div>
            <h4 style="font-size:1rem; margin-bottom:0.35rem;" class="text-emerald">3. Anti-Tampering & Software Updates</h4>
            <p style="font-size:0.85rem; color:#cbd5e1; line-height:1.5;">
              When your phone downloads an OS update, it calculates the hash of the file. If even a single byte was altered by malware or a bad connection, the hash changes completely and your device refuses to install it.
            </p>
          </div>
        </div>

        <!-- Algorithm Comparison Table -->
        <div class="glass-panel" style="padding: 1.25rem;">
          <h3 style="font-size: 1.15rem; margin-bottom: 0.5rem;">📊 Technical Algorithm Comparison</h3>
          <div style="overflow-x:auto;">
            <table class="comparison-table" style="font-size:0.85rem;">
              <thead>
                <tr>
                  <th>Cryptographic Property</th>
                  <th>MD5</th>
                  <th>SHA-1</th>
                  <th>SHA-256</th>
                  <th>SHA-512</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>Output Length</strong></td>
                  <td class="font-mono text-amber">128 bits (16 B)</td>
                  <td class="font-mono text-purple">160 bits (20 B)</td>
                  <td class="font-mono text-cyan">256 bits (32 B)</td>
                  <td class="font-mono text-emerald">512 bits (64 B)</td>
                </tr>
                <tr>
                  <td><strong>Spin Rounds</strong></td>
                  <td class="font-mono">64 (4 × 16)</td>
                  <td class="font-mono">80 (4 × 20)</td>
                  <td class="font-mono">64 rounds</td>
                  <td class="font-mono">80 rounds</td>
                </tr>
                <tr>
                  <td><strong>Security Status</strong></td>
                  <td><span class="badge badge-rose">BROKEN (2¹⁸ ops)</span></td>
                  <td><span class="badge badge-rose">BROKEN (SHAttered)</span></td>
                  <td><span class="badge badge-emerald">SECURE & APPROVED</span></td>
                  <td><span class="badge badge-emerald">SECURE & APPROVED</span></td>
                </tr>
                <tr>
                  <td><strong>Why / Where Used</strong></td>
                  <td>Fast non-security checksums</td>
                  <td>Legacy Git commit IDs</td>
                  <td>Bitcoin, TLS/SSL, Web Tokens</td>
                  <td>64-bit architectures, CA certs</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  // ==========================================
  // 6. MAIN APPLICATION CONTROLLER
  // ==========================================
  class HashApp {
    constructor() {
      this.activeAlgorithm = 'SHA-256';
      this.inputText = '';
      this.inputBytes = stringToUtf8Bytes(this.inputText);
      this.activeTab = 'story';
      this.currentRoundStep = 0;
      this.lastResult = null;

      this.init();
    }

    init() {
      this.inputArea = document.getElementById('main-text-input');
      this.digestHexDisplay = document.getElementById('digest-hex-value');
      this.digestLenBadge = document.getElementById('digest-len-badge');
      this.blockCountBadge = document.getElementById('block-count-badge');
      this.timeBadge = document.getElementById('calc-time-badge');
      this.btnCopyHash = document.getElementById('btn-copy-hash');

      this.tabContentContainer = document.getElementById('dynamic-tab-content');

      this.bindEvents();
      this.calculate();
    }

    bindEvents() {
      const algoButtons = document.querySelectorAll('.algo-selector-btn');
      algoButtons.forEach(btn => {
        btn.addEventListener('click', () => {
          algoButtons.forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          this.activeAlgorithm = btn.dataset.algo;
          this.currentRoundStep = 0;
          this.calculate();
        });
      });

      const navTabs = document.querySelectorAll('.nav-tab-btn');
      navTabs.forEach(tab => {
        tab.addEventListener('click', () => {
          navTabs.forEach(t => t.classList.remove('active'));
          tab.classList.add('active');
          this.activeTab = tab.dataset.tab;
          this.renderTab();
        });
      });

      if (this.inputArea) {
        this.inputArea.addEventListener('input', (e) => {
          this.inputText = e.target.value;
          this.inputBytes = stringToUtf8Bytes(this.inputText);
          this.calculate();
        });
      }

      document.querySelectorAll('.preset-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const preset = btn.dataset.preset;
          let val = '';
          if (preset === 'empty') val = '';
          else if (preset === 'abc') val = 'abc';
          else if (preset === 'fox') val = 'The quick brown fox jumps over the lazy dog';
          else if (preset === 'bitcoin') val = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c';
          
          this.inputText = val;
          if (this.inputArea) this.inputArea.value = val;
          this.inputBytes = stringToUtf8Bytes(val);
          this.calculate();
        });
      });

      const fileInput = document.getElementById('file-upload-input');
      if (fileInput) {
        fileInput.addEventListener('change', (e) => {
          const file = e.target.files[0];
          if (file) {
            const reader = new FileReader();
            reader.onload = (ev) => {
              this.inputBytes = new Uint8Array(ev.target.result);
              this.inputText = `[Binary File: ${file.name}]`;
              if (this.inputArea) {
                this.inputArea.value = this.inputText;
              }
              this.calculate();
            };
            reader.readAsArrayBuffer(file);
          }
        });
      }

      if (this.btnCopyHash) {
        this.btnCopyHash.addEventListener('click', () => {
          const text = this.digestHexDisplay ? this.digestHexDisplay.textContent.trim() : '';
          if (text) {
            navigator.clipboard.writeText(text).then(() => {
              const orig = this.btnCopyHash.innerHTML;
              this.btnCopyHash.innerHTML = '✓ Copied!';
              this.btnCopyHash.classList.add('btn-emerald');
              setTimeout(() => {
                this.btnCopyHash.innerHTML = orig;
                this.btnCopyHash.classList.remove('btn-emerald');
              }, 1500);
            });
          }
        });
      }
    }

    calculate() {
      if (this.inputText === '') {
        if (this.digestHexDisplay) this.digestHexDisplay.textContent = '';
        if (this.digestLenBadge) this.digestLenBadge.textContent = '';
        if (this.blockCountBadge) this.blockCountBadge.textContent = '';
        if (this.timeBadge) this.timeBadge.textContent = '';
        
        const elMd5 = document.getElementById('preview-md5');
        const elSha1 = document.getElementById('preview-sha1');
        const elSha256 = document.getElementById('preview-sha256');
        const elSha512 = document.getElementById('preview-sha512');
        if (elMd5) elMd5.textContent = '';
        if (elSha1) elSha1.textContent = '';
        if (elSha256) elSha256.textContent = '';
        if (elSha512) elSha512.textContent = '';

        if (this.tabContentContainer) this.tabContentContainer.innerHTML = '';
        return;
      }

      const startTime = performance.now();
      let result;

      switch (this.activeAlgorithm) {
        case 'MD5':
          result = runMD5(this.inputBytes);
          break;
        case 'SHA-1':
          result = runSHA1(this.inputBytes);
          break;
        case 'SHA-256':
          result = runSHA256(this.inputBytes);
          break;
        case 'SHA-512':
          result = runSHA512(this.inputBytes);
          break;
        default:
          result = runSHA256(this.inputBytes);
      }

      const elapsed = (performance.now() - startTime).toFixed(2);
      this.lastResult = result;

      if (this.digestHexDisplay) this.digestHexDisplay.textContent = result.digestHex;
      if (this.digestLenBadge) {
        const bitLen = result.digestBytes.length * 8;
        this.digestLenBadge.textContent = `${bitLen}-bit (${result.digestBytes.length} Bytes)`;
      }
      if (this.blockCountBadge) {
        this.blockCountBadge.textContent = `${result.blockCount} Block${result.blockCount > 1 ? 's' : ''} (${result.paddedLength} Bytes)`;
      }
      if (this.timeBadge) {
        this.timeBadge.textContent = `${elapsed} ms`;
      }

      this.updateAllHashes(this.inputBytes);
      this.renderTab();
    }

    updateAllHashes(bytes) {
      const md5Res = runMD5(bytes);
      const sha1Res = runSHA1(bytes);
      const sha256Res = runSHA256(bytes);
      const sha512Res = runSHA512(bytes);

      const elMd5 = document.getElementById('preview-md5');
      const elSha1 = document.getElementById('preview-sha1');
      const elSha256 = document.getElementById('preview-sha256');
      const elSha512 = document.getElementById('preview-sha512');

      if (elMd5) elMd5.textContent = md5Res.digestHex;
      if (elSha1) elSha1.textContent = sha1Res.digestHex;
      if (elSha256) elSha256.textContent = sha256Res.digestHex;
      if (elSha512) elSha512.textContent = sha512Res.digestHex;
    }

    renderTab() {
      if (!this.tabContentContainer || !this.lastResult) return;

      if (this.activeTab === 'story') {
        renderStoryMode(this.tabContentContainer, this.lastResult, this.inputText);
      } else if (this.activeTab === 'workflow') {
        renderWorkflow(this.tabContentContainer, this.lastResult);
      } else if (this.activeTab === 'rounds') {
        renderRoundsViewer(this.tabContentContainer, this.lastResult, this.currentRoundStep, (newStep) => {
          this.currentRoundStep = newStep;
          this.renderTab();
        });
      } else if (this.activeTab === 'avalanche') {
        renderAvalancheLab(this.tabContentContainer, this.inputText, this.activeAlgorithm);
      } else if (this.activeTab === 'security') {
        renderSecurityMatrix(this.tabContentContainer);
      }
    }
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        window.cryptoApp = new HashApp();
      });
    } else {
      window.cryptoApp = new HashApp();
    }
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { md5: runMD5, sha1: runSHA1, sha256: runSHA256, sha512: runSHA512 };
  }
})(typeof window !== 'undefined' ? window : this);
