/**
 * Workflow & Bits/Bytes Pipeline Visualizer Component
 * Renders conversion steps: Text -> Bytes -> Bits -> Padding -> Blocks -> Words -> Schedule
 */
import { formatBinarySpaced, u32ToHex, u64ToHex, byteToBinaryString } from '../crypto/utils.js';

export function renderWorkflowView(container, cryptoResult, activeAlgorithm) {
  if (!container || !cryptoResult) return;

  const { originalLength, paddedLength, blockCount, blocks, paddedBytes, algorithm } = cryptoResult;
  const is64Bit = algorithm === 'SHA-512';
  const blockBitSize = is64Bit ? 1024 : 512;
  const wordBitSize = is64Bit ? 64 : 32;
  const wordCount = 16;
  const endianness = algorithm === 'MD5' ? 'Little-Endian' : 'Big-Endian';

  const origBits = originalLength * 8;
  const padBits = paddedLength * 8;
  const kZeros = padBits - origBits - (is64Bit ? 128 : 64) - 8;

  let html = `
    <div class="workflow-container">
      <div class="section-header">
        <div>
          <h2>🔬 Bits & Bytes Conversion Pipeline</h2>
          <p class="section-desc">Trace the exact mathematical transformation from raw string to 512/1024-bit padded blocks and message schedule expansion.</p>
        </div>
        <div class="meta-badges">
          <span class="badge badge-cyan">${algorithm}</span>
          <span class="badge badge-purple">${endianness}</span>
          <span class="badge badge-blue">${blockBitSize}-bit Block</span>
          <span class="badge badge-emerald">${wordBitSize}-bit Words</span>
        </div>
      </div>

      <!-- Step 1: Input & Byte Stream -->
      <div class="step-card glass-panel">
        <div class="step-header">
          <span class="step-number">01</span>
          <div>
            <h3>Input String to Byte Stream (UTF-8 / ASCII)</h3>
            <p class="step-sub">Original Length: <strong>${originalLength} bytes (${origBits} bits)</strong></p>
          </div>
        </div>
        
        <div class="byte-grid-container">
          ${originalLength === 0 ? '<div class="empty-hint">Empty input string (0 bytes)</div>' : `
            <div class="byte-stream-table">
              <div class="stream-row header-row">
                <span class="col-idx">Idx</span>
                <span class="col-char">Char</span>
                <span class="col-dec">Dec</span>
                <span class="col-hex">Hex</span>
                <span class="col-bin">Binary (8-bit)</span>
              </div>
              ${blocks[0]?.rawBytes?.slice(0, originalLength).map((b, i) => {
                const ch = b >= 32 && b <= 126 ? String.fromCharCode(b) : '•';
                return `
                  <div class="stream-row">
                    <span class="col-idx">[${i}]</span>
                    <span class="col-char font-mono">"${ch}"</span>
                    <span class="col-dec font-mono">${b}</span>
                    <span class="col-hex font-mono">0x${b.toString(16).padStart(2, '0').toUpperCase()}</span>
                    <span class="col-bin font-mono text-cyan">${byteToBinaryString(b)}</span>
                  </div>
                `;
              }).join('')}
            </div>
          `}
        </div>
      </div>

      <!-- Step 2: Bit Padding Pipeline -->
      <div class="step-card glass-panel">
        <div class="step-header">
          <span class="step-number">02</span>
          <div>
            <h3>Bit Padding & Length Append (RFC / FIPS Standard)</h3>
            <p class="step-sub">Padded: <strong>${paddedLength} bytes (${padBits} bits) across ${blockCount} block(s)</strong></p>
          </div>
        </div>

        <div class="padding-formula-box">
          <div class="formula-title">Padding Formula:</div>
          <div class="formula-math">
            $M_{\\text{padded}} = M \\parallel \\mathbf{1} \\parallel \\mathbf{0}^{k} \\parallel \\text{Length}_{\\text{${is64Bit ? 128 : 64}}}$
          </div>
          <div class="formula-details">
            <span class="formula-item"><strong class="text-cyan">Message M:</strong> ${origBits} bits</span>
            <span class="formula-item"><strong class="text-amber">'1' bit + 7 zeros:</strong> 0x80 (8 bits)</span>
            <span class="formula-item"><strong class="text-purple">k Zero bits:</strong> ${Math.max(0, kZeros)} bits</span>
            <span class="formula-item"><strong class="text-emerald">${is64Bit ? 128 : 64}-bit Length:</strong> ${origBits} (${endianness})</span>
          </div>
        </div>

        <div class="padded-bytes-visualizer">
          <h4>Padded Block Structure (${is64Bit ? '1024-bit / 128-byte' : '512-bit / 64-byte'} blocks):</h4>
          <div class="blocks-accordion">
            ${blocks.map((block, bIdx) => `
              <div class="block-card">
                <div class="block-card-header">
                  <span class="block-title">Block #${bIdx + 1} (Bytes ${bIdx * (is64Bit ? 128 : 64)} to ${(bIdx + 1) * (is64Bit ? 128 : 64) - 1})</span>
                  <span class="badge badge-slate">${is64Bit ? '128 Bytes' : '64 Bytes'}</span>
                </div>
                <div class="hex-dump-grid">
                  ${block.rawBytes.map((byte, i) => {
                    const absIdx = bIdx * (is64Bit ? 128 : 64) + i;
                    let typeClass = 'byte-msg';
                    let tooltip = `Message Byte [${absIdx}]`;

                    if (absIdx === originalLength) {
                      typeClass = 'byte-one';
                      tooltip = 'Padding Start (0x80 = 10000000_2)';
                    } else if (absIdx > originalLength && absIdx < paddedLength - (is64Bit ? 16 : 8)) {
                      typeClass = 'byte-zero';
                      tooltip = 'Padding Zero (0x00)';
                    } else if (absIdx >= paddedLength - (is64Bit ? 16 : 8)) {
                      typeClass = 'byte-len';
                      tooltip = `Length Field (${is64Bit ? 128 : 64}-bit ${endianness})`;
                    }

                    return `
                      <div class="hex-byte ${typeClass}" title="${tooltip}: 0x${byte.toString(16).padStart(2, '0').toUpperCase()}">
                        <span class="byte-val">${byte.toString(16).padStart(2, '0').toUpperCase()}</span>
                        <span class="byte-idx">${i}</span>
                      </div>
                    `;
                  }).join('')}
                </div>
                <div class="hex-legend">
                  <span class="legend-item"><span class="color-dot dot-msg"></span> Message Data</span>
                  <span class="legend-item"><span class="color-dot dot-one"></span> '1' Bit (0x80)</span>
                  <span class="legend-item"><span class="color-dot dot-zero"></span> Zero Padding</span>
                  <span class="legend-item"><span class="color-dot dot-len"></span> Length Field (${endianness})</span>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>

      <!-- Step 3: Word Slicing & Endianness Parsing -->
      <div class="step-card glass-panel">
        <div class="step-header">
          <span class="step-number">03</span>
          <div>
            <h3>Word Unpacking & Endianness Architecture (${endianness})</h3>
            <p class="step-sub">Parsing 16 ${wordBitSize}-bit words from Block #1</p>
          </div>
        </div>

        <div class="endianness-explanation">
          <p>
            ${algorithm === 'MD5'
              ? '<strong>MD5 uses Little-Endian word packing:</strong> Byte 0 is the Least Significant Byte (LSB), and Byte 3 is the Most Significant Byte (MSB). Formula: <code>W = Byte0 | (Byte1 &lt;&lt; 8) | (Byte2 &lt;&lt; 16) | (Byte3 &lt;&lt; 24)</code>.'
              : `<strong>${algorithm} uses Big-Endian word packing:</strong> Byte 0 is the Most Significant Byte (MSB), and Byte ${is64Bit ? '7' : '3'} is the Least Significant Byte (LSB). Formula: <code>W = (Byte0 &lt;&lt; ${is64Bit ? '56' : '24'}) | ... | Byte${is64Bit ? '7' : '3'}</code>.`
            }
          </p>
        </div>

        <div class="words-grid">
          ${blocks[0]?.words?.map((word, wIdx) => {
            const hexStr = is64Bit ? u64ToHex(word) : u32ToHex(word);
            return `
              <div class="word-card">
                <div class="word-header">
                  <span class="word-name">M[${wIdx}] / W[${wIdx}]</span>
                  <span class="word-idx">Offset ${wIdx * (is64Bit ? 8 : 4)}</span>
                </div>
                <div class="word-hex font-mono">0x${hexStr.toUpperCase()}</div>
                <div class="word-bytes-breakdown">
                  ${Array.from({ length: is64Bit ? 8 : 4 }).map((_, bi) => {
                    const rawByte = blocks[0].rawBytes[wIdx * (is64Bit ? 8 : 4) + bi];
                    return `<span class="word-sub-byte" title="Byte ${bi}">0x${rawByte.toString(16).padStart(2, '0').toUpperCase()}</span>`;
                  }).join('')}
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>

      <!-- Step 4: Message Schedule Expansion (SHA-1, SHA-256, SHA-512) -->
      ${algorithm !== 'MD5' ? `
        <div class="step-card glass-panel">
          <div class="step-header">
            <span class="step-number">04</span>
            <div>
              <h3>Message Schedule Expansion (W₀ to W_${algorithm === 'SHA-256' ? '63' : '79'})</h3>
              <p class="step-sub">Expanding initial 16 words into ${algorithm === 'SHA-256' ? '64' : '80'} round words via bitwise rotations and additions</p>
            </div>
          </div>

          <div class="schedule-formula-box">
            ${algorithm === 'SHA-1' ? `
              <div class="formula-math">
                $W_t = (W_{t-3} \\oplus W_{t-8} \\oplus W_{t-14} \\oplus W_{t-16}) \\lll 1 \\quad (16 \\le t \\le 79)$
              </div>
            ` : algorithm === 'SHA-256' ? `
              <div class="formula-math">
                $W_t = W_{t-16} + \\sigma_0(W_{t-15}) + W_{t-7} + \\sigma_1(W_{t-2}) \\pmod{2^{32}} \\quad (16 \\le t \\le 63)$
              </div>
              <div class="sub-formulas">
                <span>$\\sigma_0(x) = (x \\ggg 7) \\oplus (x \\ggg 18) \\oplus (x \\gg 3)$</span>
                <span>$\\sigma_1(x) = (x \\ggg 17) \\oplus (x \\ggg 19) \\oplus (x \\gg 10)$</span>
              </div>
            ` : `
              <div class="formula-math">
                $W_t = W_{t-16} + \\sigma_0(W_{t-15}) + W_{t-7} + \\sigma_1(W_{t-2}) \\pmod{2^{64}} \\quad (16 \\le t \\le 79)$
              </div>
              <div class="sub-formulas">
                <span>$\\sigma_0(x) = (x \\ggg 1) \\oplus (x \\ggg 8) \\oplus (x \\gg 7)$</span>
                <span>$\\sigma_1(x) = (x \\ggg 19) \\oplus (x \\ggg 61) \\oplus (x \\gg 6)$</span>
              </div>
            `}
          </div>

          <div class="schedule-table-wrapper">
            <table class="schedule-table">
              <thead>
                <tr>
                  <th>Index t</th>
                  <th>Type</th>
                  <th>Word Hex</th>
                  <th>Expansion Calculation Details</th>
                </tr>
              </thead>
              <tbody>
                ${blocks[0]?.wExpansionSteps?.map((step) => {
                  const hexStr = is64Bit ? u64ToHex(step.val) : u32ToHex(step.val);
                  return `
                    <tr class="${step.isDirect ? 'row-direct' : 'row-expanded'}">
                      <td class="font-mono text-cyan">W[${step.t}]</td>
                      <td>
                        <span class="badge ${step.isDirect ? 'badge-blue' : 'badge-purple'}">
                          ${step.isDirect ? 'Direct Input' : 'Expanded'}
                        </span>
                      </td>
                      <td class="font-mono font-bold text-amber">0x${hexStr.toUpperCase()}</td>
                      <td class="font-mono text-sm text-slate-300">${step.formula}</td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      ` : ''}

    </div>
  `;

  container.innerHTML = html;
}
