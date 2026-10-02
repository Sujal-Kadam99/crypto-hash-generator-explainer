/**
 * Avalanche Effect Explorer & Diffusion Visualizer
 * Live comparison of 1-bit input flip and diffusion progression across rounds
 */
import { md5 } from '../crypto/md5.js';
import { sha1 } from '../crypto/sha1.js';
import { sha256 } from '../crypto/sha256.js';
import { sha512 } from '../crypto/sha512.js';
import { stringToUtf8Bytes, byteToBinaryString, hammingDistance32, hammingDistance64, u32ToHex, u64ToHex, u32ToBinary, u64ToBinary } from '../crypto/utils.js';

export class AvalancheLab {
  constructor(container) {
    this.container = container;
    this.activeAlgorithm = 'SHA-256';
    this.baseInput = 'Hello World';
    this.flippedInput = 'Hello World!';
  }

  render(algorithm = 'SHA-256') {
    this.activeAlgorithm = algorithm;
    const runner = this.getRunner(algorithm);

    const baseBytes = stringToUtf8Bytes(this.baseInput);
    const flippedBytes = stringToUtf8Bytes(this.flippedInput);

    const baseResult = runner(baseBytes);
    const flippedResult = runner(flippedBytes);

    const totalDigestBits = algorithm === 'MD5' ? 128 : algorithm === 'SHA-1' ? 160 : algorithm === 'SHA-256' ? 256 : 512;
    const is64Bit = algorithm === 'SHA-512';

    // Calculate final digest hamming distance
    let finalHamming = 0;
    const baseDigestBin = this.hexToBinary(baseResult.digestHex);
    const flippedDigestBin = this.hexToBinary(flippedResult.digestHex);

    for (let i = 0; i < totalDigestBits; i++) {
      if (baseDigestBin[i] !== flippedDigestBin[i]) finalHamming++;
    }
    const finalPercent = ((finalHamming / totalDigestBits) * 100).toFixed(1);

    // Calculate round-by-round bit flip progression
    const maxSteps = Math.min(
      baseResult.traces[0]?.steps.length || 0,
      flippedResult.traces[0]?.steps.length || 0
    );

    const roundDiffs = [];
    for (let step = 0; step < maxSteps; step++) {
      const stepA = baseResult.traces[0].steps[step];
      const stepB = flippedResult.traces[0].steps[step];
      const regKeys = Object.keys(stepA.stateAfter);
      let stepHamming = 0;
      let totalStepBits = regKeys.length * (is64Bit ? 64 : 32);

      regKeys.forEach(k => {
        const valA = stepA.stateAfter[k];
        const valB = stepB.stateAfter[k];
        stepHamming += is64Bit ? hammingDistance64(valA, valB) : hammingDistance32(valA, valB);
      });

      const pct = (stepHamming / totalStepBits) * 100;
      roundDiffs.push({
        step: step + 1,
        hamming: stepHamming,
        totalBits: totalStepBits,
        percentage: pct.toFixed(1)
      });
    }

    this.container.innerHTML = `
      <div class="avalanche-container">
        <div class="section-header">
          <div>
            <h2>🌊 Avalanche Effect & Diffusion Lab</h2>
            <p class="section-desc">Observe how flipping a single input bit propagates exponentially across rounds to achieve the Strict Avalanche Criterion (SAC ≈ 50%).</p>
          </div>
          <div class="meta-badges">
            <span class="badge badge-cyan">${algorithm}</span>
            <span class="badge ${finalPercent >= 45 && finalPercent <= 55 ? 'badge-emerald' : 'badge-amber'}">
              Digest Diff: ${finalPercent}% (${finalHamming}/${totalDigestBits} bits)
            </span>
          </div>
        </div>

        <!-- Input Comparison Boxes -->
        <div class="avalanche-inputs-grid">
          <div class="avalanche-input-card glass-panel">
            <div class="card-header">
              <span class="badge badge-blue">Input A (Original)</span>
              <span class="text-sm font-mono text-slate-400">${baseBytes.length} bytes</span>
            </div>
            <input type="text" id="avalanche-input-a" class="custom-text-input font-mono" value="${this.escapeHtml(this.baseInput)}" />
            <div class="digest-preview">
              <span class="preview-label">Digest A:</span>
              <span class="font-mono text-cyan text-sm">${baseResult.digestHex}</span>
            </div>
          </div>

          <div class="avalanche-input-card glass-panel">
            <div class="card-header">
              <span class="badge badge-purple">Input B (Modified)</span>
              <button id="btn-flip-one-bit" class="btn btn-sm btn-amber" title="Toggle 1 bit in character">⚡ Flip 1 Bit</button>
            </div>
            <input type="text" id="avalanche-input-b" class="custom-text-input font-mono" value="${this.escapeHtml(this.flippedInput)}" />
            <div class="digest-preview">
              <span class="preview-label">Digest B:</span>
              <span class="font-mono text-amber text-sm">${flippedResult.digestHex}</span>
            </div>
          </div>
        </div>

        <!-- Metric Stat Cards -->
        <div class="stats-row">
          <div class="stat-card glass-panel">
            <span class="stat-title">Input Difference</span>
            <span class="stat-value text-cyan">${this.computeInputBitDiff(baseBytes, flippedBytes)} bits</span>
            <span class="stat-sub">Microscopic input delta</span>
          </div>
          <div class="stat-card glass-panel">
            <span class="stat-title">Final Hash Difference</span>
            <span class="stat-value ${finalPercent >= 45 && finalPercent <= 55 ? 'text-emerald' : 'text-amber'}">${finalHamming} / ${totalDigestBits}</span>
            <span class="stat-sub font-mono font-bold">${finalPercent}% bits flipped</span>
          </div>
          <div class="stat-card glass-panel">
            <span class="stat-title">Avalanche Saturation</span>
            <span class="stat-value text-purple">${roundDiffs.findIndex(r => parseFloat(r.percentage) >= 45) + 1 || 'N/A'} Rounds</span>
            <span class="stat-sub">Rounds to reach ~50% SAC</span>
          </div>
        </div>

        <!-- Round Progression Heatmap & Chart -->
        <div class="chart-panel glass-panel">
          <div class="panel-header">
            <h3>📈 Diffusion Rate across Rounds 1 to ${maxSteps}</h3>
            <span class="badge badge-slate">Ideal Target: 50.0%</span>
          </div>

          <div class="round-bars-chart">
            ${roundDiffs.map(r => {
              const heightPct = Math.min(100, Math.max(4, parseFloat(r.percentage)));
              const colorClass = heightPct >= 45 && heightPct <= 55 ? 'bar-ideal' : heightPct > 55 ? 'bar-high' : 'bar-low';
              return `
                <div class="chart-bar-column" title="Round ${r.step}: ${r.percentage}% (${r.hamming}/${r.totalBits} bits)">
                  <div class="bar-fill ${colorClass}" style="height: ${heightPct}%;"></div>
                  <span class="bar-step-num font-mono">${r.step % 5 === 0 || r.step === 1 ? r.step : ''}</span>
                </div>
              `;
            }).join('')}
          </div>
          <div class="chart-x-axis">
            <span>Round 1</span>
            <span>Round ${Math.floor(maxSteps / 2)}</span>
            <span>Round ${maxSteps}</span>
          </div>
        </div>

        <!-- Binary Digest Comparison Grid -->
        <div class="digest-compare-panel glass-panel">
          <div class="panel-header">
            <h3>🔬 Bit-by-Bit Digest Comparison Matrix</h3>
            <span class="badge badge-cyan">${totalDigestBits} Bits Total</span>
          </div>

          <div class="bit-diff-stream font-mono">
            ${Array.from({ length: totalDigestBits }).map((_, i) => {
              const bitA = baseDigestBin[i] || '0';
              const bitB = flippedDigestBin[i] || '0';
              const isDiff = bitA !== bitB;
              return `
                <span class="diff-bit-cell ${isDiff ? 'bit-diff' : 'bit-same'}" title="Bit ${totalDigestBits - 1 - i}: A=${bitA}, B=${bitB} (${isDiff ? 'DIFF' : 'SAME'})">
                  ${bitB}
                </span>
              `;
            }).join('')}
          </div>
          <div class="diff-legend">
            <span class="legend-item"><span class="color-dot dot-diff"></span> Flipped Bit (${finalHamming})</span>
            <span class="legend-item"><span class="color-dot dot-same"></span> Identical Bit (${totalDigestBits - finalHamming})</span>
          </div>
        </div>

      </div>
    `;

    this.bindEvents();
  }

  bindEvents() {
    const inputA = this.container.querySelector('#avalanche-input-a');
    const inputB = this.container.querySelector('#avalanche-input-b');
    const flipBtn = this.container.querySelector('#btn-flip-one-bit');

    if (inputA) {
      inputA.oninput = (e) => {
        this.baseInput = e.target.value;
        this.render(this.activeAlgorithm);
      };
    }

    if (inputB) {
      inputB.oninput = (e) => {
        this.flippedInput = e.target.value;
        this.render(this.activeAlgorithm);
      };
    }

    if (flipBtn) {
      flipBtn.onclick = () => {
        if (!this.baseInput) {
          this.baseInput = 'A';
          this.flippedInput = 'B';
        } else {
          // Flip lowest bit of first character
          const firstCharCode = this.baseInput.charCodeAt(0);
          const flippedChar = String.fromCharCode(firstCharCode ^ 1);
          this.flippedInput = flippedChar + this.baseInput.slice(1);
        }
        this.render(this.activeAlgorithm);
      };
    }
  }

  computeInputBitDiff(bytesA, bytesB) {
    let diff = 0;
    const maxLen = Math.max(bytesA.length, bytesB.length);
    for (let i = 0; i < maxLen; i++) {
      const bA = bytesA[i] || 0;
      const bB = bytesB[i] || 0;
      let d = bA ^ bB;
      while (d) {
        diff += d & 1;
        d >>>= 1;
      }
    }
    return diff;
  }

  hexToBinary(hex) {
    let bin = '';
    for (let i = 0; i < hex.length; i++) {
      bin += parseInt(hex[i], 16).toString(2).padStart(4, '0');
    }
    return bin;
  }

  getRunner(algorithm) {
    switch (algorithm) {
      case 'MD5': return md5;
      case 'SHA-1': return sha1;
      case 'SHA-256': return sha256;
      case 'SHA-512': return sha512;
      default: return sha256;
    }
  }

  escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}
