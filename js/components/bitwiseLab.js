/**
 * Bitwise Logic & Cryptographic Primitives Playground
 * Interactive evaluator for Ch, Maj, Sigma, Rotates, Shifts, and Modular Additions
 */
import { rotr32, rotl32, shr32, add32, u32ToHex, u32ToBinary } from '../crypto/utils.js';
import { ch_256, maj_256, sigma0_256, sigma1_256, bigSigma0_256, bigSigma1_256 } from '../crypto/sha256.js';

export class BitwiseLab {
  constructor(container) {
    this.container = container;
    this.selectedFunction = 'Ch';
    this.valX = 0x5a5a5a5a >>> 0;
    this.valY = 0x0f0f0f0f >>> 0;
    this.valZ = 0x33333333 >>> 0;
    this.shiftAmount = 7;
  }

  render() {
    const result = this.calculate();

    this.container.innerHTML = `
      <div class="bitwise-lab-container">
        <div class="section-header">
          <div>
            <h2>🧮 Bitwise Logic & Primitive Playground</h2>
            <p class="section-desc">Test cryptographic building blocks (Ch, Maj, Σ, σ, Rotations) in isolation with live 32-bit registers.</p>
          </div>
          <div class="meta-badges">
            <span class="badge badge-purple font-mono">X = 0x${u32ToHex(this.valX).toUpperCase()}</span>
            <span class="badge badge-cyan font-mono">Y = 0x${u32ToHex(this.valY).toUpperCase()}</span>
            <span class="badge badge-amber font-mono">Z = 0x${u32ToHex(this.valZ).toUpperCase()}</span>
          </div>
        </div>

        <!-- Function Selector Tabs -->
        <div class="primitive-tabs glass-panel">
          <button class="prim-tab ${this.selectedFunction === 'Ch' ? 'active' : ''}" data-fn="Ch">Ch (Choice)</button>
          <button class="prim-tab ${this.selectedFunction === 'Maj' ? 'active' : ''}" data-fn="Maj">Maj (Majority)</button>
          <button class="prim-tab ${this.selectedFunction === 'Sigma0' ? 'active' : ''}" data-fn="Sigma0">Σ₀ (SHA-256)</button>
          <button class="prim-tab ${this.selectedFunction === 'Sigma1' ? 'active' : ''}" data-fn="Sigma1">Σ₁ (SHA-256)</button>
          <button class="prim-tab ${this.selectedFunction === 'sigma0' ? 'active' : ''}" data-fn="sigma0">σ₀ (Schedule)</button>
          <button class="prim-tab ${this.selectedFunction === 'sigma1' ? 'active' : ''}" data-fn="sigma1">σ₁ (Schedule)</button>
          <button class="prim-tab ${this.selectedFunction === 'ROTR' ? 'active' : ''}" data-fn="ROTR">ROTR (Circular Right)</button>
          <button class="prim-tab ${this.selectedFunction === 'ROTL' ? 'active' : ''}" data-fn="ROTL">ROTL (Circular Left)</button>
          <button class="prim-tab ${this.selectedFunction === 'ADD32' ? 'active' : ''}" data-fn="ADD32">Add Mod 2³²</button>
        </div>

        <!-- Interactive Formula Card -->
        <div class="formula-banner glass-panel">
          <div class="formula-info">
            <h3 class="text-cyan">${result.name}</h3>
            <p class="formula-expr font-mono">${result.formula}</p>
            <p class="formula-desc text-slate-300">${result.description}</p>
          </div>
          <div class="preset-buttons">
            <button class="btn btn-sm btn-slate" id="btn-preset-alternating">0xAAAA / 0x5555</button>
            <button class="btn btn-sm btn-slate" id="btn-preset-allones">0xFFFFFFFF</button>
            <button class="btn btn-sm btn-slate" id="btn-preset-random">🎲 Randomize</button>
          </div>
        </div>

        <!-- Interactive Bit Registers -->
        <div class="registers-interactive-grid glass-panel">
          <!-- Input X -->
          ${this.renderInputRegister('X', this.valX, '#a855f7')}

          <!-- Input Y (if needed) -->
          ${result.needsY ? this.renderInputRegister('Y', this.valY, '#00d2ff') : ''}

          <!-- Input Z (if needed) -->
          ${result.needsZ ? this.renderInputRegister('Z', this.valZ, '#f59e0b') : ''}

          <!-- Shift Control (if needed) -->
          ${result.needsShift ? `
            <div class="shift-slider-row">
              <label>Shift / Rotate Amount (bits): <strong class="text-emerald font-mono">${this.shiftAmount}</strong></label>
              <input type="range" id="shift-range" min="1" max="31" value="${this.shiftAmount}" class="custom-slider" />
            </div>
          ` : ''}

          <!-- Output Result -->
          <div class="output-register-card">
            <div class="reg-title-row">
              <span class="badge badge-emerald font-bold">OUTPUT RESULT</span>
              <span class="font-mono text-emerald font-bold text-lg">0x${u32ToHex(result.value).toUpperCase()}</span>
            </div>
            <div class="bit-cells-grid font-mono">
              ${this.renderOutputBits(result.value)}
            </div>
          </div>
        </div>

        <!-- Truth Table / Logic Guide -->
        <div class="logic-guide-card glass-panel">
          <h4>💡 Bitwise Logic Insight</h4>
          <p>${result.insight}</p>
        </div>
      </div>
    `;

    this.bindEvents();
  }

  renderInputRegister(label, val, accentColor) {
    const binStr = u32ToBinary(val);
    const hexStr = u32ToHex(val);

    return `
      <div class="interactive-reg-row" style="border-left: 3px solid ${accentColor}">
        <div class="reg-header-line">
          <span class="reg-lbl font-mono font-bold" style="color: ${accentColor}">Input ${label}</span>
          <div class="reg-inputs-sync">
            <span class="hex-lbl">Hex:</span>
            <input type="text" maxlength="8" class="hex-text-input font-mono" data-reg="${label}" value="${hexStr.toUpperCase()}" />
          </div>
        </div>
        <div class="bit-clicker-row font-mono">
          ${Array.from({ length: 32 }).map((_, i) => {
            const bitVal = binStr[i];
            return `
              <button class="bit-toggle-btn ${bitVal === '1' ? 'bit-is-1' : 'bit-is-0'}" data-reg="${label}" data-bit="${31 - i}" title="Click to toggle bit ${31 - i}">
                ${bitVal}
              </button>
            `;
          }).join('')}
        </div>
      </div>
    `;
  }

  renderOutputBits(val) {
    const binStr = u32ToBinary(val);
    return Array.from({ length: 32 }).map((_, i) => {
      const bitVal = binStr[i];
      return `
        <span class="output-bit-cell ${bitVal === '1' ? 'out-1' : 'out-0'}" title="Bit ${31 - i}: ${bitVal}">
          ${bitVal}
        </span>
      `;
    }).join('');
  }

  calculate() {
    const fn = this.selectedFunction;
    const x = this.valX;
    const y = this.valY;
    const z = this.valZ;
    const s = this.shiftAmount;

    switch (fn) {
      case 'Ch':
        return {
          name: 'Choice Function Ch(X, Y, Z)',
          formula: 'Ch(X, Y, Z) = (X ∧ Y) ⊕ (¬X ∧ Z)',
          description: 'Bit-multiplexer: For each bit position i, if X[i] is 1 it chooses Y[i]; if X[i] is 0 it chooses Z[i].',
          insight: 'In SHA-1, SHA-256, and SHA-512, Choice creates severe non-linear dependence between the working registers.',
          value: ch_256(x, y, z),
          needsY: true,
          needsZ: true,
          needsShift: false
        };
      case 'Maj':
        return {
          name: 'Majority Function Maj(X, Y, Z)',
          formula: 'Maj(X, Y, Z) = (X ∧ Y) ⊕ (X ∧ Z) ⊕ (Y ∧ Z)',
          description: 'Bit-majority voter: Output is 1 if at least two of X, Y, Z have bit 1 at position i.',
          insight: 'Majority ensures balanced non-linear diffusion so that register outputs do not bias toward 0 or 1.',
          value: maj_256(x, y, z),
          needsY: true,
          needsZ: true,
          needsShift: false
        };
      case 'Sigma0':
        return {
          name: 'Upper Sigma 0 Σ₀(X)',
          formula: 'Σ₀(X) = (X ⋙ 2) ⊕ (X ⋙ 13) ⊕ (X ⋙ 22)',
          description: 'SHA-256 Compression transform on working register A.',
          insight: 'Three distinct circular rotations XORed together rapidly diffuse high-order bit changes across the word.',
          value: bigSigma0_256(x),
          needsY: false,
          needsZ: false,
          needsShift: false
        };
      case 'Sigma1':
        return {
          name: 'Upper Sigma 1 Σ₁(X)',
          formula: 'Σ₁(X) = (X ⋙ 6) ⊕ (X ⋙ 11) ⊕ (X ⋙ 25)',
          description: 'SHA-256 Compression transform on working register E.',
          insight: 'Diffuses mutations in register E across three prime rotation offsets before addition into T1.',
          value: bigSigma1_256(x),
          needsY: false,
          needsZ: false,
          needsShift: false
        };
      case 'sigma0':
        return {
          name: 'Lower Sigma 0 σ₀(X)',
          formula: 'σ₀(X) = (X ⋙ 7) ⊕ (X ⋙ 18) ⊕ (X ≫ 3)',
          description: 'SHA-256 Message Schedule transform on word W[t-15].',
          insight: 'Combines two circular rotations with a logical right shift (SHR) to introduce zero bits at the MSB.',
          value: sigma0_256(x),
          needsY: false,
          needsZ: false,
          needsShift: false
        };
      case 'sigma1':
        return {
          name: 'Lower Sigma 1 σ₁(X)',
          formula: 'σ₁(X) = (X ⋙ 17) ⊕ (X ⋙ 19) ⊕ (X ≫ 10)',
          description: 'SHA-256 Message Schedule transform on word W[t-2].',
          insight: 'Guarantees that each message word W[t] mixes with previously generated words.',
          value: sigma1_256(x),
          needsY: false,
          needsZ: false,
          needsShift: false
        };
      case 'ROTR':
        return {
          name: `Circular Right Rotate ROTR(X, ${s})`,
          formula: `ROTR(X, ${s}) = (X ≫ ${s}) | (X ≪ ${32 - s})`,
          description: `Rotates bits to the right by ${s} positions. Bits shifted off the right wrap around to the left.`,
          insight: 'Unlike logical shifts, rotations preserve Hamming weight (total number of 1s in the word).',
          value: rotr32(x, s),
          needsY: false,
          needsZ: false,
          needsShift: true
        };
      case 'ROTL':
        return {
          name: `Circular Left Rotate ROTL(X, ${s})`,
          formula: `ROTL(X, ${s}) = (X ≪ ${s}) | (X ≫ ${32 - s})`,
          description: `Rotates bits to the left by ${s} positions. Used extensively in MD5 and SHA-1.`,
          insight: 'Left rotations wrap MSB bits into LSB positions.',
          value: rotl32(x, s),
          needsY: false,
          needsZ: false,
          needsShift: true
        };
      case 'ADD32':
        return {
          name: 'Modular Addition (X + Y + Z) mod 2³²',
          formula: '(X + Y + Z) mod 2³²',
          description: 'Arithmetic addition in the ring ℤ/2³²ℤ. Overflow beyond bit 31 is discarded.',
          insight: 'Modular addition is non-linear over GF(2) and destroys simple XOR linear algebra attacks.',
          value: add32(x, y, z),
          needsY: true,
          needsZ: true,
          needsShift: false
        };
      default:
        return { name: 'Ch', value: 0, needsY: true, needsZ: true };
    }
  }

  bindEvents() {
    // Function tab buttons
    this.container.querySelectorAll('.prim-tab').forEach(tab => {
      tab.onclick = () => {
        this.selectedFunction = tab.dataset.fn;
        this.render();
      };
    });

    // Bit toggle clickers
    this.container.querySelectorAll('.bit-toggle-btn').forEach(btn => {
      btn.onclick = () => {
        const reg = btn.dataset.reg;
        const bitIdx = parseInt(btn.dataset.bit, 10);
        const mask = (1 << bitIdx) >>> 0;
        if (reg === 'X') this.valX = (this.valX ^ mask) >>> 0;
        else if (reg === 'Y') this.valY = (this.valY ^ mask) >>> 0;
        else if (reg === 'Z') this.valZ = (this.valZ ^ mask) >>> 0;
        this.render();
      };
    });

    // Hex text inputs
    this.container.querySelectorAll('.hex-text-input').forEach(input => {
      input.onchange = (e) => {
        const reg = input.dataset.reg;
        const parsed = parseInt(e.target.value, 16) || 0;
        if (reg === 'X') this.valX = parsed >>> 0;
        else if (reg === 'Y') this.valY = parsed >>> 0;
        else if (reg === 'Z') this.valZ = parsed >>> 0;
        this.render();
      };
    });

    // Shift slider
    const shiftSlider = this.container.querySelector('#shift-range');
    if (shiftSlider) {
      shiftSlider.oninput = (e) => {
        this.shiftAmount = parseInt(e.target.value, 10);
        this.render();
      };
    }

    // Presets
    const btnAlt = this.container.querySelector('#btn-preset-alternating');
    const btnAll = this.container.querySelector('#btn-preset-allones');
    const btnRnd = this.container.querySelector('#btn-preset-random');

    if (btnAlt) {
      btnAlt.onclick = () => {
        this.valX = 0xAAAAAAAA >>> 0;
        this.valY = 0x55555555 >>> 0;
        this.valZ = 0x33333333 >>> 0;
        this.render();
      };
    }

    if (btnAll) {
      btnAll.onclick = () => {
        this.valX = 0xFFFFFFFF >>> 0;
        this.valY = 0x00000000 >>> 0;
        this.valZ = 0x80000001 >>> 0;
        this.render();
      };
    }

    if (btnRnd) {
      btnRnd.onclick = () => {
        this.valX = (Math.random() * 0x100000000) >>> 0;
        this.valY = (Math.random() * 0x100000000) >>> 0;
        this.valZ = (Math.random() * 0x100000000) >>> 0;
        this.render();
      };
    }
  }
}
