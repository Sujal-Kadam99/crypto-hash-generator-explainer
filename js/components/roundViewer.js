/**
 * Interactive Round Stepper & Register Visualizer Component
 * Playback controls, SVG register circuit diagram, 32/64-bit live binary matrices, bit diffs
 */
import { u32ToHex, u32ToBinary, u64ToHex, u64ToBinary, formatBinarySpaced, hammingDistance32, hammingDistance64 } from '../crypto/utils.js';

export class RoundViewer {
  constructor(container, onStepChange) {
    this.container = container;
    this.onStepChange = onStepChange;
    this.cryptoResult = null;
    this.currentBlockIdx = 0;
    this.currentStepIdx = 0;
    this.isPlaying = false;
    this.playInterval = null;
    this.playSpeed = 1000; // ms per step
  }

  setResult(cryptoResult) {
    this.cryptoResult = cryptoResult;
    this.currentBlockIdx = 0;
    this.currentStepIdx = 0;
    this.pause();
    this.render();
  }

  setStep(stepIdx) {
    if (!this.cryptoResult) return;
    const maxSteps = this.getMaxSteps();
    this.currentStepIdx = Math.max(0, Math.min(maxSteps - 1, stepIdx));
    this.renderState();
    if (this.onStepChange) this.onStepChange(this.currentStepIdx, this.getCurrentStepData());
  }

  setBlock(blockIdx) {
    if (!this.cryptoResult) return;
    this.currentBlockIdx = Math.max(0, Math.min(this.cryptoResult.blockCount - 1, blockIdx));
    this.currentStepIdx = 0;
    this.render();
  }

  getMaxSteps() {
    if (!this.cryptoResult || !this.cryptoResult.traces[this.currentBlockIdx]) return 0;
    return this.cryptoResult.traces[this.currentBlockIdx].steps.length;
  }

  getCurrentStepData() {
    if (!this.cryptoResult) return null;
    const trace = this.cryptoResult.traces[this.currentBlockIdx];
    if (!trace || !trace.steps[this.currentStepIdx]) return null;
    return trace.steps[this.currentStepIdx];
  }

  play() {
    if (this.isPlaying) return;
    this.isPlaying = true;
    this.updatePlayButton();
    this.playInterval = setInterval(() => {
      const maxSteps = this.getMaxSteps();
      if (this.currentStepIdx >= maxSteps - 1) {
        if (this.currentBlockIdx < this.cryptoResult.blockCount - 1) {
          this.setBlock(this.currentBlockIdx + 1);
        } else {
          this.pause();
          return;
        }
      } else {
        this.setStep(this.currentStepIdx + 1);
      }
    }, this.playSpeed);
  }

  pause() {
    this.isPlaying = false;
    if (this.playInterval) {
      clearInterval(this.playInterval);
      this.playInterval = null;
    }
    this.updatePlayButton();
  }

  togglePlay() {
    if (this.isPlaying) this.pause();
    else this.play();
  }

  setSpeed(speedMs) {
    this.playSpeed = speedMs;
    if (this.isPlaying) {
      this.pause();
      this.play();
    }
  }

  updatePlayButton() {
    const playBtn = this.container.querySelector('#btn-play-pause');
    if (playBtn) {
      playBtn.innerHTML = this.isPlaying
        ? '<span class="icon">⏸</span> Pause'
        : '<span class="icon">▶</span> Play';
      playBtn.classList.toggle('btn-amber', this.isPlaying);
      playBtn.classList.toggle('btn-cyan', !this.isPlaying);
    }
  }

  render() {
    if (!this.cryptoResult) {
      this.container.innerHTML = '<div class="empty-state">No cryptographic data loaded. Enter text above to start.</div>';
      return;
    }

    const { algorithm } = this.cryptoResult;
    const maxSteps = this.getMaxSteps();
    const is64Bit = algorithm === 'SHA-512';

    this.container.innerHTML = `
      <div class="round-viewer-container">
        <!-- Controls Bar -->
        <div class="stepper-controls-bar glass-panel">
          <div class="controls-left">
            <button id="btn-reset" class="btn btn-slate" title="Reset to Start"><span class="icon">⏮</span></button>
            <button id="btn-prev" class="btn btn-slate" title="Previous Round (Step Back)"><span class="icon">◀</span></button>
            <button id="btn-play-pause" class="btn btn-cyan font-bold"><span class="icon">▶</span> Play</button>
            <button id="btn-next" class="btn btn-slate" title="Next Round (Step Forward)"><span class="icon">▶</span></button>
            <button id="btn-end" class="btn btn-slate" title="Jump to Final Round"><span class="icon">⏭</span></button>
          </div>

          <div class="controls-center">
            <div class="step-slider-container">
              <span class="step-label font-mono">Round: <strong id="step-number-badge" class="text-cyan">${this.currentStepIdx + 1}</strong> / ${maxSteps}</span>
              <input type="range" id="step-range-slider" min="0" max="${maxSteps - 1}" value="${this.currentStepIdx}" class="custom-slider" />
            </div>
          </div>

          <div class="controls-right">
            ${this.cryptoResult.blockCount > 1 ? `
              <div class="block-select-wrapper">
                <label>Block:</label>
                <select id="block-selector" class="custom-select">
                  ${this.cryptoResult.blocks.map((b, idx) => `
                    <option value="${idx}" ${idx === this.currentBlockIdx ? 'selected' : ''}>Block #${idx + 1}</option>
                  `).join('')}
                </select>
              </div>
            ` : ''}

            <div class="speed-control">
              <label>Speed:</label>
              <select id="speed-selector" class="custom-select">
                <option value="2000">0.5x (Slow)</option>
                <option value="1000" selected>1.0x (Normal)</option>
                <option value="400">2.5x (Fast)</option>
                <option value="150">6.0x (Turbo)</option>
              </select>
            </div>
          </div>
        </div>

        <!-- Dynamic Round Content -->
        <div id="round-state-content" class="round-state-wrapper">
          <!-- Populated by renderState() -->
        </div>
      </div>
    `;

    this.bindEvents();
    this.renderState();
  }

  bindEvents() {
    const playBtn = this.container.querySelector('#btn-play-pause');
    const prevBtn = this.container.querySelector('#btn-prev');
    const nextBtn = this.container.querySelector('#btn-next');
    const resetBtn = this.container.querySelector('#btn-reset');
    const endBtn = this.container.querySelector('#btn-end');
    const slider = this.container.querySelector('#step-range-slider');
    const speedSelect = this.container.querySelector('#speed-selector');
    const blockSelect = this.container.querySelector('#block-selector');

    if (playBtn) playBtn.onclick = () => this.togglePlay();
    if (prevBtn) prevBtn.onclick = () => this.setStep(this.currentStepIdx - 1);
    if (nextBtn) nextBtn.onclick = () => this.setStep(this.currentStepIdx + 1);
    if (resetBtn) resetBtn.onclick = () => this.setStep(0);
    if (endBtn) endBtn.onclick = () => this.setStep(this.getMaxSteps() - 1);
    if (slider) slider.oninput = (e) => this.setStep(parseInt(e.target.value, 10));
    if (speedSelect) speedSelect.onchange = (e) => this.setSpeed(parseInt(e.target.value, 10));
    if (blockSelect) blockSelect.onchange = (e) => this.setBlock(parseInt(e.target.value, 10));
  }

  renderState() {
    const stateContainer = this.container.querySelector('#round-state-content');
    const stepBadge = this.container.querySelector('#step-number-badge');
    const slider = this.container.querySelector('#step-range-slider');

    if (stepBadge) stepBadge.textContent = `${this.currentStepIdx + 1}`;
    if (slider) slider.value = this.currentStepIdx;

    const stepData = this.getCurrentStepData();
    if (!stepData || !stateContainer) return;

    const { algorithm } = this.cryptoResult;
    const is64Bit = algorithm === 'SHA-512';
    const regNames = Object.keys(stepData.stateBefore);

    // Compute bit differences between stateBefore and stateAfter
    const registersRendered = regNames.map(name => {
      const valBefore = stepData.stateBefore[name];
      const valAfter = stepData.stateAfter[name];

      const hexBefore = is64Bit ? u64ToHex(valBefore) : u32ToHex(valBefore);
      const hexAfter = is64Bit ? u64ToHex(valAfter) : u32ToHex(valAfter);

      const binBefore = is64Bit ? u64ToBinary(valBefore) : u32ToBinary(valBefore);
      const binAfter = is64Bit ? u64ToBinary(valAfter) : u32ToBinary(valAfter);

      const hamming = is64Bit ? hammingDistance64(valBefore, valAfter) : hammingDistance32(valBefore, valAfter);
      const isChanged = hexBefore !== hexAfter;

      // Build bit cells with change indicators
      const bitCells = [];
      const bitCount = is64Bit ? 64 : 32;
      for (let bit = 0; bit < bitCount; bit++) {
        const bBefore = binBefore[bit];
        const bAfter = binAfter[bit];
        const bitFlipped = bBefore !== bAfter;
        bitCells.push(`
          <span class="bit-cell ${bitFlipped ? 'bit-flipped' : ''} ${bAfter === '1' ? 'bit-one' : 'bit-zero'}" title="Bit ${bitCount - 1 - bit}: ${bBefore} -> ${bAfter}">
            ${bAfter}
          </span>
        `);
      }

      return `
        <div class="register-row ${isChanged ? 'reg-modified' : 'reg-unchanged'}">
          <div class="reg-meta">
            <span class="reg-name font-mono">${name}</span>
            <div class="reg-hex-values">
              <span class="hex-prev font-mono" title="Before round">0x${hexBefore.toUpperCase()}</span>
              <span class="hex-arrow">➔</span>
              <span class="hex-current font-mono font-bold text-cyan" title="After round">0x${hexAfter.toUpperCase()}</span>
            </div>
            <span class="hamming-badge badge ${hamming > 0 ? 'badge-amber' : 'badge-slate'}">
              Δ ${hamming} bits flipped
            </span>
          </div>

          <div class="reg-bit-grid font-mono">
            ${bitCells.join('')}
          </div>
        </div>
      `;
    }).join('');

    // Generate dynamic operation details card
    let opDetailsHtml = '';
    if (algorithm === 'MD5') {
      opDetailsHtml = `
        <div class="op-summary-grid">
          <div class="op-item"><span class="op-label">Function:</span> <strong class="text-purple">${stepData.fnName}</strong></div>
          <div class="op-item"><span class="op-label">Constant K[${stepData.step}]:</span> <strong class="font-mono text-amber">0x${u32ToHex(stepData.kVal).toUpperCase()}</strong></div>
          <div class="op-item"><span class="op-label">Message Word M[${stepData.gIndex}]:</span> <strong class="font-mono text-cyan">0x${u32ToHex(stepData.mVal).toUpperCase()}</strong></div>
          <div class="op-item"><span class="op-label">Circular Shift:</span> <strong class="text-emerald">&lt;&lt;&lt; ${stepData.shift}</strong></div>
          <div class="op-item full-width"><span class="op-label">Step Equation:</span> <code class="code-pill">${stepData.formula}</code></div>
        </div>
      `;
    } else if (algorithm === 'SHA-1') {
      opDetailsHtml = `
        <div class="op-summary-grid">
          <div class="op-item"><span class="op-label">Stage Function:</span> <strong class="text-purple">${stepData.fnName}</strong></div>
          <div class="op-item"><span class="op-label">Stage Constant K[${stepData.stage - 1}]:</span> <strong class="font-mono text-amber">0x${u32ToHex(stepData.kVal).toUpperCase()}</strong></div>
          <div class="op-item"><span class="op-label">Schedule Word W[${stepData.step}]:</span> <strong class="font-mono text-cyan">0x${u32ToHex(stepData.wVal).toUpperCase()}</strong></div>
          <div class="op-item"><span class="op-label">Rotations:</span> <strong class="text-emerald">A &lt;&lt;&lt; 5, B &lt;&lt;&lt; 30</strong></div>
          <div class="op-item full-width"><span class="op-label">Step Equation:</span> <code class="code-pill">${stepData.formula}</code></div>
        </div>
      `;
    } else {
      // SHA-256 or SHA-512
      const hexK = is64Bit ? u64ToHex(stepData.kVal) : u32ToHex(stepData.kVal);
      const hexW = is64Bit ? u64ToHex(stepData.wVal) : u32ToHex(stepData.wVal);
      const hexT1 = is64Bit ? u64ToHex(stepData.t1) : u32ToHex(stepData.t1);
      const hexT2 = is64Bit ? u64ToHex(stepData.t2) : u32ToHex(stepData.t2);

      opDetailsHtml = `
        <div class="op-summary-grid">
          <div class="op-item"><span class="op-label">Round Constant K[${stepData.step}]:</span> <strong class="font-mono text-amber">0x${hexK.toUpperCase()}</strong></div>
          <div class="op-item"><span class="op-label">Schedule Word W[${stepData.step}]:</span> <strong class="font-mono text-cyan">0x${hexW.toUpperCase()}</strong></div>
          <div class="op-item"><span class="op-label">Compression Temp T1:</span> <strong class="font-mono text-purple">0x${hexT1.toUpperCase()}</strong></div>
          <div class="op-item"><span class="op-label">Compression Temp T2:</span> <strong class="font-mono text-emerald">0x${hexT2.toUpperCase()}</strong></div>
          <div class="op-item full-width"><span class="op-label">T1 Formula:</span> <code class="code-pill">${stepData.formulaT1}</code></div>
          <div class="op-item full-width"><span class="op-label">T2 Formula:</span> <code class="code-pill">${stepData.formulaT2}</code></div>
        </div>
      `;
    }

    stateContainer.innerHTML = `
      <div class="round-detail-layout">
        <!-- Left: SVG Architecture / Compression Circuit -->
        <div class="circuit-panel glass-panel">
          <div class="panel-header">
            <h3>⚡ Round ${this.currentStepIdx + 1} Compression Dataflow</h3>
            <span class="badge badge-purple">${algorithm}</span>
          </div>
          
          <div class="svg-circuit-wrapper">
            ${this.renderCircuitSVG(algorithm, stepData, is64Bit)}
          </div>

          <div class="round-formula-card">
            <h4>Mathematical Round Breakdown:</h4>
            ${opDetailsHtml}
          </div>
        </div>

        <!-- Right: Register Bit Matrices -->
        <div class="registers-panel glass-panel">
          <div class="panel-header">
            <h3>🔬 Working Registers (${is64Bit ? '64-bit BigInt' : '32-bit'} Words)</h3>
            <span class="badge badge-cyan">${is64Bit ? '8 × 64-bit' : algorithm === 'MD5' ? '4 × 32-bit' : algorithm === 'SHA-1' ? '5 × 32-bit' : '8 × 32-bit'}</span>
          </div>

          <div class="bit-index-legend font-mono">
            <span class="legend-msb">MSB (Bit ${is64Bit ? '63' : '31'})</span>
            <span class="legend-bar">◀ ── Bitwise Representation ── ▶</span>
            <span class="legend-lsb">LSB (Bit 0)</span>
          </div>

          <div class="registers-list">
            ${registersRendered}
          </div>
        </div>
      </div>
    `;
  }

  renderCircuitSVG(algorithm, stepData, is64Bit) {
    if (algorithm === 'MD5') {
      return `
        <svg viewBox="0 0 500 240" class="circuit-svg">
          <defs>
            <marker id="arr" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#00d2ff" />
            </marker>
          </defs>
          <!-- Register Nodes -->
          <g transform="translate(30, 20)">
            <rect x="0" y="0" width="70" height="35" rx="6" fill="#1e293b" stroke="#38bdf8" stroke-width="2"/>
            <text x="35" y="22" text-anchor="middle" fill="#38bdf8" font-weight="bold" font-family="monospace">A</text>
          </g>
          <g transform="translate(140, 20)">
            <rect x="0" y="0" width="70" height="35" rx="6" fill="#1e293b" stroke="#a855f7" stroke-width="2"/>
            <text x="35" y="22" text-anchor="middle" fill="#a855f7" font-weight="bold" font-family="monospace">B</text>
          </g>
          <g transform="translate(250, 20)">
            <rect x="0" y="0" width="70" height="35" rx="6" fill="#1e293b" stroke="#a855f7" stroke-width="2"/>
            <text x="35" y="22" text-anchor="middle" fill="#a855f7" font-weight="bold" font-family="monospace">C</text>
          </g>
          <g transform="translate(360, 20)">
            <rect x="0" y="0" width="70" height="35" rx="6" fill="#1e293b" stroke="#a855f7" stroke-width="2"/>
            <text x="35" y="22" text-anchor="middle" fill="#a855f7" font-weight="bold" font-family="monospace">D</text>
          </g>

          <!-- Nonlinear Function Box -->
          <g transform="translate(200, 80)">
            <rect x="0" y="0" width="90" height="30" rx="4" fill="#334155" stroke="#f59e0b" stroke-width="1.5"/>
            <text x="45" y="20" text-anchor="middle" fill="#fbbf24" font-size="12" font-weight="bold">${stepData.fnName.split(' ')[0]}</text>
          </g>

          <!-- Shift & Adder Nodes -->
          <circle cx="65" cy="140" r="16" fill="#0f172a" stroke="#10b981" stroke-width="2"/>
          <text x="65" y="145" text-anchor="middle" fill="#10b981" font-weight="bold" font-size="16">⊞</text>

          <g transform="translate(100, 125)">
            <rect x="0" y="0" width="60" height="30" rx="4" fill="#334155" stroke="#ec4899" stroke-width="1.5"/>
            <text x="30" y="20" text-anchor="middle" fill="#f472b6" font-size="11" font-weight="bold">&lt;&lt;&lt; ${stepData.shift}</text>
          </g>

          <!-- Connecting Arrows -->
          <path d="M 65 55 L 65 120" stroke="#00d2ff" stroke-width="2" marker-end="url(#arr)"/>
          <path d="M 245 55 L 245 80" stroke="#a855f7" stroke-width="1.5"/>
          <path d="M 200 95 L 85 135" stroke="#f59e0b" stroke-width="1.5" marker-end="url(#arr)"/>
          <path d="M 81 140 L 100 140" stroke="#10b981" stroke-width="2" marker-end="url(#arr)"/>
          <path d="M 160 140 L 220 140 L 220 190 L 175 190" stroke="#ec4899" stroke-width="2" marker-end="url(#arr)"/>

          <!-- New Register Update Box -->
          <g transform="translate(100, 175)">
            <rect x="0" y="0" width="75" height="30" rx="4" fill="#065f46" stroke="#34d399" stroke-width="1.5"/>
            <text x="37" y="19" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="bold">New B</text>
          </g>
          <text x="250" y="225" text-anchor="middle" fill="#94a3b8" font-size="11">Registers Shift Right: A=D, D=C, C=B, B=New B</text>
        </svg>
      `;
    }

    if (algorithm === 'SHA-1') {
      return `
        <svg viewBox="0 0 520 220" class="circuit-svg">
          <defs>
            <marker id="arr2" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#38bdf8" />
            </marker>
          </defs>
          <!-- Registers A, B, C, D, E -->
          <g transform="translate(15, 20)">
            <rect x="0" y="0" width="55" height="30" rx="4" fill="#1e293b" stroke="#38bdf8" stroke-width="2"/>
            <text x="27" y="20" text-anchor="middle" fill="#38bdf8" font-weight="bold">A</text>
          </g>
          <g transform="translate(85, 20)">
            <rect x="0" y="0" width="55" height="30" rx="4" fill="#1e293b" stroke="#a855f7" stroke-width="2"/>
            <text x="27" y="20" text-anchor="middle" fill="#a855f7" font-weight="bold">B</text>
          </g>
          <g transform="translate(155, 20)">
            <rect x="0" y="0" width="55" height="30" rx="4" fill="#1e293b" stroke="#a855f7" stroke-width="2"/>
            <text x="27" y="20" text-anchor="middle" fill="#a855f7" font-weight="bold">C</text>
          </g>
          <g transform="translate(225, 20)">
            <rect x="0" y="0" width="55" height="30" rx="4" fill="#1e293b" stroke="#a855f7" stroke-width="2"/>
            <text x="27" y="20" text-anchor="middle" fill="#a855f7" font-weight="bold">D</text>
          </g>
          <g transform="translate(295, 20)">
            <rect x="0" y="0" width="55" height="30" rx="4" fill="#1e293b" stroke="#a855f7" stroke-width="2"/>
            <text x="27" y="20" text-anchor="middle" fill="#a855f7" font-weight="bold">E</text>
          </g>

          <!-- Rotary and Function Boxes -->
          <g transform="translate(15, 75)">
            <rect x="0" y="0" width="55" height="25" rx="4" fill="#334155" stroke="#38bdf8" stroke-width="1.5"/>
            <text x="27" y="17" text-anchor="middle" fill="#38bdf8" font-size="10" font-weight="bold">&lt;&lt;&lt; 5</text>
          </g>
          <g transform="translate(125, 75)">
            <rect x="0" y="0" width="85" height="25" rx="4" fill="#334155" stroke="#f59e0b" stroke-width="1.5"/>
            <text x="42" y="17" text-anchor="middle" fill="#fbbf24" font-size="10" font-weight="bold">${stepData.fnName}</text>
          </g>

          <!-- Central Adder -->
          <circle cx="200" cy="140" r="16" fill="#0f172a" stroke="#10b981" stroke-width="2"/>
          <text x="200" y="145" text-anchor="middle" fill="#10b981" font-weight="bold" font-size="16">⊞</text>

          <!-- Lines -->
          <path d="M 42 50 L 42 75" stroke="#38bdf8" stroke-width="1.5"/>
          <path d="M 42 100 L 42 140 L 180 140" stroke="#38bdf8" stroke-width="1.5" marker-end="url(#arr2)"/>
          <path d="M 167 100 L 190 128" stroke="#f59e0b" stroke-width="1.5"/>
          <path d="M 322 50 L 322 140 L 220 140" stroke="#a855f7" stroke-width="1.5" marker-end="url(#arr2)"/>
          <path d="M 200 156 L 200 185 L 42 185" stroke="#10b981" stroke-width="2" marker-end="url(#arr2)"/>

          <!-- Constants Feed -->
          <text x="390" y="90" fill="#f59e0b" font-family="monospace" font-size="11">Kt: 0x${u32ToHex(stepData.kVal).toUpperCase()}</text>
          <text x="390" y="115" fill="#38bdf8" font-family="monospace" font-size="11">Wt: 0x${u32ToHex(stepData.wVal).toUpperCase()}</text>
          <path d="M 380 100 L 220 135" stroke="#94a3b8" stroke-dasharray="3,3" stroke-width="1.5"/>
        </svg>
      `;
    }

    // SHA-256 & SHA-512 SVG Circuit Diagram
    return `
      <svg viewBox="0 0 540 240" class="circuit-svg">
        <defs>
          <marker id="arr3" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#38bdf8" />
          </marker>
        </defs>

        <!-- 8 Working Registers A to H -->
        ${['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'].map((r, i) => `
          <g transform="translate(${15 + i * 62}, 15)">
            <rect x="0" y="0" width="52" height="28" rx="4" fill="#1e293b" stroke="${i < 4 ? '#38bdf8' : '#a855f7'}" stroke-width="1.5"/>
            <text x="26" y="19" text-anchor="middle" fill="${i < 4 ? '#38bdf8' : '#a855f7'}" font-weight="bold" font-family="monospace">${r}</text>
          </g>
        `).join('')}

        <!-- Transformation Boxes for E, F, G, H (T1) -->
        <g transform="translate(265, 65)">
          <rect x="0" y="0" width="55" height="22" rx="3" fill="#334155" stroke="#a855f7" stroke-width="1"/>
          <text x="27" y="15" text-anchor="middle" fill="#c084fc" font-size="10">Σ1(E)</text>
        </g>
        <g transform="translate(325, 65)">
          <rect x="0" y="0" width="65" height="22" rx="3" fill="#334155" stroke="#f59e0b" stroke-width="1"/>
          <text x="32" y="15" text-anchor="middle" fill="#fbbf24" font-size="10">Ch(E,F,G)</text>
        </g>

        <!-- T1 Adder -->
        <circle cx="360" cy="120" r="14" fill="#0f172a" stroke="#a855f7" stroke-width="2"/>
        <text x="360" y="125" text-anchor="middle" fill="#a855f7" font-weight="bold" font-size="14">T₁</text>

        <!-- Transformation Boxes for A, B, C (T2) -->
        <g transform="translate(20, 65)">
          <rect x="0" y="0" width="55" height="22" rx="3" fill="#334155" stroke="#38bdf8" stroke-width="1"/>
          <text x="27" y="15" text-anchor="middle" fill="#38bdf8" font-size="10">Σ0(A)</text>
        </g>
        <g transform="translate(85, 65)">
          <rect x="0" y="0" width="65" height="22" rx="3" fill="#334155" stroke="#10b981" stroke-width="1"/>
          <text x="32" y="15" text-anchor="middle" fill="#34d399" font-size="10">Maj(A,B,C)</text>
        </g>

        <!-- T2 Adder -->
        <circle cx="85" cy="120" r="14" fill="#0f172a" stroke="#38bdf8" stroke-width="2"/>
        <text x="85" y="125" text-anchor="middle" fill="#38bdf8" font-weight="bold" font-size="14">T₂</text>

        <!-- New A & New E Flow -->
        <path d="M 360 135 L 360 180 L 225 180" stroke="#a855f7" stroke-width="2" marker-end="url(#arr3)"/>
        <text x="290" y="175" fill="#a855f7" font-size="10" font-weight="bold">E_next = D + T1</text>

        <path d="M 360 120 L 105 120" stroke="#10b981" stroke-width="1.5" stroke-dasharray="3,3"/>
        <path d="M 85 135 L 85 200 L 40 200 L 40 48" stroke="#38bdf8" stroke-width="2" marker-end="url(#arr3)"/>
        <text x="85" y="218" fill="#38bdf8" font-size="10" font-weight="bold">A_next = T1 + T2</text>
      </svg>
    `;
  }
}
