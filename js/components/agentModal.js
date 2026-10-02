/**
 * Agentic Cryptography Explainer & AI Assistant
 * Autonomous step explanations, guided learning tours, vulnerability audits, and interactive quizzes
 */
import { u32ToHex, u64ToHex } from '../crypto/utils.js';

export class AgentModal {
  constructor(container) {
    this.container = container;
    this.activeMode = 'auditor'; // 'auditor', 'tours', 'audit', 'quiz'
    this.currentTourIdx = 0;
    this.quizState = {
      questionIdx: 0,
      score: 0,
      selectedAnswer: null,
      submitted: false
    };
  }

  render(cryptoResult, activeStepIdx) {
    if (!this.container) return;

    this.cryptoResult = cryptoResult;
    this.activeStepIdx = activeStepIdx || 0;

    let contentHtml = '';
    switch (this.activeMode) {
      case 'auditor':
        contentHtml = this.renderStepAuditor();
        break;
      case 'tours':
        contentHtml = this.renderGuidedTours();
        break;
      case 'audit':
        contentHtml = this.renderVulnerabilityAudit();
        break;
      case 'quiz':
        contentHtml = this.renderQuiz();
        break;
    }

    this.container.innerHTML = `
      <div class="agent-wrapper glass-panel">
        <div class="agent-header">
          <div class="agent-brand">
            <div class="agent-avatar">🤖</div>
            <div>
              <h3>CryptoAgent Autonomous Assistant</h3>
              <p class="agent-status"><span class="status-dot"></span> Active Cryptographic Analyzer</p>
            </div>
          </div>

          <!-- Agent Navigation Tabs -->
          <div class="agent-tabs">
            <button class="agent-tab-btn ${this.activeMode === 'auditor' ? 'active' : ''}" data-mode="auditor">🔍 Step Auditor</button>
            <button class="agent-tab-btn ${this.activeMode === 'tours' ? 'active' : ''}" data-mode="tours">🎓 Guided Tours</button>
            <button class="agent-tab-btn ${this.activeMode === 'audit' ? 'active' : ''}" data-mode="audit">🛡️ Security Audit</button>
            <button class="agent-tab-btn ${this.activeMode === 'quiz' ? 'active' : ''}" data-mode="quiz">❓ Interactive Quiz</button>
          </div>
        </div>

        <div class="agent-body">
          ${contentHtml}
        </div>
      </div>
    `;

    this.bindEvents();
  }

  renderStepAuditor() {
    if (!this.cryptoResult) {
      return '<div class="empty-state">Load an algorithm above to inspect step explanations.</div>';
    }

    const { algorithm } = this.cryptoResult;
    const stepData = this.cryptoResult.traces[0]?.steps[this.activeStepIdx];
    if (!stepData) {
      return '<div class="empty-state">No step data available.</div>';
    }

    const is64Bit = algorithm === 'SHA-512';
    const totalSteps = this.cryptoResult.traces[0].steps.length;

    let analysisText = '';
    if (algorithm === 'MD5') {
      analysisText = `
        In <strong>Round ${stepData.step + 1} (${stepData.fnName})</strong>, register <code>B</code> undergoes non-linear mutation by mixing 
        current registers <code>(B, C, D)</code> through function <code>${stepData.fnName.charAt(0)}</code>, adding message word <code>M[${stepData.gIndex}]</code> 
        and precomputed sinusoidal constant <code>T[${stepData.step}] = 0x${u32ToHex(stepData.kVal).toUpperCase()}</code>. 
        The accumulated sum is rotated left by <strong>${stepData.shift} bits</strong> and added back to <code>B</code>. 
        Finally, registers rotate right: <code>(A, B, C, D) ← (D, new B, B, C)</code>.
      `;
    } else if (algorithm === 'SHA-1') {
      analysisText = `
        In <strong>Round ${stepData.step + 1} (Stage ${stepData.stage}: ${stepData.fnName})</strong>, working register <code>A</code> is updated 
        via temporary sum <code>TEMP = (A ⋘ 5) + f_t(B,C,D) + E + W[${stepData.step}] + K[${stepData.stage - 1}]</code>. 
        Register <code>B</code> is circularly shifted left by 30 bits before transferring into <code>C</code>, which prevents easy linear bit cancellation attacks.
      `;
    } else {
      // SHA-256 or SHA-512
      const hexK = is64Bit ? u64ToHex(stepData.kVal) : u32ToHex(stepData.kVal);
      const hexW = is64Bit ? u64ToHex(stepData.wVal) : u32ToHex(stepData.wVal);
      analysisText = `
        In <strong>Round ${stepData.step + 1} of ${totalSteps}</strong>, compression functions <code>Σ₁</code> and <code>Ch</code> compute 
        intermediate value <code>T₁</code> using schedule word <code>W[${stepData.step}] = 0x${hexW.toUpperCase()}</code> and cube-root constant <code>K[${stepData.step}] = 0x${hexK.toUpperCase()}</code>. 
        Concurrently, <code>Σ₀</code> and <code>Maj</code> compute <code>T₂</code> from registers <code>(A, B, C)</code>. 
        Register <code>E</code> absorbs <code>D + T₁</code>, while <code>A</code> absorbs <code>T₁ + T₂</code>, causing all 8 registers to shift down.
      `;
    }

    return `
      <div class="auditor-view">
        <div class="agent-bubble glass-panel">
          <div class="bubble-header">
            <span class="badge badge-cyan font-mono">${algorithm} • Round ${this.activeStepIdx + 1} of ${totalSteps}</span>
            <span class="badge badge-purple font-mono">Live Register Inspector</span>
          </div>
          <div class="bubble-content">
            <p class="explanation-p">${analysisText}</p>
          </div>
        </div>

        <div class="agent-insights-grid">
          <div class="insight-box glass-panel">
            <h4>💡 Cryptographic Purpose</h4>
            <p class="text-sm text-slate-300">
              ${algorithm === 'MD5' ? 'MD5 uses 4 distinct non-linear functions across 16-step rounds to disrupt linear cryptanalysis.' :
                algorithm === 'SHA-1' ? 'SHA-1 employs four 20-round stages with distinct constants derived from √2, √3, √5, and √10.' :
                'SHA-2 (256/512) splits dataflow into dual parallel paths (T1 on high registers, T2 on low registers) to maximize avalanche diffusion.'}
            </p>
          </div>
          <div class="insight-box glass-panel">
            <h4>⚡ Non-Linearity Metric</h4>
            <p class="text-sm text-slate-300">
              Modular addition $(\boxplus)$ combined with bitwise rotations provides algebraic non-linearity over both $\\mathbb{F}_2$ and $\\mathbb{Z}/2^{${is64Bit ? '64' : '32'}}\\mathbb{Z}$.
            </p>
          </div>
        </div>
      </div>
    `;
  }

  renderGuidedTours() {
    const tours = [
      {
        title: "1. The Complete Journey: From Plaintext to Digest",
        steps: [
          "1. <strong>Input Encoding:</strong> Converts human-readable text into raw UTF-8 binary bytes.",
          "2. <strong>Bit Padding:</strong> Appends a single '1' bit (0x80), followed by '0' bits, and the 64/128-bit original length.",
          "3. <strong>Block Partitioning:</strong> Divides data into 512-bit (SHA-256) or 1024-bit (SHA-512) chunks.",
          "4. <strong>Word Expansion:</strong> Derives 64 or 80 round words ($W_t$) from the initial 16 words.",
          "5. <strong>Iterative Compression:</strong> Passes words through round functions to thoroughly scramble internal registers.",
          "6. <strong>Feed-Forward Accumulation:</strong> Adds round output back to the hash state (Merkle-Damgård construction)."
        ]
      },
      {
        title: "2. The Merkle-Damgård Construction & Length Extension",
        steps: [
          "1. <strong>Iterative Structure:</strong> Takes a compression function $f(H_{i-1}, M_i) \\to H_i$.",
          "2. <strong>State Output Exposure:</strong> The final hash output is simply the internal state after the last block.",
          "3. <strong>Vulnerability:</strong> An attacker knowing $\\text{Hash}(K \\parallel M)$ can continue hashing new blocks $M'$ without knowing secret key $K$.",
          "4. <strong>Modern Countermeasure:</strong> Use <strong>HMAC</strong> or sponge constructions (like SHA-3 / Keccak)."
        ]
      },
      {
        title: "3. The Avalanche Effect & Cryptographic Security",
        steps: [
          "1. <strong>Definition:</strong> Strict Avalanche Criterion requires that flipping 1 input bit changes ~50% of output bits.",
          "2. <strong>Diffusion Mechanism:</strong> Bitwise circular rotations spread single-bit changes across word positions.",
          "3. <strong>Confusion Mechanism:</strong> Modular additions create carry-chain propagation that destroys bit independence."
        ]
      }
    ];

    const currentTour = tours[this.currentTourIdx];

    return `
      <div class="tours-view">
        <div class="tours-nav">
          ${tours.map((t, idx) => `
            <button class="tour-btn ${idx === this.currentTourIdx ? 'active' : ''}" data-tour="${idx}">
              ${t.title.split(':')[0]}
            </button>
          `).join('')}
        </div>

        <div class="tour-content-card glass-panel">
          <h3 class="text-cyan">${currentTour.title}</h3>
          <div class="tour-steps-list">
            ${currentTour.steps.map(s => `
              <div class="tour-step-item">
                <span class="tour-check">✓</span>
                <div class="tour-step-text">${s}</div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }

  renderVulnerabilityAudit() {
    if (!this.cryptoResult) {
      return '<div class="empty-state">Load input data above to run security audit.</div>';
    }

    const { algorithm, originalLength } = this.cryptoResult;

    let score = 'A+';
    let statusBadge = 'badge-emerald';
    let verdict = 'Cryptographically Secure for Production Use';
    let recommendations = [];

    if (algorithm === 'MD5') {
      score = 'F';
      statusBadge = 'badge-rose';
      verdict = 'COMPROMISED: Severe Practical Collision Attacks Known';
      recommendations = [
        'Do NOT use for digital signatures, certificates, or token generation.',
        'Migrate immediately to SHA-256 or SHA-512.',
        'Acceptable only for non-adversarial legacy file integrity checks.'
      ];
    } else if (algorithm === 'SHA-1') {
      score = 'D';
      statusBadge = 'badge-amber';
      verdict = 'DEPRECATED: Chosen-Prefix Collisions Feasible (SHAttered)';
      recommendations = [
        'Disallowed by NIST for digital certificates and signatures since 2011.',
        'Transition Git repositories to SHA-256 object format.',
        'Upgrade all TLS cipher suites to SHA-256 or SHA-384.'
      ];
    } else {
      score = 'A+';
      statusBadge = 'badge-emerald';
      verdict = 'NIST Approved: Collision & Preimage Resistant';
      recommendations = [
        'Recommended standard for TLS 1.3, Bitcoin PoW, and digital signatures.',
        'When hashing secrets or authenticating messages, wrap with HMAC (RFC 2104) to prevent Length Extension Attacks.',
        'For password storage, do not use raw SHA-256; use Argon2id or bcrypt.'
      ];
    }

    return `
      <div class="audit-view">
        <div class="audit-summary-card glass-panel">
          <div class="audit-score-circle">
            <span class="score-letter ${score === 'A+' ? 'text-emerald' : score === 'D' ? 'text-amber' : 'text-rose'}">${score}</span>
            <span class="score-label">Security Grade</span>
          </div>
          <div class="audit-details">
            <div class="audit-header-line">
              <h4>${algorithm} Cryptographic Health Evaluation</h4>
              <span class="badge ${statusBadge}">${score === 'A+' ? 'SECURE' : 'VULNERABLE'}</span>
            </div>
            <p class="audit-verdict font-bold">${verdict}</p>
            <p class="text-sm text-slate-300">Input size: ${originalLength} bytes | Digest size: ${algorithm === 'MD5' ? '128' : algorithm === 'SHA-1' ? '160' : algorithm === 'SHA-256' ? '256' : '512'} bits</p>
          </div>
        </div>

        <div class="audit-recommendations glass-panel">
          <h4>📋 Security Best Practices & Mitigation Roadmap</h4>
          <ul class="rec-list">
            ${recommendations.map(r => `<li><span class="rec-bullet">➔</span> ${r}</li>`).join('')}
          </ul>
        </div>
      </div>
    `;
  }

  renderQuiz() {
    const questions = [
      {
        q: "What is the primary difference between word endianness in MD5 vs SHA-256?",
        options: [
          "MD5 uses Big-Endian; SHA-256 uses Little-Endian",
          "MD5 uses Little-Endian; SHA-256 uses Big-Endian",
          "Both use Big-Endian",
          "Both use Little-Endian"
        ],
        correct: 1,
        explanation: "MD5 unpacks bytes in Little-Endian order (LSB first), whereas SHA-1, SHA-256, and SHA-512 use Big-Endian order (MSB first)."
      },
      {
        q: "Why is raw SHA-256(secret || message) insecure for message authentication?",
        options: [
          "It produces collisions in 2^18 operations",
          "It is vulnerable to Length Extension Attacks due to Merkle-Damgård state output",
          "It only uses 32-bit words",
          "It does not support UTF-8 inputs"
        ],
        correct: 1,
        explanation: "Because SHA-256 outputs its entire internal state as the digest, an attacker can append data and compute a valid hash without knowing the secret key. HMAC solves this."
      },
      {
        q: "What are the round constants in SHA-256 derived from?",
        options: [
          "Sine function values floor(2^32 * |sin(i+1)|)",
          "First 32 bits of the fractional parts of cube roots of the first 64 prime numbers",
          "Fibonacci numbers modulo 2^32",
          "Random numbers generated by NIST"
        ],
        correct: 1,
        explanation: "SHA-256 round constants $K_0..K_{63}$ are the fractional parts of the cube roots of the first 64 primes (2, 3, 5, 7, ...), ensuring 'nothing-up-my-sleeve' transparency."
      },
      {
        q: "How many bits are processed per block in SHA-512?",
        options: [
          "256 bits",
          "512 bits",
          "1024 bits (128 bytes)",
          "2048 bits"
        ],
        correct: 2,
        explanation: "SHA-512 operates on 1024-bit blocks sliced into sixteen 64-bit words ($W_0..W_{15}$), running 80 rounds of compression."
      }
    ];

    const curQ = questions[this.quizState.questionIdx];
    const isLast = this.quizState.questionIdx === questions.length - 1;

    return `
      <div class="quiz-view">
        <div class="quiz-header">
          <span class="badge badge-purple">Question ${this.quizState.questionIdx + 1} of ${questions.length}</span>
          <span class="badge badge-emerald">Score: ${this.quizState.score}</span>
        </div>

        <div class="quiz-card glass-panel">
          <h4 class="quiz-question-title">${curQ.q}</h4>

          <div class="quiz-options-list">
            ${curQ.options.map((opt, oIdx) => {
              let optClass = '';
              if (this.quizState.submitted) {
                if (oIdx === curQ.correct) optClass = 'opt-correct';
                else if (oIdx === this.quizState.selectedAnswer) optClass = 'opt-wrong';
              } else if (this.quizState.selectedAnswer === oIdx) {
                optClass = 'opt-selected';
              }

              return `
                <button class="quiz-option-btn ${optClass}" data-opt="${oIdx}" ${this.quizState.submitted ? 'disabled' : ''}>
                  <span class="opt-indicator">${String.fromCharCode(65 + oIdx)}</span>
                  <span class="opt-text">${opt}</span>
                </button>
              `;
            }).join('')}
          </div>

          ${this.quizState.submitted ? `
            <div class="quiz-explanation-box ${this.quizState.selectedAnswer === curQ.correct ? 'bg-emerald' : 'bg-rose'}">
              <strong>${this.quizState.selectedAnswer === curQ.correct ? '🎉 Correct!' : '❌ Incorrect'}</strong>
              <p>${curQ.explanation}</p>
            </div>
          ` : ''}

          <div class="quiz-actions">
            ${!this.quizState.submitted ? `
              <button id="btn-submit-quiz" class="btn btn-cyan" ${this.quizState.selectedAnswer === null ? 'disabled' : ''}>Submit Answer</button>
            ` : `
              <button id="btn-next-quiz" class="btn btn-emerald">${isLast ? 'Restart Quiz' : 'Next Question ➔'}</button>
            `}
          </div>
        </div>
      </div>
    `;
  }

  bindEvents() {
    // Mode tabs
    this.container.querySelectorAll('.agent-tab-btn').forEach(btn => {
      btn.onclick = () => {
        this.activeMode = btn.dataset.mode;
        this.render(this.cryptoResult, this.activeStepIdx);
      };
    });

    // Tours navigation
    this.container.querySelectorAll('.tour-btn').forEach(btn => {
      btn.onclick = () => {
        this.currentTourIdx = parseInt(btn.dataset.tour, 10);
        this.render(this.cryptoResult, this.activeStepIdx);
      };
    });

    // Quiz options selection
    this.container.querySelectorAll('.quiz-option-btn').forEach(btn => {
      btn.onclick = () => {
        if (this.quizState.submitted) return;
        this.quizState.selectedAnswer = parseInt(btn.dataset.opt, 10);
        this.render(this.cryptoResult, this.activeStepIdx);
      };
    });

    // Quiz submit
    const submitBtn = this.container.querySelector('#btn-submit-quiz');
    if (submitBtn) {
      submitBtn.onclick = () => {
        this.quizState.submitted = true;
        const questions = [
          { correct: 1 }, { correct: 1 }, { correct: 1 }, { correct: 2 }
        ];
        if (this.quizState.selectedAnswer === questions[this.quizState.questionIdx].correct) {
          this.quizState.score += 100;
        }
        this.render(this.cryptoResult, this.activeStepIdx);
      };
    }

    // Quiz next
    const nextBtn = this.container.querySelector('#btn-next-quiz');
    if (nextBtn) {
      nextBtn.onclick = () => {
        if (this.quizState.questionIdx < 3) {
          this.quizState.questionIdx++;
          this.quizState.selectedAnswer = null;
          this.quizState.submitted = false;
        } else {
          // Restart
          this.quizState.questionIdx = 0;
          this.quizState.score = 0;
          this.quizState.selectedAnswer = null;
          this.quizState.submitted = false;
        }
        this.render(this.cryptoResult, this.activeStepIdx);
      };
    }
  }
}
