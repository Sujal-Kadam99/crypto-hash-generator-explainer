/**
 * CyberHash - Main Application Controller
 */
import { md5 } from './crypto/md5.js';
import { sha1 } from './crypto/sha1.js';
import { sha256 } from './crypto/sha256.js';
import { sha512 } from './crypto/sha512.js';
import { stringToUtf8Bytes, bytesToHexString } from './crypto/utils.js';

class App {
  constructor() {
    this.activeAlgorithm = 'SHA-256';
    this.inputText = '';
    this.cryptoResult = null;

    this.initElements();
    this.bindEvents();
    this.runCalculation();
  }

  initElements() {
    this.inputArea = document.getElementById('main-text-input');
    this.digestHexDisplay = document.getElementById('digest-hex-value');
    this.digestLenBadge = document.getElementById('digest-len-badge');
    this.blockCountBadge = document.getElementById('block-count-badge');
    this.timeBadge = document.getElementById('calc-time-badge');
    this.btnCopyHash = document.getElementById('btn-copy-hash');
  }

  bindEvents() {
    // Algorithm selector buttons
    document.querySelectorAll('.algo-selector-btn').forEach(btn => {
      btn.onclick = () => {
        document.querySelectorAll('.algo-selector-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.activeAlgorithm = btn.dataset.algo;
        this.runCalculation();
      };
    });

    // Text input with debounce
    let debounceTimer;
    this.inputArea.oninput = (e) => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        this.inputText = e.target.value;
        this.runCalculation();
      }, 150);
    };

    // File input
    const fileInput = document.getElementById('file-upload-input');
    if (fileInput) {
      fileInput.onchange = (e) => {
        const file = e.target.files[0];
        if (file) {
          const reader = new FileReader();
          reader.onload = (event) => {
            const buffer = new Uint8Array(event.target.result);
            this.runCalculationWithBytes(buffer, `File: ${file.name} (${file.size} bytes)`);
          };
          reader.readAsArrayBuffer(file);
        }
      };
    }

    // Preset buttons
    document.querySelectorAll('.preset-btn').forEach(btn => {
      btn.onclick = () => {
        const preset = btn.dataset.preset;
        if (preset === 'empty') this.inputText = '';
        else if (preset === 'abc') this.inputText = 'abc';
        else if (preset === 'fox') this.inputText = 'The quick brown fox jumps over the lazy dog';
        else if (preset === 'bitcoin') this.inputText = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c';
        
        this.inputArea.value = this.inputText;
        this.runCalculation();
      };
    });

    // Copy hash button
    this.btnCopyHash.onclick = () => {
      if (this.cryptoResult?.digestHex) {
        navigator.clipboard.writeText(this.cryptoResult.digestHex).then(() => {
          const originalText = this.btnCopyHash.innerHTML;
          this.btnCopyHash.innerHTML = '✓ Copied!';
          this.btnCopyHash.classList.add('btn-emerald');
          setTimeout(() => {
            this.btnCopyHash.innerHTML = originalText;
            this.btnCopyHash.classList.remove('btn-emerald');
          }, 1500);
        });
      }
    };
  }

  runCalculation() {
    const bytes = stringToUtf8Bytes(this.inputText);
    this.runCalculationWithBytes(bytes);
  }

  runCalculationWithBytes(bytes, labelOverride) {
    if (bytes.length === 0) {
      this.cryptoResult = null;
      this.digestHexDisplay.textContent = '';
      this.digestLenBadge.textContent = '';
      this.blockCountBadge.textContent = '';
      this.timeBadge.textContent = '';
      return;
    }

    const startTime = performance.now();
    let result;

    switch (this.activeAlgorithm) {
      case 'MD5':
        result = md5(bytes);
        break;
      case 'SHA-1':
        result = sha1(bytes);
        break;
      case 'SHA-256':
        result = sha256(bytes);
        break;
      case 'SHA-512':
        result = sha512(bytes);
        break;
      default:
        result = sha256(bytes);
    }

    const elapsed = (performance.now() - startTime).toFixed(2);
    this.cryptoResult = result;

    // Update Header Displays
    this.digestHexDisplay.textContent = result.digestHex;
    const bitLen = result.digestBytes.length * 8;
    this.digestLenBadge.textContent = `${bitLen}-bit (${result.digestBytes.length} Bytes)`;
    this.blockCountBadge.textContent = `${result.blockCount} Block${result.blockCount > 1 ? 's' : ''} (${result.paddedLength} Bytes)`;
    this.timeBadge.textContent = `${elapsed} ms`;
  }
}

// Boot application when DOM is loaded
window.addEventListener('DOMContentLoaded', () => {
  window.cryptoApp = new App();
});
