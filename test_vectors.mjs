import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';

// Load the browser script in a mock environment
const code = fs.readFileSync('./js/hash_tool.js', 'utf8');
const sandbox = {
  document: { 
    readyState: 'complete', 
    addEventListener: () => {},
    getElementById: () => ({ textContent: '', classList: { add: ()=>{}, remove: ()=>{} }, style: {}, addEventListener: () => {} }),
    querySelectorAll: () => [],
    createElement: () => ({ classList: { add: ()=>{} }, style: {}, appendChild: ()=>{} })
  },
  window: {},
  performance: { now: () => 0 },
  setTimeout,
  clearTimeout,
  console
};
sandbox.window.document = sandbox.document;

vm.createContext(sandbox);
vm.runInContext(code, sandbox);

// Because we added module.exports to hash_tool.js for testing, we could also just mock `module`
// Let's run it again with `module` mocked so it exports
const moduleMock = { exports: {} };
sandbox.module = moduleMock;
vm.runInContext(code, sandbox);

const { md5, sha1, sha256, sha512 } = moduleMock.exports;

const testStrings = [
  '', // empty input
  'a',
  'abc',
  'message digest',
  'The quick brown fox jumps over the lazy dog',
  'The quick brown fox jumps over the lazy dog.',
  '12345678901234567890123456789012345678901234567890123456789012345678901234567890',
  'a'.repeat(55), // 55-byte boundary (1 byte before MD5/SHA1/SHA256 pad boundary)
  'a'.repeat(56), // 56-byte boundary (exact MD5/SHA1/SHA256 pad boundary)
  'a'.repeat(64), // 64-byte block boundary
  'a'.repeat(119), // 119-byte (1 byte before SHA512 pad boundary)
  'a'.repeat(120), // 120-byte (exact SHA-512 pad boundary)
  'a'.repeat(128), // 128-byte block boundary (SHA512)
  'Hello 🌍, Γειά σου Κόσμε, こんにちは世界', // multi-byte UTF-8
  'large_'.repeat(20000) // Large input (~120KB)
];

console.log('--- TESTING CRYPTO IMPLEMENTATIONS AGAINST NODE CRYPTO ---');
let allPassed = true;
const enc = new TextEncoder();

for (const str of testStrings) {
  const bytes = Array.from(enc.encode(str));
  
  // MD5
  const myMd5 = md5(bytes).digestHex;
  const nodeMd5 = crypto.createHash('md5').update(str).digest('hex');
  if (myMd5 !== nodeMd5) {
    console.error(`MD5 Mismatch for length ${str.length}`);
    allPassed = false;
  }

  // SHA-1
  const mySha1 = sha1(bytes).digestHex;
  const nodeSha1 = crypto.createHash('sha1').update(str).digest('hex');
  if (mySha1 !== nodeSha1) {
    console.error(`SHA-1 Mismatch for length ${str.length}`);
    allPassed = false;
  }

  // SHA-256
  const mySha256 = sha256(bytes).digestHex;
  const nodeSha256 = crypto.createHash('sha256').update(str).digest('hex');
  if (mySha256 !== nodeSha256) {
    console.error(`SHA-256 Mismatch for length ${str.length}`);
    allPassed = false;
  }

  // SHA-512
  const mySha512 = sha512(bytes).digestHex;
  const nodeSha512 = crypto.createHash('sha512').update(str).digest('hex');
  if (mySha512 !== nodeSha512) {
    console.error(`SHA-512 Mismatch for length ${str.length}`);
    allPassed = false;
  }
}

if (allPassed) {
  console.log('✅ ALL TEST VECTORS PASSED PERFECTLY FOR MD5, SHA-1, SHA-256, SHA-512!');
} else {
  console.error('❌ SOME TEST VECTORS FAILED');
  process.exit(1);
}
