/**
 * Security, Comparison & Cryptographic Usages Component
 * Comprehensive comparison matrix, collision vulnerability history, length extension attacks, and protocols
 */
export function renderSecurityView(container) {
  if (!container) return;

  container.innerHTML = `
    <div class="security-view-container">
      <div class="section-header">
        <div>
          <h2>🛡️ Cryptographic Security, Attacks & Real-World Usages</h2>
          <p class="section-desc">Analyze collision resistances, known cryptographic exploits, Merkle-Damgård construction properties, and industry standards.</p>
        </div>
      </div>

      <!-- 1. Algorithm Comparison Matrix -->
      <div class="comparison-panel glass-panel">
        <div class="panel-header">
          <h3>📊 Algorithm Comparison & Cryptanalysis Matrix</h3>
          <span class="badge badge-purple">NIST FIPS 180-4 & RFC 1321</span>
        </div>

        <div class="comparison-table-wrapper">
          <table class="comparison-table">
            <thead>
              <tr>
                <th>Feature / Property</th>
                <th class="col-md5">MD5</th>
                <th class="col-sha1">SHA-1</th>
                <th class="col-sha256">SHA-256</th>
                <th class="col-sha512">SHA-512</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Digest Size</strong></td>
                <td class="font-mono">128 bits (16 B)</td>
                <td class="font-mono">160 bits (20 B)</td>
                <td class="font-mono">256 bits (32 B)</td>
                <td class="font-mono">512 bits (64 B)</td>
              </tr>
              <tr>
                <td><strong>Block Size</strong></td>
                <td class="font-mono">512 bits (64 B)</td>
                <td class="font-mono">512 bits (64 B)</td>
                <td class="font-mono">512 bits (64 B)</td>
                <td class="font-mono">1024 bits (128 B)</td>
              </tr>
              <tr>
                <td><strong>Word Size</strong></td>
                <td class="font-mono">32 bits</td>
                <td class="font-mono">32 bits</td>
                <td class="font-mono">32 bits</td>
                <td class="font-mono">64 bits</td>
              </tr>
              <tr>
                <td><strong>Number of Rounds</strong></td>
                <td class="font-mono">64 (4 × 16)</td>
                <td class="font-mono">80 (4 × 20)</td>
                <td class="font-mono">64</td>
                <td class="font-mono">80</td>
              </tr>
              <tr>
                <td><strong>Endianness</strong></td>
                <td class="font-mono text-amber">Little-Endian</td>
                <td class="font-mono text-cyan">Big-Endian</td>
                <td class="font-mono text-cyan">Big-Endian</td>
                <td class="font-mono text-cyan">Big-Endian</td>
              </tr>
              <tr>
                <td><strong>Collision Resistance</strong></td>
                <td><span class="badge badge-rose font-bold">BROKEN (2¹⁸ ops)</span></td>
                <td><span class="badge badge-rose font-bold">BROKEN (2⁶³ ops)</span></td>
                <td><span class="badge badge-emerald font-bold">SECURE (2¹²⁸ ops)</span></td>
                <td><span class="badge badge-emerald font-bold">SECURE (2²⁵⁶ ops)</span></td>
              </tr>
              <tr>
                <td><strong>Preimage Resistance</strong></td>
                <td><span class="badge badge-amber font-bold">WEAKENED (2¹²³ ops)</span></td>
                <td><span class="badge badge-slate font-bold">THEORETICAL (2¹⁵⁹ ops)</span></td>
                <td><span class="badge badge-emerald font-bold">SECURE (2²⁵⁶ ops)</span></td>
                <td><span class="badge badge-emerald font-bold">SECURE (2⁵¹² ops)</span></td>
              </tr>
              <tr>
                <td><strong>Length Extension Attack</strong></td>
                <td><span class="text-rose font-bold">Vulnerable</span></td>
                <td><span class="text-rose font-bold">Vulnerable</span></td>
                <td><span class="text-rose font-bold">Vulnerable</span></td>
                <td><span class="text-rose font-bold">Vulnerable</span></td>
              </tr>
              <tr>
                <td><strong>NIST Regulatory Status</strong></td>
                <td><span class="badge badge-rose">DISALLOWED</span></td>
                <td><span class="badge badge-rose">DEPRECATED</span></td>
                <td><span class="badge badge-emerald">APPROVED</span></td>
                <td><span class="badge badge-emerald">APPROVED</span></td>
              </tr>
              <tr>
                <td><strong>Primary Real-World Usage</strong></td>
                <td>Legacy Checksums, non-crypto ID</td>
                <td>Legacy Git commits, PGP keys</td>
                <td>Bitcoin PoW, TLS 1.3, DNSSEC</td>
                <td>Linux Passwords ($6$), TLS certs</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- 2. Cryptanalytic Attacks Deep Dive -->
      <div class="attacks-grid">
        <div class="attack-card glass-panel border-rose">
          <div class="attack-header">
            <span class="badge badge-rose">CRITICAL EXPLOIT</span>
            <h3>💥 MD5 Collision Attacks & Flame Malware</h3>
          </div>
          <p class="attack-desc">
            In 2004, Prof. Xiaoyun Wang demonstrated chosen-prefix collisions for MD5 in just minutes. In 2008, researchers generated a rogue SSL Certification Authority. In 2012, the state-sponsored <strong>Flame cyberweapon</strong> forged Microsoft Windows Update digital signatures by generating colliding MD5 hashes.
          </p>
          <div class="takeaway-box">
            <strong>Key Lesson:</strong> MD5 must NEVER be used for digital certificates, password storage, or authentication tokens.
          </div>
        </div>

        <div class="attack-card glass-panel border-amber">
          <div class="attack-header">
            <span class="badge badge-amber">BROKEN PRIMITIVE</span>
            <h3>📄 The SHAttered SHA-1 Collision (Google 2017)</h3>
          </div>
          <p class="attack-desc">
            In February 2017, Google and CWI Amsterdam published <strong>SHAttered</strong>: the first practical collision against SHA-1. They produced two completely different PDF documents with identical SHA-1 hashes using $9 \times 10^{18}$ SHA-1 computations (110 GPU years), rendering SHA-1 unfit for signatures.
          </p>
          <div class="takeaway-box">
            <strong>Key Lesson:</strong> Major browsers rejected SHA-1 SSL certificates, and Git introduced SHA-256 object hashes.
          </div>
        </div>

        <div class="attack-card glass-panel border-cyan">
          <div class="attack-header">
            <span class="badge badge-cyan">CONSTRUCTION PROPERTY</span>
            <h3>⛓️ Length Extension Attack on Merkle-Damgård</h3>
          </div>
          <p class="attack-desc">
            Because MD5, SHA-1, SHA-256, and SHA-512 output the raw internal state accumulator ($H_0..H_n$), an adversary who knows $\text{Hash}(K \parallel M)$ and the length of $K \parallel M$ can append data $M'$ and calculate $\text{Hash}(K \parallel M \parallel \text{Pad} \parallel M')$ <strong>without knowing the secret key $K$</strong>!
          </p>
          <div class="takeaway-box">
            <strong>Defense:</strong> Use <strong>HMAC</strong> ($\text{Hash}((K \oplus \text{opad}) \parallel \text{Hash}((K \oplus \text{ipad}) \parallel M))$), SHA-512/256 (which truncates state), or SHA-3 (Keccak sponge).
          </div>
        </div>
      </div>

      <!-- 3. Real-World Applications & Protocol Deep Dive -->
      <div class="protocols-panel glass-panel">
        <div class="panel-header">
          <h3>🌐 Cryptographic Hash Functions in Modern Infrastructure</h3>
          <span class="badge badge-blue">Production Architecture</span>
        </div>

        <div class="protocols-grid">
          <div class="protocol-card">
            <div class="protocol-icon">₿</div>
            <h4>Bitcoin Mining & Proof-of-Work</h4>
            <p>Bitcoin uses <strong>Double SHA-256</strong> ($\text{SHA-256}(\text{SHA-256}(\text{BlockHeader})) < \text{Target}$) for proof-of-work mining and SHA-256 + RIPEMD-160 to generate Bitcoin wallet addresses.</p>
          </div>

          <div class="protocol-card">
            <div class="protocol-icon">🌿</div>
            <h4>Git Distributed Version Control</h4>
            <p>Every commit, blob, tree, and tag in Git is identified by a 40-character hexadecimal cryptographic hash calculated as $\text{SHA-1}(\text{"commit "} \parallel \text{size} \parallel \text{content})$ (now migrating to SHA-256).</p>
          </div>

          <div class="protocol-card">
            <div class="protocol-icon">🔒</div>
            <h4>TLS / HTTPS & Digital Signatures</h4>
            <p>TLS 1.3 utilizes SHA-256 and SHA-384 in HMAC-based Key Derivation (HKDF), Cipher Suites, and ECDSA/RSA digital certificate validation to secure global internet traffic.</p>
          </div>

          <div class="protocol-card">
            <div class="protocol-icon">🔑</div>
            <h4>Password Storage: Why NOT Raw Hashes</h4>
            <p>Raw SHA-256 or SHA-512 hashes are vulnerable to GPU brute-forcing (billions of hashes/sec). Modern systems use salted & memory-hard Key Derivation Functions like <strong>Argon2id</strong>, <strong>bcrypt</strong>, or <strong>PBKDF2</strong>.</p>
          </div>
        </div>
      </div>

    </div>
  `;
}
