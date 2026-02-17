# Security Analysis: Fuel Wallet (dldjpboieedgcmpkchcjcbijingjcgok)

## Extension Metadata
- **Name**: Fuel Wallet
- **Extension ID**: dldjpboieedgcmpkchcjcbijingjcgok
- **Version**: 0.62.3
- **Manifest Version**: 3
- **Estimated Users**: ~100,000
- **Developer**: Fuel Labs (fuel.network)
- **Analysis Date**: 2026-02-14

## Executive Summary
Fuel Wallet is the official cryptocurrency wallet for the Fuel blockchain network with **MEDIUM** risk status. While the extension is legitimate and performs as advertised, several concerning issues were identified: (1) Mock Service Worker (MSW) testing library included in production build, (2) postMessage handlers without origin validation in development/test code, (3) CSP allows 'wasm-unsafe-eval', and (4) clipboard permission with seed phrase copy functionality. The extension does not exhibit malicious behavior, but the presence of development/testing artifacts in a production crypto wallet represents poor security hygiene.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Mock Service Worker in Production Build (CRITICAL FINDING)
**Severity**: HIGH
**Files**:
- `/mockServiceWorker.js` (lines 1-6)
- `/assets/e2e-CmQkTLT_.js` (e2e testing code)

**Analysis**:
The extension ships with Mock Service Worker (MSW) v0.49.1, a development/testing library designed to intercept network requests for testing purposes. The file explicitly warns "Please do NOT serve this file on production."

**Code Evidence** (`mockServiceWorker.js`):
```javascript
/**
 * Mock Service Worker (0.49.1).
 * @see https://github.com/mswjs/msw
 * - Please do NOT modify this file.
 * - Please do NOT serve this file on production.
 */
```

**Why This is Concerning**:
1. **Attack Surface**: MSW can intercept ALL fetch requests if activated, providing a code path for potential exploitation
2. **Testing Code in Production**: File `e2e-CmQkTLT_.js` (1.3MB) contains end-to-end testing libraries that should never ship to users
3. **Service Worker Interference**: Could potentially interfere with legitimate service worker operations
4. **Code Bloat**: 1.3MB+ of unnecessary testing code increases attack surface

**Current State**:
- MSW appears inactive (no activation calls found in production code paths)
- Likely an oversight during build process (Vite/webpack didn't tree-shake test files)
- No evidence of malicious use

**Verdict**: **HIGH RISK** - Development artifacts in production crypto wallet. While not actively exploited, this represents serious supply chain security concerns.

**Recommendation**: Extension should be rebuilt with proper production build configuration to exclude test files.

---

### 2. postMessage Handlers Without Origin Validation
**Severity**: HIGH
**Files**:
- `/mockServiceWorker.js` (line 19)
- `/assets/e2e-CmQkTLT_.js` (line 8110)

**Analysis**:
Multiple postMessage event listeners exist without proper origin validation in test code.

**Code Evidence** (`mockServiceWorker.js`, line 19):
```javascript
self.addEventListener('message', async (event) => {
  const clientId = event.source.id;
  if (!clientId || !self.clients) {
    return;
  }
  // No origin check on incoming messages
  switch (event.data) {
    case 'MOCK_ACTIVATE':
    case 'INTEGRITY_CHECK_REQUEST':
    // ...
  }
});
```

**Mitigation**:
The production content script (`contentScript.ts-CYvjgIl6.js`) DOES properly validate origins:
```javascript
shouldAcceptMessage(e, t) {
  return t === window.location.origin &&
         e.target === i &&
         e.connectorName === this.connectorName
}

postMessage(e) {
  window.postMessage(t, window.location.origin) // Proper origin restriction
}
```

**Verdict**: **MEDIUM RISK** - Vulnerable handlers exist in test code (MSW) but production code properly validates origins. Risk is mitigated by MSW being inactive, but the vulnerable code shouldn't be present at all.

---

### 3. Content Security Policy: 'wasm-unsafe-eval'
**Severity**: MEDIUM
**Files**: `/manifest.json` (line 51)

**Analysis**:
CSP allows 'wasm-unsafe-eval' to enable WebAssembly execution.

**Code Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

**Justification**:
The extension uses WebAssembly for secp256k1 cryptographic operations (elliptic curve cryptography for blockchain signatures).

**WASM Usage** (`secp256k1-DdArpRbT.js`, lines 6156-6165):
```javascript
async function rg(r, t) {
  if (typeof WebAssembly.instantiateStreaming == "function") {
    return await WebAssembly.instantiateStreaming(r, t)
  }
  // Fallback to WebAssembly.instantiate
  const e = await r.arrayBuffer();
  return await WebAssembly.instantiate(e, t)
}
```

**Risk Assessment**:
- **Legitimate Use**: WASM needed for high-performance crypto operations (standard for crypto wallets)
- **No 'unsafe-eval'**: Regular JavaScript eval() is still blocked (only WASM allowed)
- **Pre-compiled**: WASM module is bundled, not loaded from external sources

**Verdict**: **LOW RISK** - CSP is appropriately scoped for legitimate cryptographic needs. 'wasm-unsafe-eval' does not enable arbitrary code execution like 'unsafe-eval' would.

---

### 4. Clipboard Permission and Seed Phrase Handling
**Severity**: MEDIUM
**Files**:
- `/manifest.json` (permission declared)
- `/assets/main-CjYtXK6q.js` (lines 72623, 38804, 74645)

**Analysis**:
The extension requests `clipboardWrite` permission and uses it to copy sensitive data.

**Code Evidence** (`main-CjYtXK6q.js`, line 72623):
```javascript
async function h() {
  const E = t === "read" ? e : l;
  await navigator.clipboard.writeText(E.join(" "));
  Os.success("Seed phrase copied to clipboard")
}
```

**Also Used For**:
- Copying wallet addresses (line 74645)
- Copying arbitrary text in UI components (line 38804)

**Security Considerations**:
1. **User-Initiated**: All clipboard operations require explicit user interaction (button clicks)
2. **No Clipboard Reading**: Extension only writes, doesn't read clipboard
3. **Expected Behavior**: Crypto wallets commonly provide "copy seed phrase" functionality
4. **Clipboard Hijacking Risk**: Clipboard remains accessible to other extensions/malware

**Data Flow**:
- Seed phrases stored encrypted in `chrome.storage.session` (password-protected)
- Export requires password re-entry
- Copied to clipboard only on explicit user action
- **No network transmission** of seed phrases detected

**Verdict**: **MEDIUM RISK** - Clipboard usage is legitimate and user-controlled, but copying seed phrases to clipboard exposes them to clipboard hijacking attacks by other malicious software. This is inherent risk in all crypto wallets, not specific vulnerability.

---

### 5. Private Key Export Functionality
**Severity**: MEDIUM (Expected Behavior)
**Files**: `/assets/config-D02o9Sm2.js` (lines 7454-7459)

**Analysis**:
The extension provides private key export functionality (standard wallet feature).

**Code Evidence**:
```javascript
async exportPrivateKey({
  address: t,
  password: s
}) {
  await this.manager.unlock(s);
  return this.manager.exportPrivateKey(rn.fromString(t))
}
```

**Security Measures**:
- Requires password authentication before export
- Keys encrypted at rest in `chrome.storage.session`
- User must explicitly request export
- No automatic or background key extraction

**Verdict**: **NOT MALICIOUS** - Standard cryptocurrency wallet functionality with appropriate authentication.

---

### 6. Storage of Encrypted Vault Data
**Severity**: LOW
**Files**: `/assets/index.ts-Cn5TcUtA.js` (lines 102-152)

**Analysis**:
Wallet data stored encrypted in browser storage using password-derived encryption.

**Code Evidence**:
```javascript
async function Ct(s, t) {
  const e = await At(); // Generate random salt
  try {
    const n = await pt(e, s); // Encrypt with password
    chrome.storage.session.set({
      data: n,
      lockTime: t,
      timer: $().add(t, "minute").valueOf()
    })
  } catch {
    R() // Clear on error
  }
}
```

**Security Features**:
- Random salt generation via `crypto.randomUUID()`
- Session-based storage (cleared on browser restart)
- Auto-lock timer based on user preference
- Password required to decrypt

**Verdict**: **CLEAN** - Proper encryption practices for sensitive data storage.

---

## False Positive Analysis (ext-analyzer Findings)

### EXFILTRATION Flows (4 reported - ALL FALSE POSITIVES)

#### 1. `document.querySelectorAll → fetch(ipfs.io)`
**Finding**: Data from DOM selection flows to IPFS fetch
**Reality**: FALSE POSITIVE
**Explanation**:
- Line 54001 shows `p.replace("ipfs://", "https://ipfs.io/ipfs/")` - simple string replacement
- Used to display NFT images from IPFS protocol URIs
- No DOM data is sent to ipfs.io; instead, IPFS URIs from NFT metadata are converted to HTTP URLs for image loading
- This is standard NFT wallet functionality (loading NFT artwork)

#### 2. `chrome.tabs.query → *.src`
**Finding**: Tab information flows to element src attribute
**Reality**: FALSE POSITIVE
**Explanation**:
- `chrome.tabs.query` used to inject content scripts (line 208-216, `index.ts-Cn5TcUtA.js`)
- No tab data exfiltrated; only used to determine which tabs need script injection
- `.src` assignment is unrelated to tabs (React component image sources)

#### 3. `chrome.tabs.query → fetch(ipfs.io)`
**Finding**: Tab data flows to IPFS fetch
**Reality**: FALSE POSITIVE
**Explanation**:
- Same as findings 1 & 2 - separate code paths incorrectly linked by static analysis
- tabs.query used for content script injection
- IPFS fetches used for NFT image loading
- No connection between these operations

#### 4. `document.getElementById → fetch(ipfs.io)`
**Finding**: DOM element data flows to IPFS
**Reality**: FALSE POSITIVE
**Explanation**:
- getElementById used by React's internal DOM reconciliation
- IPFS fetches for NFT metadata (verified-assets.fuel.network provides asset list)
- No actual DOM data sent to external servers

**Root Cause**: Static analyzer cannot distinguish between:
- NFT metadata (IPFS URIs stored in blockchain/asset registry)
- DOM manipulation by React framework
- Legitimate asset fetching from Fuel's verified asset list

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `verified-assets.fuel.network` | Asset metadata registry | None (GET requests) | On wallet load |
| `*.fuel.network` | Fuel blockchain RPC nodes | Transaction data, account queries | Per transaction |
| `ipfs.io` | NFT image gateway | None (image requests only) | When viewing NFTs |
| `walletconnect.com` | WalletConnect protocol | Connection metadata | When using WalletConnect |
| `api.web3modal.org` | Web3Modal UI library | UI resources | Modal interactions |
| `avatar.vercel.sh` | Avatar generation service | Wallet addresses (for avatar images) | Optional UI feature |

### Data Flow Summary

**Data Collection**: NONE (beyond standard blockchain queries)
**Seed Phrase Transmission**: NONE
**Private Key Transmission**: NONE
**Tracking/Analytics**: NONE detected
**Third-Party SDKs**: WalletConnect (industry standard), Web3Modal (UI library)

All sensitive cryptographic operations occur locally. Network calls limited to:
1. Blockchain RPC (required for wallet functionality)
2. Asset metadata (NFT/token information)
3. Connection protocols (WalletConnect for dApp integration)

**No browsing data, browsing history, or personal information transmitted beyond wallet addresses and transaction data required for blockchain operations.**

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `storage` | Encrypted vault and settings storage | Low (local only) |
| `alarms` | Auto-lock timer, update checks | Low (functional) |
| `tabs` | Content script injection for dApp integration | Medium (broad access) |
| `clipboardWrite` | Copy addresses and seed phrases | Medium (see vuln #4) |
| `scripting` | Inject connector scripts into web pages | Medium (required for dApp interaction) |
| `host_permissions: <all_urls>` | dApp integration on any website | **HIGH** (very broad) |

**Assessment**:
- `<all_urls>` is concerning but standard for crypto wallets that need to interact with dApps on any domain
- All permissions justified for declared wallet functionality
- No evidence of permission abuse

---

## Code Quality Observations

### Positive Indicators
1. **Strong Cryptography**: secp256k1 implementation (industry standard)
2. **Encrypted Storage**: Password-protected vault encryption
3. **Origin Validation**: Production postMessage handlers validate origins
4. **No eval()**: No dynamic code execution in production paths
5. **Session-Based Security**: Auto-lock, session storage clearing
6. **Proper Key Management**: No hardcoded keys or secrets

### Negative Indicators
1. **Test Code in Production**: 1.3MB+ of MSW and e2e test code shipped to users
2. **Large Bundle Size**: 3.5MB+ JavaScript (minified but not tree-shaken)
3. **Build Process Issues**: Development dependencies not excluded from production
4. **Code Obfuscation**: Heavy minification makes auditing difficult (though not intentionally malicious)

### Obfuscation Level
**HIGH** - Modern build tools (Vite/Rollup) with heavy minification. Variable names like `rg`, `pt`, `$` make manual review difficult, but this is standard for React applications, not intentional obfuscation.

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No chrome.management usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | Content scripts only for wallet connector |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote code loading | ✗ No | All code bundled |
| Cookie harvesting | ✗ No | No cookie access |
| Hidden data exfiltration | ✗ No | All network calls transparent |
| Seed phrase exfiltration | ✗ No | No external transmission detected |

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:
1. **No Malicious Intent Detected** - Extension functions as legitimate Fuel blockchain wallet
2. **Major Security Hygiene Issue** - MSW and test code in production is unacceptable for crypto wallet
3. **Standard Crypto Wallet Risks** - Clipboard usage, broad permissions inherent to wallet functionality
4. **Good Cryptographic Practices** - Proper encryption, key management, origin validation

**Primary Concerns**:
- Development/test artifacts in production build (MSW, e2e tests)
- Very broad host permissions (<all_urls>)
- Clipboard exposure of seed phrases (user-initiated but risky)

**Why MEDIUM not HIGH**:
- No active exploitation or malicious behavior
- MSW appears inactive in production
- Proper security controls in production code paths
- Reputable developer (Fuel Labs)

### Recommendations

**For Users**:
1. **Use with Caution**: Wallet functional but build quality concerns
2. **Backup Seed Phrases Offline**: Don't rely solely on clipboard
3. **Monitor for Updates**: Watch for version that removes test code
4. **Verify Transactions**: Always review transaction details before signing

**For Developers (Fuel Labs)**:
1. **CRITICAL**: Rebuild with production configuration to exclude:
   - mockServiceWorker.js
   - e2e-CmQkTLT_.js (1.3MB test code)
   - All development dependencies
2. **Improve Build Process**: Add tree-shaking, proper dev/prod splits
3. **Security Audit**: Third-party audit recommended for crypto wallet
4. **Reduce Bundle Size**: 3.5MB is excessive; code splitting recommended

### User Privacy Impact
**MEDIUM** - The extension accesses:
- All web pages (for dApp connector injection)
- Blockchain data (public by nature)
- Clipboard (for copy operations only)
- No analytics, tracking, or personal data collection detected

**Clipboard Risk**: Seed phrases copied to clipboard vulnerable to:
- Other extensions with clipboardRead permission
- Malware with clipboard monitoring
- Clipboard history features in OS

---

## Technical Summary

**Lines of Code**: ~3.5MB minified JavaScript
**External Dependencies**: React, Fuel SDK, WalletConnect, Web3Modal, secp256k1 WASM
**Third-Party Libraries**: Standard blockchain/crypto libraries
**Remote Code Loading**: None
**Dynamic Code Execution**: WASM only (for cryptography)

**Critical Files**:
- `mockServiceWorker.js` - **Should not be in production**
- `e2e-CmQkTLT_.js` - **Test code, should be excluded**
- `config-D02o9Sm2.js` - Vault manager, key operations
- `contentScript.ts-CYvjgIl6.js` - dApp connector (properly secured)

---

## Conclusion

Fuel Wallet is a **legitimate cryptocurrency wallet** for the Fuel blockchain that performs as advertised without malicious behavior. However, the presence of Mock Service Worker and 1.3MB+ of end-to-end testing code in production represents serious security hygiene issues for a cryptocurrency wallet handling private keys and seed phrases.

The extension itself does not exhibit malicious characteristics - all network calls are transparent, cryptographic operations are properly implemented, and no data exfiltration occurs. The ext-analyzer "EXFILTRATION" findings are all false positives resulting from NFT image loading and React framework internals.

**Primary Risk**: Poor build configuration allowing development artifacts into production. While not actively malicious, this indicates insufficient security practices in the build/release process for software handling financial assets.

**Final Verdict: MEDIUM** - Functional and non-malicious, but production build quality issues preclude CLEAN/LOW rating for financial software.

---

## Tags
- `behavior:dev_artifacts_in_prod` - Mock Service Worker and test code in production
- `vuln:postmessage_no_origin` - Test code contains handlers without origin checks
- `privacy:clipboard_sensitive_data` - Clipboard write of seed phrases (user-initiated)
- `behavior:crypto_wallet` - Legitimate cryptocurrency wallet functionality
