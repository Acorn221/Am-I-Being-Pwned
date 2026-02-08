# MathWallet Extension Security Analysis

## Metadata
- **Extension Name**: MathWallet
- **Extension ID**: afbcbjpbpfadlkmhmclhkeeodmamcflc
- **Version**: 4.0.6
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

MathWallet is a legitimate multi-chain cryptocurrency wallet extension that provides Web3 functionality across multiple blockchain networks (Bitcoin, Ethereum, Tron, Solana, Polkadot/Substrate). The extension handles sensitive cryptographic material including private keys and mnemonics.

**Overall Risk Assessment**: CLEAN

The extension serves its intended purpose as a cryptocurrency wallet without malicious behavior. While it has broad permissions and handles highly sensitive data (private keys, mnemonics), these are necessary for its legitimate wallet functionality. The code shows proper security practices including local encryption of sensitive data, no unauthorized data exfiltration, and standard wallet operations.

## Vulnerability Details

### FINDING 1: Broad Host Permissions (Informational)
**Severity**: INFORMATIONAL
**Files**: `manifest.json`
**Code**:
```json
"host_permissions": [
  "file://*/*",
  "http://*/*",
  "https://*/*"
],
"content_scripts": [{
  "matches": ["http://*/*", "https://*/*"],
  "run_at": "document_start",
  "all_frames": true
}]
```

**Analysis**: The extension requests broad host permissions to inject Web3 provider APIs (window.ethereum, window.tronWeb, etc.) into all web pages. This is standard and necessary for cryptocurrency wallet extensions that need to interact with dApps across all domains.

**Verdict**: NOT VULNERABLE - Required for legitimate wallet functionality

---

### FINDING 2: Private Key and Mnemonic Handling (Informational)
**Severity**: INFORMATIONAL
**Files**:
- `assets/backupPrivateKey-DlVzQWRk.js`
- `assets/backupMnemonic-BmXIxC-_.js`
- `assets/createWallet-D-CwPRHQ.js`
- `assets/index.js-8vH-KUer.js`

**Code Sample**:
```javascript
// Encryption/Decryption operations
static decryptMathWallet(t, e) {
  e = M.fromJson(e), e.decrypt(l), e.keychain.keypairs.map(i => i.decrypt(l)), t(e), e = null
}

static updateMathWallet(t, e) {
  this.lockGuard(t, () => {
    e = M.fromJson(e), e.keychain.keypairs.map(i => i.encrypt(l)), e.encrypt(l), g.setMathWallet(e).then(i => {
      e.decrypt(l), t(e)
    })
  })
}
```

**Analysis**: The extension properly encrypts sensitive cryptographic material before storage. Private keys and mnemonics are only decrypted in memory when needed and are protected by a user-provided password/seed. Data is stored in chrome.storage.local (encrypted) and never transmitted to remote servers.

**Verdict**: NOT VULNERABLE - Proper cryptographic practices observed

---

### FINDING 3: Web3 Provider Injection (Informational)
**Severity**: INFORMATIONAL
**Files**:
- `injects/evm.js`
- `injects/bitcoin.js`
- `injects/solana.js`
- `injects/tron.js`
- `injects/substrate.js`

**Code Sample**:
```javascript
// EVM injection
window.ethereum = this.provider
window.web3 = { currentProvider: this.provider }

// Bitcoin injection
window.bitcoin = t

// Tron injection
window.tronWeb && console.log("TronWeb is already initiated. MathWallet will overwrite the current instance")
```

**Analysis**: The extension injects blockchain provider objects into web pages to enable dApp interaction. This is standard wallet behavior. The providers communicate with the extension background script via postMessage, which properly validates requests and requires user approval for sensitive operations (signing transactions, accessing accounts).

**Verdict**: NOT VULNERABLE - Standard Web3 wallet architecture

---

### FINDING 4: Dynamic Code Execution (False Positive)
**Severity**: FALSE POSITIVE
**Files**: `injects/tron.js`

**Code**:
```javascript
}).call(null) || Function("return this")();
```

**Analysis**: This pattern appears in the bundled TronWeb library and is a standard polyfill for accessing the global object across different JavaScript environments. It's not used for arbitrary code execution.

**Verdict**: FALSE POSITIVE - Legitimate library code

---

### FINDING 5: Message Passing Architecture (Informational)
**Severity**: INFORMATIONAL
**Files**:
- `assets/index.js-CSO-CXFo.js`
- `assets/NetworkMessage-BW0-V9eW.js`
- `assets/MessageTags-Cc1Tzw03.js`

**Code**:
```javascript
// Content script communication
class y {
  listenMessages() {
    this.port = d.runtime.connect({ name: o });
    this.port.onMessage.addListener(t => {
      if (!t || !t.hasOwnProperty("type") || !t.hasOwnProperty("resolver") || t.type === i) return;
      const e = this.requests.find(s => s.resolver === t.resolver);
      e && this.respond(e, t.payload || {})
    });
  }
}
```

**Analysis**: The extension uses a message passing system between content scripts, injected scripts, and background service worker. Messages are properly structured with type/payload/resolver pattern. User approval is required for sensitive operations (identity requests, transaction signing).

**Verdict**: NOT VULNERABLE - Secure message architecture

## False Positive Analysis

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| `Function("return this")()` | `injects/tron.js` | Standard global object polyfill in TronWeb library |
| `proxy:` references | Multiple Vue.js files | Vue 3 reactivity Proxy objects, not network proxies |
| `password` strings | `injects/tron.js` | Part of TronWeb cryptographic library for wallet encryption |
| `localStorage` access | `assets/ChainRepository-DeACPZOU.js` | Legitimate local storage for chain configuration data |
| Base64 encoding | Multiple files | Standard data encoding for images and cryptographic operations |

## API Endpoints and Network Activity

| Endpoint/Domain | Purpose | Risk Level |
|----------------|---------|------------|
| `clients2.google.com/service/update2/crx` | Chrome Web Store updates | LOW - Standard |
| User-configured RPC nodes | Blockchain network communication | LOW - User controlled |
| Various blockchain network domains | Chain metadata and documentation | LOW - Informational |

**Note**: The extension does NOT make unauthorized network requests. All blockchain communication goes through user-configured or default RPC endpoints, which is expected behavior for a wallet.

## Data Flow Summary

```
User Input (Password/PIN)
  ↓
Decrypt Wallet (In Memory)
  ↓
User Action (Sign Transaction/Message)
  ↓
Cryptographic Signing (Local)
  ↓
Broadcast to Blockchain (User-controlled RPC)
```

**Key Points**:
- Private keys never leave the extension
- All sensitive data encrypted at rest
- User approval required for all sensitive operations
- No unauthorized data transmission
- No tracking or analytics

## Chrome API Usage

**Permissions Used**:
- `storage` - Store encrypted wallet data locally
- `unlimitedStorage` - Large blockchain data structures
- `scripting` - Dynamic content script injection
- `tabs` - Query active tabs for Web3 injection
- `alarms` - Auto-lock timer functionality
- `background` - Service worker background processing

**Content Security Policy**:
```
script-src 'self' 'wasm-unsafe-eval'; object-src 'none';
```
The `wasm-unsafe-eval` is required for WebAssembly execution (likely cryptographic operations).

## Security Strengths

1. **Proper Encryption**: All sensitive data (private keys, mnemonics) encrypted with user password
2. **No Remote Servers**: No phoning home or unauthorized data transmission
3. **User Consent**: All sensitive operations require explicit user approval
4. **Lock Mechanism**: Auto-lock functionality protects inactive sessions
5. **Local-Only Storage**: All data stored in chrome.storage.local, not synced
6. **Standard Architecture**: Follows established Web3 wallet design patterns
7. **Manifest V3**: Uses modern, more secure manifest version

## Overall Risk Assessment

**Risk Level**: CLEAN

**Justification**:
MathWallet is a legitimate cryptocurrency wallet extension that properly handles sensitive cryptographic material. While it has broad permissions and handles private keys/mnemonics, these are necessary for its core functionality as a multi-chain Web3 wallet. The extension demonstrates proper security practices:

- Encryption of sensitive data at rest
- No unauthorized network activity
- User approval gates for sensitive operations
- Standard wallet architecture patterns
- No malicious code patterns detected
- No tracking or analytics SDKs
- No ad injection or content manipulation
- No proxy infrastructure
- No extension enumeration or interference

The extension serves its stated purpose without deviating into malicious behavior. Users should trust this extension for cryptocurrency wallet operations, understanding that wallet extensions inherently require broad permissions and handle sensitive data as part of their legitimate functionality.

## Recommendations

1. Users should ensure they download from the official Chrome Web Store
2. Always verify the extension ID matches: afbcbjpbpfadlkmhmclhkeeodmamcflc
3. Use a strong password for wallet encryption
4. Enable auto-lock feature for security
5. Regularly backup mnemonic phrases securely offline
6. Be cautious about which dApps you connect to

## Conclusion

MathWallet is a legitimate, properly-implemented multi-chain cryptocurrency wallet extension with no security vulnerabilities or malicious behavior detected. The broad permissions and sensitive data handling are necessary and appropriate for wallet functionality. The extension follows security best practices and does not exhibit any red flags.
