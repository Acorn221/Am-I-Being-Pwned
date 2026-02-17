# Vulnerability Report: MyTonWallet · My TON Wallet

## Metadata
- **Extension ID**: fldfpgipfncgndfolcbkdeeknbbbnhcc
- **Extension Name**: MyTonWallet · My TON Wallet
- **Version**: 4.6.3
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

MyTonWallet is a legitimate cryptocurrency wallet extension for managing TON (The Open Network) and TRON blockchain assets. The extension implements proper security controls for a wallet application, including strict CSP policies, disclosed API endpoints, and proper message channel validation. While the static analyzer flagged postMessage handlers without explicit origin checks, manual code review reveals that the extension does validate message channels and implements origin checking through targetOrigin parameters in its inter-context communication architecture.

The extension handles sensitive cryptographic operations (private keys, mnemonics) as expected for a cryptocurrency wallet. All network communications are directed to disclosed, legitimate endpoints owned by the mytonwallet.org domain and well-known third-party services (MoonPay for fiat on/off-ramp, blockchain explorers). The use of WASM is for rlottie animation rendering, a legitimate library.

## Vulnerability Details

### 1. LOW: PostMessage Handlers Without Explicit Origin Validation in Some Contexts

**Severity**: LOW
**Files**: main.00df085f48324ea55058.js:7837, 524.b224675e028ee59b7808.js:1875, extensionServiceWorker.js:61520, extensionContentScript.js:809
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The static analyzer detected multiple window.addEventListener('message') handlers without immediate origin checks visible in the AST analysis.

**Evidence**:
```javascript
// main.00df085f48324ea55058.js:7837
window.addEventListener('message', handleMessage);

// However, the handlers validate via channel and targetOrigin:
function handleMessage(e) {
    if (targetOrigin && e.origin !== targetOrigin) return;
    if (e.data?.channel === channel) {
        void onMessage(api, e.data, sendToOrigin);
    }
}

// And in createExtensionInterface (line 7821-7833):
function handleMessage(e) {
    if (targetOrigin && e.origin !== targetOrigin) return;
    if (e.data?.channel === channel) {
        void onMessage(api, e.data, sendToOrigin);
    }
}
```

**Verdict**: The static analyzer's detection is a shallow analysis result. The code does implement origin validation through the `targetOrigin` parameter pattern and channel-based message filtering. The architecture uses a secure message-passing system with chrome.runtime.connect for extension-to-content-script communication and validates origins when communicating with embedded iframes. This is a low-severity finding due to the defense-in-depth approach, though explicit origin checks at the top of every handler would be ideal.

## False Positives Analysis

1. **WASM Usage**: The extension uses rlottie-wasm.wasm for Lottie animation rendering, a legitimate open-source library. This is not malicious.

2. **Obfuscation Flag**: The static analyzer marked the code as "obfuscated," but this is standard Webpack bundling with code splitting, not malicious obfuscation.

3. **Data Exfiltration Flow**: The analyzer detected `document.getElementById → fetch` as a potential exfiltration flow. In context, this is the normal operation of a wallet fetching blockchain data from disclosed API endpoints based on user-selected accounts/transactions.

4. **Private Key/Mnemonic References**: These are expected for a cryptocurrency wallet extension and indicate proper functionality, not malicious credential harvesting.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.mytonwallet.org | Wallet backend API | Account addresses, transaction requests | LOW - disclosed service |
| toncenter.mytonwallet.org | TON blockchain node | Blockchain queries | LOW - disclosed service |
| tonapiio.mytonwallet.org | TON API service | Blockchain queries | LOW - disclosed service |
| tronapi.mytonwallet.org | TRON blockchain API | Blockchain queries | LOW - disclosed service |
| tonconnectbridge.mytonwallet.org | TON Connect protocol bridge | dApp connection requests | LOW - disclosed service |
| buy.moonpay.com | Fiat on-ramp | Payment information (user-initiated) | LOW - legitimate third-party |
| tonscan.org / tonviewer.com | Blockchain explorers | Transaction viewing (embedded iframes) | LOW - public explorers |
| static.mytonwallet.org | Static assets | None (CDN) | LOW - asset hosting |
| fonts.googleapis.com / fonts.gstatic.com | Google Fonts | None (CSS/font loading) | LOW - Google CDN |

All endpoints are either owned by the extension developer or well-known, legitimate third-party services disclosed in the extension's description and CSP policy.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
MyTonWallet is a legitimate, well-architected cryptocurrency wallet extension with proper security controls. The postMessage handlers implement defense-in-depth through channel validation and conditional origin checking. All network communications are to disclosed, legitimate endpoints. The extension's permissions (webRequest, proxy, storage, unlimitedStorage) are appropriate for a cryptocurrency wallet that needs to manage blockchain RPC connections and store encrypted user data. The CSP policy is strict and properly configured. No evidence of malicious behavior, undisclosed data collection, or security vulnerabilities beyond the minor architectural improvement opportunity around explicit origin validation.
