# Vulnerability Report: Razor Wallet

## Metadata
- **Extension ID**: fdcnegogpncmfejlfnffnofpngdiejii
- **Extension Name**: Razor Wallet
- **Version**: 2.0.22
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Razor Wallet is a cryptocurrency wallet extension for the Move ecosystem (Aptos, Cedra, Movement networks). It provides standard wallet functionality including account management, transaction signing, and network switching. The extension uses a content script injected on all URLs to facilitate communication between web pages and the wallet.

The primary security concern is the use of `window.addEventListener("message")` handlers in the injected script without proper origin validation. While the extension does capture `event.origin` in the content script, several message listeners in `injectScript.js` do not validate the message source, potentially allowing malicious websites to interact with wallet functionality or inject crafted messages.

## Vulnerability Details

### 1. MEDIUM: Insufficient postMessage Origin Validation

**Severity**: MEDIUM
**Files**: injectScript.js (lines 21044, 21065, 21352, 21373, 21660, 21679)
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension's injected script registers multiple `window.addEventListener("message")` handlers that process messages without validating the origin. While there is a validation mechanism that checks for the `isRazor` flag in messages, there is no verification that messages originate from the extension itself or trusted sources. This creates an attack surface where malicious websites could potentially craft messages with the correct structure.

**Evidence**:
```javascript
// Line 21044 - No origin check before processing
window.addEventListener("message", i), window.postMessage({
  isRazor: !0,
  line: Eg.APTOS,
  type: Ps.REQUEST__WEB_TO_CONTENT_SCRIPT,
  messageId: n,
  message: t
});

// Line 21679-21683 - Message listener that references origin but doesn't validate
(async () => window.addEventListener(
  "message",
  (t) => {
    t.origin, window.location.origin;  // Origin is accessed but not compared
  }
))();
```

The content script does capture origin properly:
```javascript
// contentScript.ts-B100O46I.js:10
origin: event.origin,
```

However, the message handlers in the injected script rely solely on checking the `isRazor` flag rather than verifying the message origin matches the extension or the current page.

**Verdict**:
This is a **MEDIUM** risk issue. While the extension uses message filtering via the `isRazor` flag and structured message types, the lack of explicit origin validation is a security weakness. An attacker would need to reverse-engineer the message protocol and include the correct flags, which provides some protection, but this is security through obscurity rather than proper origin validation. The risk is mitigated by:
1. The extension's use of structured message types and validation
2. Critical operations (signing transactions) appear to require user interaction via popup windows
3. The background script does check allowed origins for account connections

### 2. FALSE POSITIVE: Data Exfiltration Flow

**Severity**: N/A
**Files**: assets/main-C2frhYCq.js

**Description**:
The static analyzer flagged a flow from `document.querySelectorAll` to `fetch`. Upon investigation, this is legitimate functionality:
- Line 68: `fetch(link.href, fetchOpts)` - This is part of resource preloading logic for the React-based UI
- Line 39739: Standard HTTP request handling using axios/fetch libraries
- All fetch calls are to legitimate blockchain RPC endpoints and explorers

**Verdict**:
This is a false positive. The extension makes network requests to blockchain nodes and indexers as expected for a cryptocurrency wallet. No sensitive user data is being exfiltrated.

## False Positives Analysis

1. **Obfuscation Flag**: The extension is built with webpack/bundler which minifies variable names (e.g., `t`, `e`, `r`, `n`). This is standard build tooling, not malicious obfuscation.

2. **All URLs Permission**: Required for wallet functionality - the extension needs to inject its provider API on websites that interact with blockchain dApps.

3. **Fetch Calls**: All network requests are to legitimate blockchain infrastructure:
   - Aptos/Cedra/Movement RPC endpoints for transaction submission
   - GraphQL indexers for account data
   - Block explorers for transaction viewing
   - Faucets for testnet token distribution

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| testnet.cedra.dev | Cedra blockchain RPC | Signed transactions, account queries | Low - legitimate blockchain node |
| graphql.cedra.dev | Cedra GraphQL indexer | Account/transaction queries | Low - read-only queries |
| full.mainnet.movementinfra.xyz | Movement blockchain RPC | Signed transactions, account queries | Low - legitimate blockchain node |
| indexer.mainnet.movementnetwork.xyz | Movement GraphQL indexer | Account/transaction queries | Low - read-only queries |
| rpc.sentio.xyz | Aptos blockchain RPC (via Sentio) | Signed transactions, account queries | Low - legitimate third-party node provider |
| api.mainnet.aptoslabs.com | Aptos GraphQL indexer | Account/transaction queries | Low - official Aptos Labs infrastructure |

All endpoints are standard blockchain infrastructure. The extension does not send data to analytics servers, advertising networks, or unexpected third-party services.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
Razor Wallet is a legitimate cryptocurrency wallet extension with standard functionality for the Move ecosystem. The primary security concern is the insufficient origin validation in postMessage handlers, which could theoretically allow malicious websites to attempt message injection attacks. However, this risk is partially mitigated by:

1. Use of structured message protocols with type checking
2. User interaction requirements for sensitive operations
3. The background script maintains allowed origins lists
4. No evidence of data exfiltration or malicious behavior

The extension follows standard patterns for wallet extensions (similar to MetaMask, Phantom, etc.) and communicates only with legitimate blockchain infrastructure. The postMessage vulnerability should be addressed by implementing strict origin validation, but the overall security posture is acceptable for a cryptocurrency wallet with proper user awareness.

**Recommendations**:
1. Add explicit origin validation to all postMessage event listeners
2. Validate that messages originate from the extension's content script or the current page origin
3. Consider using more restrictive message filtering beyond just the `isRazor` flag
4. Implement Content Security Policy headers for additional protection
