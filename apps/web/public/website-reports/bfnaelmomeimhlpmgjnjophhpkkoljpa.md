# Vulnerability Report: Phantom

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Phantom |
| Extension ID | bfnaelmomeimhlpmgjnjophhpkkoljpa |
| Version | 26.4.0 |
| Manifest Version | 3 |
| Users | ~5,000,000 |
| Category | Crypto Wallet (Solana, Ethereum, Bitcoin, Sui) |

## Executive Summary

Phantom is a well-known multi-chain cryptocurrency wallet supporting Solana, Ethereum (and L2s), Bitcoin, and Sui. The extension requests broad but justified permissions for its intended functionality as a wallet that must interact with dApps across all websites. The codebase is professionally structured using modern bundling (ESBuild with code-splitting), contains no evidence of malicious behavior, data exfiltration, or supply chain compromise. All external communications are directed to first-party Phantom infrastructure (`*.phantom.app`, `*.phantom.dev`, `*.phantom.com`) or well-known blockchain RPC endpoints. The extension includes proactive security features such as Blowfish-powered phishing blocklist protection, transaction simulation, and encrypted vault storage.

## Permissions Analysis

| Permission | Justification | Risk |
|------------|---------------|------|
| `activeTab` | Access current tab for dApp interaction | LOW |
| `alarms` | Periodic tasks (e.g., token price refresh, session management) | LOW |
| `identity` | OAuth2 authentication for Phantom accounts | LOW |
| `storage` / `unlimitedStorage` | Wallet data, encrypted keys, settings | LOW |
| `scripting` | Inject provider scripts into pages for dApp connectivity | MEDIUM |
| `tabs` | Manage popup windows for transaction approval | LOW |
| `webRequest` | Phishing blocklist - intercepts navigations to known scam sites | MEDIUM |
| `sidePanel` | Side panel UI support | LOW |
| `host_permissions: <all_urls>` | Required for wallet to work on any dApp site | MEDIUM |

**Assessment:** All permissions are justified for a multi-chain crypto wallet. The broad host_permissions and webRequest are necessary: host_permissions for injecting provider APIs on any dApp, and webRequest for phishing protection.

## Content Security Policy

```
script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; worker-src 'self'
```

**Assessment:** Appropriately restrictive CSP. `wasm-unsafe-eval` is required for WASM modules (Juicebox SDK, Rive animations). No `unsafe-eval` or remote script sources.

## Vulnerability Details

### 1. MetaMask Compatibility Flag (`isMetaMask=!0`)
- **Severity:** INFO
- **File:** `evmMetamask.js`
- **Code:** `isPhantom=!0;isMetaMask=!0`
- **Verdict:** FALSE POSITIVE - This is standard practice in the wallet ecosystem. Phantom implements MetaMask-compatible APIs so dApps that only check for `window.ethereum.isMetaMask` still work. Phantom also announces itself via EIP-6963 with its own `rdns: "app.phantom"`.

### 2. Broad Content Script Injection (MAIN world)
- **Severity:** LOW
- **Files:** `manifest.json`, `solana.js`, `phantom.js`
- **Details:** Content scripts inject into all frames on all URLs at `document_start` in the MAIN world.
- **Verdict:** EXPECTED - Required to expose `window.solana`, `window.phantom`, and `window.ethereum` provider objects to dApps. This is the standard architecture for all browser-based crypto wallets.

### 3. Feature Flags via Eppo SDK
- **Severity:** INFO
- **File:** `chunk-7YHYDYR3.js`
- **Code:** `BASE_URL="https://fscdn.eppo.cloud/api"`, `PRECOMPUTED_BASE_URL="https://fs-edge-assignment.eppo.cloud"`
- **Verdict:** EXPECTED - Eppo is a legitimate feature flagging service. Used for standard A/B testing and kill switches for features like swaps, staking, perps, etc. No evidence of remote code execution capability.

### 4. Datadog RUM & Sentry Error Tracking
- **Severity:** INFO
- **Files:** `chunk-5QQLABHI.js` (Datadog RUM), `chunk-7YHYDYR3.js` (Sentry), `chunk-7CWP5SI2.js` (config)
- **Code:** `dsn:"https://pub5df2cf131c51c4215f2ca3aa32d4e4b7@sentry-intake.datadoghq.com/1"`, `sampleRate:.1`
- **Verdict:** EXPECTED - Standard production monitoring. Sentry captures errors only (10% sample rate). Datadog RUM is used for frontend performance monitoring. Both are industry-standard tools with no evidence of collecting wallet data or private keys.

### 5. `executeScript` for Favicon/Tab Meta Extraction
- **Severity:** LOW
- **File:** `background/serviceWorker.js`
- **Code:** `scripting.executeScript({target:{tabId:e},func:()=>{let i={},a=document.querySelectorAll("head link[rel^=apple-touch-icon]")...`
- **Verdict:** EXPECTED - Extracts favicon and page title for display in dApp connection UI. The injected function is a static inline function (not remote code), and only reads meta information.

### 6. Clipboard Write Access
- **Severity:** INFO
- **File:** `chunk-QDOMAMUW.js`
- **Code:** `navigator.clipboard.writeText(J)` (copy wallet address / link to clipboard)
- **Verdict:** EXPECTED - User-initiated clipboard write for copy-to-clipboard functionality (addresses, transaction links). No clipboard reading or monitoring detected.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `isMetaMask=!0` | evmMetamask.js | Standard EVM wallet compatibility pattern |
| `innerHTML` references | chunk-VKBPNC3B.js | XSS detection regex in i18next sanitization, not usage |
| `document.cookie` | chunk-VKBPNC3B.js, chunk-OENHJLUF.js | i18next language detection module + Axios cookie handling for API auth |
| `new Function` | (not found) | No dynamic code execution |
| `eval()` | (not found) | No eval usage in key files |
| `base64` encode/decode | contentScript.js, background/serviceWorker.js | Buffer polyfill and cryptographic operations |
| `proxy` keyword | Multiple chunks | Solana RPC proxy endpoint (`node-proxy.phantom.app`) and JavaScript Proxy objects, not residential proxy |
| React `dangerouslySetInnerHTML` reference | chunk-4HDKJQH4.js | React framework warning messages, not actual usage |

## API Endpoints Table

| Endpoint | Purpose |
|----------|---------|
| `https://api.phantom.app` | Main Phantom API (account data, settings) |
| `https://auth.phantom.app` | OAuth2 authentication |
| `https://data.phantom.app` | Asset/token data |
| `https://node-proxy.phantom.app` | Solana RPC proxy |
| `https://solana-mainnet.phantom.app` | Solana mainnet RPC endpoint |
| `https://btc-mainnet.phantom.app` | Bitcoin RPC endpoint |
| `https://gas-price-oracle.phantom.app` | EVM gas price oracle |
| `https://blowfish-blocklist-proxy.phantom.app` | Phishing/scam domain blocklist |
| `https://sanity-proxy-v2.phantom.app` | CMS content proxy |
| `https://eppo-proxy.phantom.app/api` | Feature flag configuration |
| `https://time.phantom.app/utc` | Server time sync |
| `https://trade.phantom.com` | Swap/trade functionality |
| `https://sui-mainnet.mystenlabs.com/graphql` | Sui network RPC |
| `https://api.hyperliquid.xyz/info` | Hyperliquid DEX data |
| `https://fscdn.eppo.cloud/api` | Eppo feature flags CDN |
| `https://sentry-intake.datadoghq.com` | Error reporting (Sentry via Datadog) |
| `https://d20xtzwzcl0ceb.cloudfront.net` | Datadog RUM CDN |
| `https://production-juicebox.phantom.app` | Social recovery (Juicebox SDK) |
| `https://cdn.live.ledger.com` | Ledger hardware wallet crypto assets |

## Data Flow Summary

1. **Provider Injection:** Content scripts (`solana.js`, `phantom.js`) inject in MAIN world to expose `window.solana`, `window.phantom`, and `window.ethereum` provider objects. These communicate with the background service worker via `runtime.connect()` port messaging.

2. **Content Script Bridge:** `contentScript.js` runs in ISOLATED world, establishing a message port to the background service worker. It relays messages between MAIN world (via `CustomEvent` on `phantomRpcMessage`/`dappRpcMessage`) and the extension background.

3. **Transaction Flow:** dApp requests (connect, sign, send) flow from page -> content script -> background service worker -> approval popup -> back to background -> response to dApp. Private keys never leave the encrypted vault in the background.

4. **Phishing Protection:** `webRequest.onBeforeSendHeaders` intercepts navigations, checks URLs against Blowfish bloom filter blocklist, and redirects to `phishing.html` warning page if match found.

5. **Telemetry:** Error reporting via Sentry (10% sample rate) and Datadog RUM for performance monitoring. Feature flags via Eppo. No evidence of collecting wallet addresses, balances, transaction data, or private keys in telemetry.

6. **Key Management:** Encrypted vault using KMS (Key Management Service) with password-derived encryption. Social recovery via Juicebox SDK. Hardware wallet support via Ledger.

## Overall Risk Assessment

**CLEAN**

Phantom is a legitimate, professionally-built multi-chain cryptocurrency wallet with ~5 million users. While it requires broad permissions (all URLs, webRequest, scripting, tabs), every permission is justified by its core functionality as a wallet that must:
- Inject provider APIs on any website for dApp interaction
- Monitor navigations for phishing protection
- Manage popup windows for transaction approvals
- Store encrypted wallet data

The extension demonstrates multiple proactive security measures:
- Blowfish-powered phishing domain blocklist
- Transaction simulation before signing
- Encrypted vault with KMS
- Strict CSP without `unsafe-eval`
- No dynamic code execution (no eval, no new Function)

All network communications go to first-party Phantom infrastructure or well-known blockchain endpoints. No evidence of data exfiltration, residential proxy infrastructure, ad injection, AI scraping, or any malicious behavior.
