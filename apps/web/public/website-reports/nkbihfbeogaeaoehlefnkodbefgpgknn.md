# MetaMask Security Analysis Report

## Metadata
| Field | Value |
|---|---|
| Extension Name | MetaMask |
| Extension ID | `nkbihfbeogaeaoehlefnkodbefgpgknn` |
| Version | 13.16.1 |
| Manifest Version | 3 |
| User Count | ~13,000,000 |
| Author | https://metamask.io |
| Analysis Date | 2026-02-08 |

## Executive Summary

MetaMask is the most widely-used Ethereum/Web3 wallet browser extension. This analysis found **no malicious behavior, no data exfiltration, and no key vulnerabilities**. The extension requests broad permissions (all URLs, webRequest, scripting, etc.) which are **necessary for its core function** as a Web3 provider that must inject an Ethereum provider object into every webpage and communicate with blockchain RPC nodes.

The codebase is well-structured, uses SES (Secure ECMAScript) lockdown for runtime hardening, LavaMoat for supply chain security, Snow for realm protection, and Blockaid for transaction security scanning. Analytics (Segment/MetaMetrics) are opt-in with a clear `participateInMetaMetrics` flag that gates all telemetry. The extension includes a phishing detection system and transaction security validation via PPOM (Privacy-Preserving Offline Module).

## Permissions Analysis

| Permission | Justification |
|---|---|
| `activeTab` | Needed to interact with the current tab for dapp connections |
| `alarms` | Service worker keep-alive and scheduled tasks |
| `clipboardWrite` | Copy addresses/transaction data to clipboard |
| `notifications` | Transaction confirmations/alerts |
| `scripting` | Content script injection for Web3 provider |
| `storage` / `unlimitedStorage` | Wallet data, preferences, transaction history |
| `webRequest` | Phishing detection (onBeforeRequest) and deep link handling |
| `offscreen` | Hardware wallet communication (Ledger/Trezor/Lattice), Snaps execution |
| `identity` | Google OAuth for MetaMask institutional/portfolio features |
| `sidePanel` | Chrome side panel UI |
| `host_permissions: all URLs` | Must inject Web3 provider on any website, connect to any RPC endpoint |

**Optional:** `clipboardRead` - only requested when user explicitly enables paste functionality.

## CSP Analysis

- **Extension pages:** `script-src 'self' 'wasm-unsafe-eval'` - Tight. Only allows self scripts and WASM (needed for PPOM and crypto operations). No `unsafe-eval` or `unsafe-inline`.
- **Sandbox (Snaps):** `script-src 'self' 'unsafe-inline' 'unsafe-eval'` - Intentionally permissive for the Snaps sandbox, which runs third-party Snap code in an isolated sandbox page with SES lockdown. The sandbox has `default-src 'none'` and `connect-src *` (Snaps need network access).

## Vulnerability Details

### INFO-01: Broad `externally_connectable` Configuration
- **Severity:** INFO
- **File:** `manifest.json`
- **Code:** `"matches": ["http://*/*", "https://*/*"], "ids": ["*"]`
- **Analysis:** Any website or extension can initiate a connection to MetaMask. However, all external connections are routed through `setupUntrustedCommunicationEip1193` / `setupUntrustedCommunicationCaip`, which treat them as untrusted and require explicit user approval for any sensitive operation.
- **Verdict:** By design. This is how dapps connect to MetaMask. All connections are untrusted and gated by user confirmation.

### INFO-02: Content Script Runs on All Pages at `document_start`
- **Severity:** INFO
- **File:** `manifest.json`, `scripts/contentscript.js`, `scripts/inpage.js`
- **Code:** `"matches": ["file://*/*", "http://*/*", "https://*/*"], "run_at": "document_start", "all_frames": true`
- **Analysis:** The content script injects the `window.ethereum` provider (EIP-1193) into every page via the MAIN world. This is the fundamental requirement for a Web3 wallet.
- **Verdict:** Expected behavior for a Web3 wallet extension.

### INFO-03: Segment Analytics (Opt-In MetaMetrics)
- **Severity:** INFO
- **File:** `common-6.js`, `common-11.js`
- **Code:** `this.host=(0,o.default)(t.host||"https://api.segment.io")` routed via `https://proxy.api.cx.metamask.io/segment/v1`
- **Analysis:** Analytics data is only sent when `participateInMetaMetrics === true`, explicitly checked: `if(!0!==n)return null`. Users opt in during onboarding and can disable it in settings. MetaMask provides a Data Deletion Service (`DataDeletionService`) that allows users to request deletion of collected analytics.
- **Verdict:** Legitimate opt-in analytics with data deletion support. Not a privacy concern.

### INFO-04: Remote Feature Flags
- **Severity:** INFO
- **File:** `background-1.js`, `background-9.js`
- **Code:** `BASE_URL="https://client-config.api.cx.metamask.io/v1"` via `@metamask/remote-feature-flag-controller`
- **Analysis:** Feature flags are fetched from MetaMask's API to enable/disable features. This is a standard practice used by the official `@metamask/remote-feature-flag-controller` package. No evidence of code injection or behavior modification beyond feature gating.
- **Verdict:** Standard feature flag system. No kill switch or remote code execution capability.

### INFO-05: Snaps Sandbox with `unsafe-eval`
- **Severity:** INFO
- **File:** `manifest.json` (sandbox CSP), `snaps/index.html`
- **Analysis:** The Snaps sandbox uses `unsafe-eval` to execute third-party Snap code. This is intentional and runs in a fully sandboxed page with SES lockdown (`lockdown()` + `harden()`), preventing Snaps from accessing the extension's privileged APIs directly. Communication is strictly via `postMessage` streams.
- **Verdict:** Secure-by-design sandbox architecture. The `unsafe-eval` is contained within the sandbox and does not affect extension pages.

### INFO-06: WASM Binary (PPOM)
- **Severity:** INFO
- **File:** `scripts/ppom_bg.wasm` (3.3MB)
- **Analysis:** This is the Privacy-Preserving Offline Module (PPOM) from Blockaid (`@blockaid/ppom_release`), used for client-side transaction security scanning. The CSP allows `wasm-unsafe-eval` specifically for this module.
- **Verdict:** Legitimate security feature for transaction validation.

## False Positive Table

| Pattern | File(s) | Reason |
|---|---|---|
| `eval()` | `background-8.js` | `shmeval()` function in `@open-rpc/schema-utils-js` JSON pointer evaluation - not code execution |
| `eval()` | `scripts/lockdown-install.js`, `scripts/runtime-lavamoat.js` | SES lockdown eval taming - security hardening code that restricts eval |
| `String.fromCharCode` | `ui-3.js`, `common-13.js` | Standard library usage: markdown parsing, ethers.js hex conversion, base64 encoding |
| `innerHTML` | `ui-*.js`, `common-6.js` | React SVG rendering (known FP) |
| `document.cookie` | `scripts/contentscript.js`, `scripts/inpage.js`, `common-9.js` | `loglevel` library storing log level preference in cookie - standard logging library |
| `document.cookie` | `background-4.js` | Axios cookie handling for HTTP requests to RPC nodes |
| `keydown/keyup` | Multiple UI files | UI keyboard shortcut handling and form input management |
| `postMessage` | Multiple files | Inter-context communication (content script <-> background, offscreen <-> background, Snaps sandbox <-> host) |
| `btoa/atob` | Multiple files | Standard base64 encoding for blockchain data serialization |
| Sentry SDK | `scripts/sentry-install.js`, `background-9.js` | Known FP - Sentry error reporting with opt-in consent |
| Firebase/FCM | `background-8.js` | Push notification registration for transaction alerts |
| `chrome.scripting.executeScript` | `common-6.js` | No-op function injection to verify content script connectivity: `func:()=>{}` |

## API Endpoints Table

| Endpoint | Purpose |
|---|---|
| `https://*.infura.io/v3/{projectId}` | Blockchain RPC nodes (Ethereum, Polygon, Arbitrum, etc.) |
| `https://proxy.api.cx.metamask.io/segment/v1` | Analytics proxy (opt-in MetaMetrics) |
| `https://client-config.api.cx.metamask.io/v1` | Remote feature flags |
| `https://gas.api.cx.metamask.io` | Gas price estimates |
| `https://token.api.cx.metamask.io` | Token metadata and logos |
| `https://price.api.cx.metamask.io` | Token price data |
| `https://swap.api.cx.metamask.io` | Token swap quotes |
| `https://bridge.api.cx.metamask.io` | Cross-chain bridge quotes |
| `https://nft.api.cx.metamask.io` | NFT metadata |
| `https://proxy.api.cx.metamask.io/opensea/v1/api/v2` | OpenSea NFT proxy |
| `https://security-alerts.api.cx.metamask.io` | Transaction security scanning |
| `https://phishing-detection.api.cx.metamask.io` | Phishing site detection lists |
| `https://client-side-detection.api.cx.metamask.io` | Client-side threat detection |
| `https://dapp-scanning.api.cx.metamask.io` | Dapp security scanning |
| `https://authentication.api.cx.metamask.io` | MetaMask account authentication |
| `https://user-storage.api.cx.metamask.io` | Synced user settings |
| `https://notification.api.cx.metamask.io` | Push notifications |
| `https://push.api.cx.metamask.io` | Push notification delivery |
| `https://transaction.api.cx.metamask.io` | Transaction history |
| `https://accounts.api.cx.metamask.io` | Account management |
| `https://npm-ota.api.cx.metamask.io` | Snaps npm package proxy |
| `https://execution.metamask.io/iframe/10.3.0/index.html` | Snaps execution iframe |
| `https://acl.execution.metamask.io/latest/registry.json` | Snaps permission registry |
| `https://metamask.github.io/phishing-warning/v5.1.0/` | Phishing warning page |
| `https://metamask.github.io/ledger-iframe-bridge/9.0.1/` | Ledger hardware wallet bridge |
| `https://on-ramp.api.cx.metamask.io/geolocation` | Fiat on-ramp geolocation |
| `https://rewards.api.cx.metamask.io` | MetaMask rewards program |
| `https://perps.api.cx.metamask.io` | Perpetual trading features |
| `https://defiadapters.api.cx.metamask.io` | DeFi protocol adapters |
| `https://tx-sentinel-*.api.cx.metamask.io` | Smart transaction submission |
| `https://accounts.google.com/o/oauth2/v2/auth` | Google OAuth (institutional features) |
| `https://fcmregistrations.googleapis.com/v1` | Firebase Cloud Messaging registration |

## Data Flow Summary

1. **Content Script -> Background:** The content script (`contentscript.js`) establishes a port-based connection to the service worker, relaying dapp RPC requests (eth_sendTransaction, eth_sign, etc.) from the injected `window.ethereum` provider.

2. **Background -> Blockchain:** The service worker routes RPC requests to configured Infura endpoints or custom RPC URLs, using the user's selected network.

3. **Background -> MetaMask APIs:** Various controllers fetch gas prices, token prices, security alerts, phishing lists, and feature flags from MetaMask's `*.api.cx.metamask.io` infrastructure.

4. **Analytics (opt-in):** When MetaMetrics is enabled, anonymized usage events are sent to Segment via MetaMask's proxy (`proxy.api.cx.metamask.io/segment/v1`). A `DataDeletionService` is available for GDPR compliance.

5. **Hardware Wallets:** Offscreen document communicates with Ledger (via iframe bridge), Trezor (via `@trezor/connect-web`), and Lattice (via window popup) for hardware signing.

6. **Snaps:** Third-party Snaps execute in a sandboxed iframe (`execution.metamask.io`) with SES lockdown, communicating via `postMessage` streams through the offscreen document.

7. **Security:** Phishing detection intercepts navigation via `webRequest.onBeforeRequest`, and Blockaid's PPOM WASM module validates transactions client-side before submission.

## Security Hardening

MetaMask employs several layers of security hardening uncommon in browser extensions:

- **SES Lockdown:** `lockdown()` freezes all JavaScript intrinsics, preventing prototype pollution and supply chain attacks.
- **LavaMoat:** Runtime supply chain security that compartmentalizes all third-party packages with per-package policies (`scripts/policy-load.js`, `scripts/runtime-lavamoat.js`).
- **Snow:** Realm protection that scuttles new realm creation attempts, preventing iframe-based prototype pollution bypasses.
- **Console Taming:** `scripts/disable-console.js` disables console methods in production to prevent information leakage.
- **Intrinsic Protection:** `scripts/lockdown-more.js` makes all global properties non-configurable and non-writable after lockdown.

## Overall Risk Assessment

| Rating | CLEAN |
|---|---|

**Justification:** MetaMask is a legitimate, well-engineered Web3 wallet extension. Its broad permissions (all URLs, webRequest, scripting, storage, identity) are all necessary for its core functionality as a universal Web3 provider. The extension:

- Does NOT access cookies, history, or bookmarks
- Does NOT enumerate or interact with other extensions
- Does NOT inject ads, coupons, or affiliate links
- Does NOT contain obfuscated or suspicious code
- Does NOT use residential proxy infrastructure
- Does NOT contain market intelligence SDKs
- Does NOT scrape AI conversations or web content
- Analytics are strictly opt-in with user-facing controls and data deletion capability
- All API communication is to MetaMask's own infrastructure (`*.api.cx.metamask.io`, `*.infura.io`)
- Employs industry-leading security hardening (SES, LavaMoat, Snow, Blockaid)

The extension is invasive by necessity (it must inject into every page), but serves its intended purpose with no evidence of malicious behavior.
