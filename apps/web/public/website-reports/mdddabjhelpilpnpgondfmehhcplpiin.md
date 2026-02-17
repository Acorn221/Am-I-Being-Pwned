# Vulnerability Report: Explain and Send Screenshots

## Metadata
- **Extension ID**: mdddabjhelpilpnpgondfmehhcplpiin
- **Extension Name**: Explain and Send Screenshots
- **Version**: 19.0.11
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Explain and Send Screenshots is a legitimate screenshot and screen recording extension developed by Jason Savard. The extension provides functionality to capture screenshots, record screen video, and edit/annotate images. Analysis reveals this is a clean extension with standard permissions appropriate for its functionality. The extension includes a donation/contribution system for unlocking premium features, which is a standard monetization pattern. No security vulnerabilities, privacy issues, or malicious behavior were identified.

The extension uses permissions (storage, activeTab, scripting, system.display, alarms, offscreen) strictly for its stated screenshot and recording functionality. All network communication is limited to the developer's legitimate domains (jasonsavard.com, apps.jasonsavard.com) and payment processors (PayPal, Stripe, Coinbase).

## Vulnerability Details

No vulnerabilities found. This section documents false positives and legitimate behaviors that were analyzed.

### FALSE POSITIVE: WebAssembly and Obfuscation Flags
**Severity**: N/A
**Files**: js/tfjs-imports.js
**Description**: The ext-analyzer flagged this extension with "WASM" and "obfuscated" flags. Investigation reveals the extension includes TensorFlow.js (113,649 lines in tfjs-imports.js) for machine learning features (likely background removal mentioned in the UI). This is bundled/minified library code, not obfuscated malware.
**Evidence**: The tfjs-imports.js file contains legitimate TensorFlow.js library code with identifiable function names like `makeTrainFunction`, `poolingFunction`, `iteratorFromFunction`, etc.
**Verdict**: False positive - legitimate bundled ML library, not obfuscation for malicious purposes.

### FALSE POSITIVE: Dynamic Code Execution
**Severity**: N/A
**Files**: js/explainAndSendScreenshots.js (lines 328, 435, 438)
**Description**: The extension uses `chrome.scripting.executeScript` to inject content scripts for screenshot selection functionality.
**Evidence**:
```javascript
// Line 328 - Select element functionality
await chrome.scripting.executeScript({target: {tabId: tab.id}, files: [
    "js/contentScriptSelectElement.js"
]});

// Line 438 - Entire page capture
const responses = await chrome.scripting.executeScript({target: {tabId: tab.id, frameIds:[0]}, files: [
    "js/contentScript.js"
]});
```
**Verdict**: Legitimate use of scripting API to inject content scripts for user-initiated screenshot capture. This is the standard Chrome extension pattern for interacting with page content.

## False Positives Analysis

1. **TensorFlow.js Library**: The 113KB+ tfjs-imports.js file is a legitimate machine learning library, likely used for the "Remove background" feature mentioned in the UI strings. This is bundled/minified code, not malicious obfuscation.

2. **Content Script Injection**: The extension injects content scripts only when the user explicitly triggers screenshot/selection actions. This is necessary for capturing page content and element selection.

3. **Payment Processing**: The extension includes comprehensive donation/payment code (contribute.js) for Stripe, PayPal, Coinbase, Apple Pay, and Alipay/WeChat Pay. This is a legitimate freemium monetization model.

4. **Third-party Domains**: All external domains are legitimate:
   - jasonsavard.com - Developer's website
   - apps.jasonsavard.com - Developer's API server
   - checkout.stripe.com, paypal.com, coinbase.com - Payment processors
   - versionhistory.googleapis.com - Chrome version checking

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| jasonsavard.com | Homepage, changelog, uninstall tracking | Extension version, days installed | None - standard telemetry |
| apps.jasonsavard.com/controller.php | Donation verification, minimum payment amounts | Item ID, email (optional) | None - payment backend |
| apps.jasonsavard.com/paymentSystems/* | Payment processing | Payment details, amounts, currency | None - standard payment flow |
| jasonsavard.com/getBrowserDetails | Firefox version checking | User agent | None - compatibility checking |
| jasonsavard.com/qrcode | QR code generation for mobile payments | Payment URL | None - UI utility |
| versionhistory.googleapis.com | Chrome version validation | Browser version | None - Google API |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This is a legitimate, professionally developed screenshot extension with no security or privacy concerns. The extension:

1. **Appropriate Permissions**: Uses only permissions necessary for screenshot/recording functionality (activeTab, scripting, desktopCapture, tabCapture, etc.)
2. **No Data Exfiltration**: Does not collect or transmit user data beyond optional donation emails
3. **Transparent Monetization**: Uses standard freemium model with optional premium features unlocked via donation
4. **Professional Development**: Well-structured code, proper error handling, extensive localization (6 languages)
5. **User Control**: All screenshot/recording actions are user-initiated, not automatic
6. **No Analytics**: The `sendGA()` function is a no-op - analytics were removed or never implemented
7. **Secure Architecture**: MV3 service worker, proper CSP, sandboxed offscreen documents for media recording
8. **Open Communication**: Uses documented Chrome APIs, no hidden behaviors

The extension's description claim of "NO crazy permissions" is accurate - it requests only what's needed for screenshots and recording. This is a clean extension suitable for production use.
