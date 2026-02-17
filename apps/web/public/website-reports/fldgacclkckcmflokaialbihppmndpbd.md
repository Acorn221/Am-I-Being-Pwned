# Vulnerability Report: Mapify - AI Summarizer & Mind Map Generator for YouTube, PDFs, and Webpages

## Metadata
- **Extension ID**: fldgacclkckcmflokaialbihppmndpbd
- **Extension Name**: Mapify - AI Summarizer & Mind Map Generator for YouTube, PDFs, and Webpages
- **Version**: 1.6.3
- **Users**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Mapify is an AI-powered extension that generates mind maps and summaries from web content, YouTube videos, and PDFs. The extension uses third-party analytics services (Mixpanel and Plausible) to track user interactions and behavior. While the static analyzer flagged potential exfiltration flows and postMessage handlers without origin validation, deeper code analysis reveals these are false positives or low-severity issues. The extension's data collection is limited to usage analytics and authentication flows to its primary service (mapify.so), which is expected for an AI-powered cloud service. The extension does not access sensitive user data beyond what is necessary for its stated functionality.

The primary security concern is the use of postMessage event listeners without strict origin validation in the content script, which could theoretically allow malicious websites to interact with the extension's messaging system. However, the risk is mitigated by the extension's architecture and the nature of the data flows.

## Vulnerability Details

### 1. LOW: postMessage Event Listeners Without Origin Validation
**Severity**: LOW
**Files**: content-scripts/content.js (lines ~6520, 6541)
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The content script registers multiple window message event listeners that check for a specific `target` field in the message data (`t.data.target === "content-script"`) but do not validate the origin of the message sender. This could theoretically allow a malicious webpage to send crafted messages to the extension's message handlers.

**Evidence**:
```javascript
// Line 6520
window.addEventListener("message", t => {
  Do.value || t.data.target === "content-script" && e(t.data.data)
})

// Line 6541
window.addEventListener("message", n => {
  Do.value === t && n.data.target === "content-script" && r(n.data.data)
})
```

**Verdict**: While this is a security weakness, the actual risk is low because:
1. The handlers only process messages with a specific target field
2. The extension's architecture appears to use these for internal component communication (likely between injected elements and the content script)
3. No sensitive operations appear to be triggered directly by these message handlers
4. The extension operates primarily on mapify.so domains where this communication is intentional

## False Positives Analysis

### Static Analyzer Exfiltration Flows to www.w3.org
The static analyzer reported exfiltration flows to `www.w3.org`, which are false positives. These references are:
- XML namespace declarations for SVG and MathML rendering (`http://www.w3.org/2000/svg`, `http://www.w3.org/1998/Math/MathML`, `http://www.w3.org/1999/xlink`)
- These are standard DOM API constants used by the Vue.js framework for rendering, not actual network requests

### Webpack-bundled Code Flagged as "Obfuscated"
The extension uses standard Vue.js and modern JavaScript build tooling (Vite/Webpack). The minimized/bundled code is not maliciously obfuscated but rather the result of normal production build processes. The code structure includes:
- Vue.js framework code
- Browser polyfills (webextension-polyfill)
- Consola logging library
- Standard UI component libraries

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://mapify.so | Primary service backend | User authentication, content to summarize, mind map data | Low - Expected functionality |
| https://api-js.mixpanel.com | Analytics tracking | Usage events, page views, feature interactions | Low - Standard analytics, disclosed behavior |
| https://plausible.io | Privacy-friendly analytics | Pageview events, basic usage metrics | Low - Privacy-preserving analytics service |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
The extension performs its stated functionality (AI-powered content summarization and mind mapping) without engaging in undisclosed data collection or malicious behavior. The analytics integrations (Mixpanel and Plausible) are standard for understanding user engagement and are limited to tracking usage events rather than sensitive user data. The extension appropriately requests `<all_urls>` host permissions because it needs to access and analyze content from any webpage the user visits, which aligns with its purpose.

The postMessage origin validation weakness is the only identified vulnerability, and it poses minimal practical risk given the extension's architecture and usage patterns. The extension does not access cookies beyond its own authentication needs, does not perform credential harvesting, and does not inject ads or affiliate links.

**Recommendation**: Users concerned about analytics tracking should be aware that the extension sends usage data to Mixpanel and Plausible. Otherwise, the extension appears safe for its intended purpose.
