# Vulnerability Report: AITDK SEO Extension - Traffic/Keywords/Whois/SEO analyzer

## Metadata
- **Extension ID**: hhfkpjffbhledfpkhhcoidplcebgdgbk
- **Extension Name**: AITDK SEO Extension - Traffic/Keywords/Whois/SEO analyzer
- **Version**: 2.4.2
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

AITDK SEO Extension is a legitimate SEO analysis tool that provides keyword research, traffic analysis, and website metrics through integration with services like Ahrefs and Google Trends. The extension loads an external iframe from `https://extension.aitdk.com/` and establishes bidirectional communication using the postMessage RPC pattern. While this is intentional functionality for the extension's SEO analysis features, it creates privacy concerns due to sharing complete page HTML/DOM content with the external service.

The extension implements two primary privacy-relevant behaviors: (1) postMessage communication without proper origin validation in the receiving listener, and (2) exposing full page HTML and extensive DOM metadata (links, images, headings, text content) through RPC methods accessible to the iframe. These behaviors are aligned with the extension's stated SEO analysis purpose, but represent a medium privacy risk to users who may not expect their browsing data to be shared with an external service.

## Vulnerability Details

### 1. MEDIUM: PostMessage Communication Without Origin Validation
**Severity**: MEDIUM
**Files**: sidebar.524fe15c.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension uses the `@mixer/postmessage-rpc` library to establish communication with an iframe loaded from `extension.aitdk.com`. The default message listener from the library accepts messages without enforcing strict origin validation on the receiving end (lines 7669-7673 in sidebar.524fe15c.js).

**Evidence**:
```javascript
// sidebar.524fe15c.js lines 7669-7673
n.defaultRecievable = {
  readMessages: function(e) {
    return window.addEventListener("message", e),
      function() {
        return window.removeEventListener("message", e)
      }
  }
}
```

While the RPC library checks origin when configured (line 7380), the postMessage receiver does not enforce origin validation at the listener level, potentially allowing message injection if an attacker can embed content.

**Verdict**: MEDIUM severity. While the RPC library has origin checking capabilities, the default listener lacks strict enforcement. This could allow message injection in certain scenarios where an attacker controls embedded content on the same page.

### 2. MEDIUM: Extensive Page Data Exfiltration to External Service
**Severity**: MEDIUM
**Files**: sidebar.524fe15c.js (lines 7290, 8100-8174)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension exposes two RPC methods (`getPageHtml` and `getPageData`) that transmit comprehensive page content to the iframe at `extension.aitdk.com`. This includes the complete HTML source, all links, images, headings, meta tags, structured data, and body text from every page the user visits.

**Evidence**:
```javascript
// Lines 7290 - RPC method exposure
c = n, n.expose("getPageHtml", async () => await (0, i.getPageHtml)()),
n.expose("getPageData", async () => await (0, i.getPageData)()),

// Lines 8090-8098 - getPageHtml implementation
async function s() {
  let e = chrome?.runtime?.getManifest() || { version: "0.0.0" },
    t = e.version,
    n = (await chrome.storage.sync.get(["defaultReportId"]))?.defaultReportId,
    r = (await chrome.storage.sync.get(["displayMode"]))?.displayMode,
    o = location.href,
    l = document.documentElement.outerHTML;  // Full page HTML
  return { version: t, defaultReportId: n, displayMode: r, url: o, html: l }
}

// Lines 8100-8174 - getPageData implementation extracts:
// - All links with href/text/title/follow status
// - All images with src/alt/title
// - All headings (h1-h6) with text content
// - All meta tags
// - All alternate links (hreflang)
// - All external scripts
// - Structured data (JSON-LD)
// - Complete body text content
```

**Verdict**: MEDIUM severity. This behavior is consistent with an SEO analysis tool's legitimate need to analyze page structure and content. However, it represents a significant privacy exposure as all browsing activity on pages where the extension is active gets shared with `extension.aitdk.com`. Users should be clearly informed of this data sharing in the privacy policy.

## False Positives Analysis

### Static Analyzer Findings
The ext-analyzer flagged several flows as exfiltration:
- `chrome.tabs.query → *.src(reactjs.org)` - This is benign React framework usage
- `document.querySelectorAll → fetch` - These are legitimate SEO data collection for the tool's purpose
- `chrome.storage.sync.get → fetch` - User preferences being synced with the service

These patterns are expected for an SEO analysis extension and align with the extension's disclosed purpose.

### Webpack Bundling
The code is bundled with Parcel (not Webpack), which creates modular function wrapping. This is standard build tooling, not obfuscation, though the static analyzer flagged it as "obfuscated."

### Context Menu Integration
The extension creates legitimate context menu entries for SEO tools (Google Trends, Ahrefs keyword checker, etc.) which is appropriate functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| extension.aitdk.com | SEO analysis iframe | Full page HTML, DOM structure, all links/images/text, user settings | MEDIUM - Extensive data sharing for stated purpose |
| aitdk.com | Installation tracking | UTM tracking on install | LOW - Standard analytics |
| trends.google.com | Context menu | Selected text for trends search | LOW - User-initiated |
| ahrefs.com | Context menu | Selected text/domain for SEO queries | LOW - User-initiated |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: AITDK SEO Extension is a legitimate SEO analysis tool that functions as advertised. The extension's architecture of loading an external iframe and sharing page data is appropriate for its SEO analysis purpose. However, it presents medium privacy risk due to:

1. **Privacy Exposure**: Complete page HTML and DOM metadata is shared with `extension.aitdk.com` on all pages where users activate the sidebar
2. **PostMessage Security**: Lack of strict origin validation in the message listener creates potential for message injection
3. **Scope**: Content scripts run on `<all_urls>` giving broad access to user browsing

The extension is not malicious and appears to operate within its stated purpose. The risk is primarily privacy-related rather than security-based. Users should be aware that activating this extension shares comprehensive page data with the AITDK service for SEO analysis.

**Recommendations**:
- Implement strict origin validation in postMessage receivers
- Clearly disclose data sharing practices in privacy policy
- Consider limiting data collection to only when the sidebar is actively opened by the user
- Add user controls for data sharing preferences
