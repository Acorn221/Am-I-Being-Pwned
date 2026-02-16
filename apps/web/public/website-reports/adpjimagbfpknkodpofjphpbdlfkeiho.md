# Vulnerability Report: Zoom to Fill - Ultrawide Video

## Metadata
- **Extension ID**: adpjimagbfpknkodpofjphpbdlfkeiho
- **Extension Name**: Zoom to Fill - Ultrawide Video
- **Version**: 2.1.8
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Zoom to Fill is a video aspect ratio adjustment extension that removes black bars on streaming platforms by zooming videos to fill ultrawide monitors. The extension uses content scripts injected on all URLs to manipulate video elements and add custom UI controls. Static analysis identified one minor vulnerability: message data flowing to innerHTML without origin validation. However, upon code review, this is a false positive as the innerHTML assignments only use hardcoded SVG strings for UI buttons, not external message data. The extension opens new tabs to the developer's website on install/update, which is standard behavior. Overall, the extension poses minimal security risk and functions as advertised.

## Vulnerability Details

### 1. LOW: Message Handling with innerHTML Injection (False Positive)

**Severity**: LOW
**Files**: src/content/index.js, src/popup/js/popup.js
**CWE**: CWE-79 (Cross-Site Scripting)
**Description**: The static analyzer flagged a potential data flow from `chrome.runtime.onMessage` to `innerHTML` assignments in the content script. This could theoretically allow malicious messages to inject arbitrary HTML.

**Evidence**:
```javascript
// ext-analyzer flagged:
// message data → *.innerHTML from: src/popup/js/popup.js ⇒ src/content/index.js

// Content script message handler at line 6315:
chrome.runtime.sendMessage(ot, h((t => {
  void 0;
  const n = q();
  if (t && !n) {
    i();
    D();
    P();
    rt()
  }
})));

// innerHTML assignments at lines 6138, 6156, 6176, 6208, 6226:
n.innerHTML = `<div class="focus-hack-div" tabindex="-1">
    <svg style="outline: none;" ... ></svg></div>`;
```

**Verdict**: FALSE POSITIVE. All innerHTML assignments use hardcoded SVG strings for UI buttons, not message data. The message handler only triggers UI initialization functions and doesn't pass message content to innerHTML. The extension uses `chrome.tabs.sendMessage` to communicate zoom commands (strings like "+", "-", "16:9") between popup and content script, but these are pattern-matched against expected values and never used in innerHTML.

### 2. LOW: No Origin Validation on Message Handler

**Severity**: LOW
**Files**: src/sw/index.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Description**: The service worker message handler doesn't validate message sender origin, though it does implement an obfuscated ID check.

**Evidence**:
```javascript
// Service worker at line 57:
chrome.runtime.onMessage.addListener(((e, o, t) => {
  let s = "";
  const n = "dgsmlpdjeisnqnrgsrimsksegoinhlkr";
  for (let i of n) {
    const e = i === i.toUpperCase();
    i = i.toLowerCase();
    let o = r.indexOf(i);
    if (-1 === o) {
      s += i;
      continue
    }
    o = (o + 23) % 26;
    s += e ? r[o].toUpperCase() : r[o]
  }
  const c = e === s;
  return t(c)
}));
```

**Verdict**: MINOR ISSUE. The handler performs a ROT-23 Caesar cipher check (decoded: "adpjimagbfpknkodpofjphpbdlfkeiho" - the extension's own ID) but doesn't validate sender origin. However, the response is only a boolean indicating ID match, so impact is negligible. This appears to be an anti-tampering check.

## False Positives Analysis

1. **innerHTML injection**: All innerHTML assignments use static SVG templates for UI buttons. No user-controlled or message-derived content is injected.

2. **<all_urls> permission**: Required for the extension's legitimate purpose of detecting and zooming videos on all streaming platforms (Netflix, YouTube, Amazon Prime, Disney+, HBO Max, etc.).

3. **Obfuscated code**: The content script includes lodash (62KB minified library). The ROT-23 cipher in the service worker is trivial obfuscation for an extension ID check, not malicious.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://zoomtofill.com/version/2 | Welcome page on install | None | Low |
| https://zoomtofill.com/version/2/update | Update notification page | None | Low |
| https://zoomtofill.com/farewell | Uninstall survey | None | Low |

All endpoints are on the developer's domain. No user data is transmitted. The extension opens these URLs in new tabs on install/update/uninstall events, which is standard practice.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: The extension performs its stated function (video aspect ratio adjustment) without collecting or transmitting user data. The flagged innerHTML vulnerability is a false positive - all HTML injection uses hardcoded templates. The message handler lacks origin validation but has minimal security impact. The extension's use of `<all_urls>` is justified for its video manipulation functionality. The only external network access is opening the developer's website on install/update, which contains no tracking or data collection. The code is primarily webpack-bundled with lodash, not truly obfuscated.

**Recommendation**: CLEAN with minor code quality issues. Users can safely install this extension for its intended video zoom functionality.
