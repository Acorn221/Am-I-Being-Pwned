# Vulnerability Assessment Report

## Extension Metadata
- **Name**: Activate Enable Right Click & Copy
- **Extension ID**: pkoccklolohdacbfooifnpebakpbeipc
- **Version**: 6.5.1
- **User Count**: ~60,000
- **Manifest Version**: 3

## Executive Summary

This extension provides three primary features: enabling copy/paste on websites that block it, an "absolute mode" to bypass all restrictions, and OCR (Optical Character Recognition) for extracting text from images. The extension uses Tesseract.js for OCR functionality and includes promotional content in its UI.

**Overall Risk Level: MEDIUM**

The extension has broad permissions and promotional monetization behavior that raises concerns, but no evidence of overtly malicious functionality was found. The main concerns are around promotional redirects on install/uninstall, excessive permissions, and the use of third-party promotional links in the popup interface.

## Vulnerability Details

### 1. Install/Uninstall Redirect Tracking
**Severity**: MEDIUM
**Files**: `background.js` (lines 922-945)
**Description**: The extension opens promotional websites on install and sets an uninstall URL to track user behavior.

**Code Evidence**:
```javascript
const installPage = 'https://prepphint.com/';
const uninstallPage = 'https://melodicvista.com/';

chrome.runtime.onInstalled.addListener((details) => {
  indexedDB.databases().then(databases => {
    for (const { name } of databases) {
      indexedDB.deleteDatabase(name);
    }
  });

  if (details.reason === 'install') {
    chrome.tabs.create({ url: installPage });
  }
});

chrome.runtime.setUninstallURL(uninstallPage, () => {
  if (chrome.runtime.lastError) {
    console.error("Failed to set uninstall URL:", chrome.runtime.lastError.message);
  }
});
```

**Verdict**: Monetization/tracking behavior. Opens `prepphint.com` on install and `melodicvista.com` on uninstall. This is common in free extensions for affiliate tracking but creates user friction and privacy concerns.

---

### 2. Promotional Content and External Links
**Severity**: LOW
**Files**: `popup.html` (lines 17-41), `popup.js` (lines 400-408, 517-652)
**Description**: The popup contains a promotional slideshow that links to other Chrome extensions and external promotional websites.

**Code Evidence from popup.html**:
```html
<a href="https://chromewebstore.google.com/detail/volume-master-increase-vo/ofhcpjnedbemoknknjpdcbhfielakpbk" target="_blank" class="promo-slide active" data-slide="0">
    <img src="/promo-ads/promo1.png" alt="Promo 1" />
</a>
<a href="https://chromewebstore.google.com/detail/biubiu-vpn-the-website-un/fdgonnhnndhigfoljgpogifhejjighha" target="_blank" class="promo-slide" data-slide="1">
    <img src="/promo-ads/promo2.png" alt="Promo 2" />
</a>
```

**Code Evidence from popup.js**:
```javascript
const earningsElement = document.getElementById("earnings");
if (earningsElement) {
    earningsElement.addEventListener('click', () => {
        chrome.tabs.create({ url: "https://prepphint.com/" });
    });
}
```

**Verdict**: Standard monetization through cross-promotion. Promotes other extensions ("Volume Master", "BiuBiu VPN", "Chrome Audio Capture") and the developer's website. Not malicious but adds UI clutter and potential tracking.

---

### 3. Broad Host Permissions
**Severity**: MEDIUM
**Files**: `manifest.json` (lines 36-40)
**Description**: Extension requests `<all_urls>` permission, granting access to all websites.

**Code Evidence**:
```json
"host_permissions": [
    "https://tessdata.projectnaptha.com/*.gz",
    "https://github.com/naptha/tessdata/blob/gh-pages/*.gz?raw=true",
    "<all_urls>"
]
```

**Verdict**: While `<all_urls>` is necessary for the extension's core functionality (enabling copy/paste on any website), it grants very broad access. The extension does legitimately inject content scripts into all pages for its copy-enabling features. The Tesseract data URLs are for OCR language data downloads, which is expected.

---

### 4. Extensive Permissions List
**Severity**: MEDIUM
**Files**: `manifest.json` (lines 24-33)
**Description**: Extension requests multiple sensitive permissions.

**Code Evidence**:
```json
"permissions": [
    "tabs",
    "activeTab",
    "storage",
    "scripting",
    "unlimitedStorage",
    "notifications",
    "clipboardWrite",
    "offscreen"
]
```

**Analysis by permission**:
- `tabs`, `activeTab`: Required to inject scripts into active tabs
- `storage`, `unlimitedStorage`: Stores user settings and OCR language data. `unlimitedStorage` allows storing large Tesseract trained data files
- `scripting`: Required to inject content scripts dynamically
- `notifications`: Used for user feedback on mode toggles
- `clipboardWrite`: Required for OCR text-to-clipboard functionality
- `offscreen`: Used for clipboard operations in MV3 service worker context

**Verdict**: All permissions appear to have legitimate use cases for the stated functionality. The `unlimitedStorage` permission is justified for storing OCR language training data, which can be several MB per language.

---

### 5. DOM Manipulation and Event Interception
**Severity**: LOW
**Files**: `enable.js`, `enableA.js`
**Description**: Content scripts modify page CSS and intercept events to enable copy/paste functionality.

**Code Evidence from enable.js**:
```javascript
const css = document.createElement("style");
css.setAttribute('data-extension-injected', 'enable-copy');
css.type = 'text/css';
css.innerText = `* {
    -webkit-user-select: text !important;
    -moz-user-select: text !important;
    -ms-user-select: text !important;
     user-select: text !important;
}`;

const protectedEvents = ['copy', 'cut', 'paste', 'select', 'selectstart'];
protectedEvents.forEach(eventType => {
    const handler = function(e) {
        e.stopPropagation();
    };
    trackedAddEventListener(document, eventType, handler, true);
});
```

**Verdict**: This is the core legitimate functionality of the extension. It overrides CSS and JavaScript that websites use to prevent text selection and copying. The event interception is done to prevent websites from blocking these actions. The extension includes cleanup mechanisms to remove these modifications when disabled.

---

### 6. Third-Party Library Usage
**Severity**: LOW
**Files**: `data/engine/tesseract/tesseract.min.js`, `worker.min.js`
**Description**: Extension uses Tesseract.js for OCR functionality.

**Verdict**: Tesseract.js is a legitimate open-source OCR library. The files contain expected minified code with `eval`, `Function()`, and other patterns typical of legitimate OCR/WASM libraries. No evidence of malicious modifications detected in the library code patterns.

---

### 7. Web Accessible Resources
**Severity**: LOW
**Files**: `manifest.json` (lines 44-55)
**Description**: Extension exposes certain resources to all web pages.

**Code Evidence**:
```json
"web_accessible_resources": [
    {
        "resources": [
            "/data/engine/index.html",
            "/data/inject/sandbox.html",
            "/data/inject/clipboard.html"
        ],
        "matches": [
            "<all_urls>"
        ]
    }
]
```

**Verdict**: These resources are required for the OCR functionality. The sandbox.html is used for iframe-based OCR UI, and clipboard.html is for clipboard operations in MV3. The resources are appropriately scoped for the extension's functionality.

---

## False Positives

| Pattern | Location | Reason It's Safe |
|---------|----------|------------------|
| `eval` in tesseract.min.js | Third-party library | Part of legitimate Tesseract.js OCR library |
| `Function()` constructor | tesseract-core-simd-lstm.js | WASM initialization for OCR, standard pattern |
| `fromCharCode` usage | Tesseract library files | Text encoding/decoding for OCR processing |
| Event listener capture mode | enable.js, enableA.js | Required to override website event blocking |
| CSS `!important` injection | enable.js (line 48-52) | Core feature to force text selection enabling |
| `stopPropagation()` on events | enableA.js (line 59) | Prevents sites from blocking copy events |

---

## API Endpoints and External Connections

| Domain | Purpose | Evidence | Risk Level |
|--------|---------|----------|------------|
| `prepphint.com` | Install/promotional redirect | background.js line 922, popup.js line 406 | LOW - Promotional |
| `melodicvista.com` | Uninstall tracking | background.js line 923 | LOW - Tracking |
| `tessdata.projectnaptha.com` | OCR language training data | manifest.json line 37 | CLEAN - Legitimate OCR data |
| `github.com/naptha/tessdata` | OCR language training data | manifest.json line 38 | CLEAN - Legitimate OCR data |
| `chromewebstore.google.com` | Cross-promotion links | popup.html lines 20-30 | CLEAN - CWS links |

**No outbound telemetry or analytics calls detected in the code.**

---

## Data Flow Summary

### Data Collection
- **User Settings**: Stores website list where copy/paste is enabled (local storage only)
- **OCR Preferences**: Language selection, accuracy settings (local storage only)
- **No PII Collection**: No evidence of personal data collection or transmission

### Data Storage
- `chrome.storage.local`: User preferences and website whitelist
- IndexedDB/Caches: Tesseract trained data (deleted on install, used for offline OCR)
- No remote storage or cloud sync detected

### Data Transmission
- **OCR Data Downloads**: Downloads Tesseract language files from `tessdata.projectnaptha.com` (HTTPS)
- **No Analytics**: No detected analytics, telemetry, or user behavior tracking APIs
- **Promotional Redirects**: Opens URLs on install/uninstall (tracking concern but no data sent)

### Security Observations
- All OCR processing happens locally in the browser
- No screenshot or page content is transmitted to external servers
- Clipboard operations use standard Chrome APIs
- Memory leak prevention mechanisms implemented throughout

---

## Code Quality Notes

### Positive Observations
- Comprehensive cleanup mechanisms to prevent memory leaks
- Proper error handling throughout
- Context invalidation detection to handle service worker lifecycle
- Tracked timeouts/intervals/event listeners with cleanup
- MV3 best practices (service worker, offscreen documents)

### Areas of Concern
- Aggressive promotional behavior (install/uninstall redirects)
- Promotional slideshow in popup takes up significant UI space
- Very broad permissions for relatively simple functionality
- No Content Security Policy restrictions on third-party content

---

## Recommendations

### For Users
1. **Acceptable for intended use**: If you need to copy text from websites that block it, this extension works as advertised
2. **Be aware**: Extension will open promotional tabs on install and uninstall
3. **Privacy consideration**: No evidence of data exfiltration, but promotional redirects enable basic user tracking
4. **Alternative options**: Consider if you need all three features or just the copy/paste functionality

### For Developers
1. Make promotional content opt-in rather than default
2. Consider reducing permission scope where possible
3. Add clearer privacy policy links in the extension
4. Make the slideshow dismissible or smaller
5. Consider removing uninstall URL tracking

---

## Overall Risk Assessment: MEDIUM

### Risk Factors
- ⚠️ Monetization through install/uninstall redirects
- ⚠️ Broad permissions (`<all_urls>`)
- ⚠️ Promotional content in UI
- ✓ No evidence of malicious code
- ✓ No data exfiltration detected
- ✓ Local-only OCR processing
- ✓ No analytics/telemetry detected
- ✓ Good code quality with cleanup mechanisms

### Verdict
This is a functional extension with legitimate utility but aggressive monetization practices. The broad permissions are justified for the functionality, but the promotional redirects and cross-promotion UI elements reduce trust. No malicious behavior detected, but users should be aware of the promotional aspects. Suitable for use with awareness of the monetization model.

**Risk Level: MEDIUM** - Functional with monetization concerns, but not malicious.
