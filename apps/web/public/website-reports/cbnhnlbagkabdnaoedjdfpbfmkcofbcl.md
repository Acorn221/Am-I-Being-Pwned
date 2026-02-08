# Vulnerability Report: Image downloader - picture and photos saver

## Metadata
- **Extension ID**: cbnhnlbagkabdnaoedjdfpbfmkcofbcl
- **Extension Name**: Image downloader - picture and photos saver
- **Version**: 1.0.6
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

The Image Downloader extension is a **CLEAN** extension that provides legitimate image downloading functionality with no evidence of malicious behavior. The extension uses appropriate permissions for its stated purpose, employs standard React/JavaScript patterns, and contains no concerning network calls, obfuscation, or data exfiltration mechanisms. The extension demonstrates good security practices including the use of declarativeNetRequest for modifying referer headers (rather than the more powerful webRequest API) and local-only data storage.

## Vulnerability Details

### 1. No Critical or High Severity Issues Found
**Severity**: N/A
**Files**: N/A
**Verdict**: CLEAN

After comprehensive analysis of all extension components, no critical or high severity vulnerabilities were identified.

### 2. Referer Header Modification (Informational)
**Severity**: LOW (Informational)
**Files**:
- `/src/extension/popup/index.js` (lines 13657-13684, 13735-13738)

**Code Context**:
```javascript
const eS = (e, t) => {
  let n = [], r = [];
  return e.forEach((o, i) => {
    const l = i + 1;
    o && o.indexOf("http") === 0 && (n[n.length] = {
      id: l,
      priority: 1,
      action: {
        type: Z3.MODIFY_HEADERS,
        requestHeaders: [{
          header: "Referer",
          operation: q3.SET,
          value: t
        }]
      },
      condition: {
        urlFilter: o,
        resourceTypes: [J3.IMAGE]
      }
    }, r[r.length] = l)
  }), {
    fixRefererRules: n,
    deleteOldRefererRules: r
  }
}

await chrome.declarativeNetRequest.updateSessionRules({
  addRules: f,
  removeRuleIds: h
});
```

**Analysis**:
The extension modifies HTTP Referer headers for image requests to set them to the page origin. This is a legitimate technique to bypass referer-based hotlink protection on some websites. The implementation:
- Uses `declarativeNetRequest` (session rules only, not persisted)
- Only modifies headers for IMAGE resources
- Sets referer to the current page origin (not arbitrary values)
- Limited to images discovered on the current page

**Verdict**: BENIGN - This is standard functionality for image downloading extensions to bypass hotlink protection. The implementation is properly scoped and uses the modern MV3 API appropriately.

### 3. Content Script Injection
**Severity**: LOW (Informational)
**Files**:
- `/src/extension/popup/index.js` (lines 13712-13722)
- `/src/extension/imageHelper/index.js` (entire file)

**Code Context**:
```javascript
chrome.tabs.query({
  active: !0,
  currentWindow: !0
}, function(y) {
  chrome.scripting.executeScript({
    target: {
      tabId: y[0].id ?? 0,
      allFrames: n.isSearchInAllFrame
    },
    files: ["src/extension/imageHelper/index.js"]
  }, S)
})
```

**Analysis**:
The extension injects a content script (`imageHelper/index.js`) to scan the page for images. The injected script:
- Collects images from `<img>` tags, srcset attributes, background-image CSS, input[type=image], and anchor links
- Queries shadow DOM for images
- Extracts image URLs from page HTML using regex
- Returns data structure with: `{images: [], title: document.title, isTop: boolean, origin: window.location.origin}`
- Does NOT access sensitive data (passwords, cookies, form data)
- Does NOT modify page content
- Does NOT send data to external servers

**Verdict**: BENIGN - Legitimate image enumeration functionality required for the extension's stated purpose.

### 4. Broad Host Permissions
**Severity**: LOW (Informational)
**Files**:
- `/manifest.json` (lines 29-32)

**Code Context**:
```json
"host_permissions": [
  "http://*/*",
  "https://*/*",
  "<all_urls>"
]
```

**Analysis**:
The extension requests access to all URLs. This is necessary for the extension's functionality (downloading images from any website). However, the actual code:
- Only injects content scripts when user clicks the extension popup
- Does not automatically execute on page load
- Does not send data to external servers
- Only accesses image resources

**Verdict**: JUSTIFIED - Broad permissions are required for the stated functionality and are not abused.

## False Positive Analysis

| Pattern | File | Context | Reason for False Positive |
|---------|------|---------|---------------------------|
| `innerHTML` | popup/index.js (multiple) | React SVG rendering, HTML namespace handling | Standard React DOM manipulation, not user-controlled content |
| `postMessage` | popup/index.js (line 606) | MessageChannel API for React scheduler | Internal React scheduler, not cross-origin messaging |
| `Reflect.construct` | popup/index.js (line 886) | React error boundary stack traces | Standard React development pattern |
| `document.createElement` + src assignment | popup/index.js (line 13742) | Image dimension detection | Legitimate technique to measure image dimensions |
| Chrome Web Store URL | popup/index.js (line 13479) | Rating prompt | Links to extension's own store page for reviews |

## API Endpoints and External Connections

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| None | N/A | N/A | N/A |

**Analysis**: The extension makes NO external network requests. All functionality is local.

## Data Flow Summary

### Data Collection
- **Images**: URLs, dimensions, file types, sizes from current tab
- **Page metadata**: Page title, origin URL
- **User preferences**: Settings stored in `chrome.storage.local` (filter preferences, download location settings, UI preferences)

### Data Storage
- **Location**: `chrome.storage.local` only (local to browser)
- **Keys**: `Mt.Filter`, `Mt.Settings`, `Mt.Monitoring`
- **Persistence**: Local only, no sync to Google account

### Data Transmission
- **External servers**: NONE
- **Cross-origin**: NONE
- **Third-party services**: NONE

### Data Usage
- Images are downloaded directly using `chrome.downloads.download()` API
- Filenames are constructed from user settings (URL-based or custom folder)
- All processing happens locally in the browser

## Chrome API Usage

| API | Permission | Usage | Risk Assessment |
|-----|------------|-------|-----------------|
| `chrome.storage.local` | `storage` | Store user settings and preferences | LOW - Local only |
| `chrome.downloads` | `downloads` | Download selected images | LOW - Standard API |
| `chrome.scripting` | `scripting` | Inject image enumeration script | LOW - User-initiated only |
| `chrome.tabs` | `activeTab` | Get current tab info, open new tabs | LOW - Minimal scope |
| `chrome.runtime` | Built-in | Message passing between components | LOW - Internal only |
| `chrome.declarativeNetRequest` | `declarativeNetRequest` | Modify referer headers for images | LOW - Session rules only |
| `chrome.webRequest` | `webRequest` | Listen to response headers (background.js) | LOW - Read-only, metadata only |
| `chrome.management` | Built-in | Get own extension ID for store link | LOW - Self-reference only |

## Code Quality and Security Practices

### Positive Indicators
1. **No obfuscation**: Code is standard minified React, no malicious obfuscation
2. **No eval/Function**: No dynamic code execution
3. **No external requests**: All functionality is local
4. **Modern APIs**: Uses MV3 declarativeNetRequest instead of legacy webRequest
5. **Minimal permissions**: Uses `activeTab` instead of `tabs` permission where possible
6. **Type safety**: Uses TypeScript-compiled code (React/JSX patterns)

### Architecture
- **Frontend**: React 18.2.0 with standard build tooling (Vite)
- **Background**: Minimal service worker for webRequest monitoring
- **Content Script**: Image enumeration helper (injected on-demand)
- **Build**: Standard Vite bundler output

## Risk Assessment by Category

| Category | Risk Level | Notes |
|----------|------------|-------|
| Data Exfiltration | NONE | No external network requests |
| Credential Theft | NONE | No access to passwords/cookies |
| Keylogging | NONE | No keyboard event listeners |
| Ad Injection | NONE | No DOM manipulation for ads |
| Tracking/Analytics | NONE | No analytics SDKs present |
| Proxy Infrastructure | NONE | No proxy-related code |
| Extension Fingerprinting | NONE | No extension enumeration |
| Remote Code Execution | NONE | No eval/Function/fetch of scripts |
| Cookie Harvesting | NONE | No cookie access |
| XHR/Fetch Hooking | NONE | No prototype modification |

## Overall Risk Level: CLEAN

### Justification
This extension is a legitimate image downloading utility with no malicious characteristics:

1. **Transparent functionality**: All code aligns with stated purpose
2. **No data exfiltration**: Zero external network connections
3. **Appropriate permissions**: All requested permissions are used and necessary
4. **Standard patterns**: Uses React and standard Chrome extension APIs correctly
5. **No obfuscation**: Code is standard minified output, not intentionally obscured
6. **User-controlled**: Only activates when user clicks extension icon
7. **Local storage only**: No cloud sync or external storage

### Recommendations
- **For users**: Safe to use. The extension performs exactly as advertised.
- **For developers**: Consider adding Content Security Policy to manifest for defense-in-depth.
- **For reviewers**: No security concerns identified.

## Technical Implementation Notes

### Background Service Worker
- Monitors `chrome.webRequest.onCompleted` and `onBeforeRedirect` events
- Stores image metadata (content-type, content-length) for popup display
- Enables message passing for metadata retrieval
- Does NOT intercept or modify traffic

### Popup UI
- Large React application (~13,800 lines minified)
- Provides filtering, sorting, and batch download UI
- User preferences for download location, folder naming
- Rating prompt after specific usage milestones (non-intrusive)

### Image Enumeration
- Comprehensive image discovery (img tags, srcset, CSS backgrounds, shadow DOM)
- Regex-based URL extraction from page HTML
- Dimension and type detection
- No modification of page content

## Conclusion

**Image downloader - picture and photos saver** is a **CLEAN** extension with legitimate functionality and no security concerns. The extension demonstrates good security practices for a MV3 extension and poses no risk to users.
