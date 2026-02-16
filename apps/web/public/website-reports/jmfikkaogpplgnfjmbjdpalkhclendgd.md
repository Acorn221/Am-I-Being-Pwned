# Vulnerability Report: Save to Facebook

## Metadata
- **Extension ID**: jmfikkaogpplgnfjmbjdpalkhclendgd
- **Extension Name**: Save to Facebook
- **Version**: 2.4
- **Users**: ~800,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

"Save to Facebook" is an official Facebook extension that allows users to save web content to their Facebook account. While the extension appears to be legitimate and published by Facebook, it employs a highly concerning architecture pattern: it dynamically loads remote JavaScript from Facebook servers on every launch without integrity checks. This means Facebook has the ability to execute arbitrary code with extension privileges (activeTab, cookie access to facebook.com) at any time by changing the served JavaScript. Additionally, the extension uses `'unsafe-eval'` in its CSP and reloads itself every 24 hours to fetch the "latest" code, eliminating any review or approval process for code changes after the initial Chrome Web Store submission.

While there's no evidence of current malicious behavior and this is likely an intentional architectural decision by Facebook to enable rapid updates, this pattern fundamentally undermines the Chrome Web Store security model and represents a significant trust requirement from users.

## Vulnerability Details

### 1. HIGH: Remote Code Execution via Dynamic Script Loading
**Severity**: HIGH
**Files**: background.js (lines 94-109), popup.js (lines 19-35)
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension dynamically loads JavaScript from `https://www.facebook.com/saved/extension/rsrc/js/` on every launch without any integrity verification (no Subresource Integrity hashes, no signature checks). This JavaScript is then executed with full extension privileges.

**Evidence**:
```javascript
// background.js lines 94-109
function ensureJSLoaded() {
  if (_jsState == NOT_LOADED) {
    _jsState = LOADING;

    // TODO (#11999424): cache key in browser to take advantage of caching JS
    var randomKey = guid();
    requestScript(
      getFullUrl('/saved/extension/rsrc/js/?key=' + randomKey),
      function(success) {
        _jsState = (success && SavedExtension !== undefined)
          ? LOADED
          : NOT_LOADED;
        onLoadStateUpdated();
      });
  }
}
```

The `requestScript` function creates a script element with `crossOrigin = 'anonymous'` but no integrity checks:
```javascript
// background.js lines 12-29
function requestScript(source, callback, doc) {
  doc = doc ? doc : document;

  var script  = doc.createElement('script');
  script.src  = source;
  script.type = 'text/javascript';
  script.async = true;
  script.crossOrigin = 'anonymous';
  script.onload = function() {
    callback && callback(true);
  };

  script.onerror = function() {
    callback && callback(false);
  };

  doc.getElementsByTagName('head')[0].appendChild(script);
}
```

**Verdict**: This allows Facebook to modify extension behavior post-publication without Chrome Web Store review. While Facebook is a reputable company, this pattern means:
1. Any compromise of Facebook's servers could lead to malicious code execution in users' browsers
2. Facebook employees with access to these endpoints could push arbitrary code
3. There is no transparency or audit trail for what code actually runs
4. Users cannot verify what the extension does by inspecting the Chrome Web Store listing

### 2. HIGH: Forced 24-Hour Reload Cycle
**Severity**: HIGH
**Files**: background.js (line 132)
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension automatically reloads itself every 24 hours to fetch "fresh" code from Facebook servers, ensuring any code changes are deployed to all users within a day.

**Evidence**:
```javascript
// background.js line 132
if (getIsLoaded()) {
   SavedExtension.initBackground();

   // Configure extension to re-load JS every 24 hours, fetch latest JS
   window.setTimeout(chrome.runtime.reload, 24 * 60 * 60000);
}
```

**Verdict**: This creates a continuous update mechanism completely outside the Chrome Web Store review process. Combined with the remote code loading, this means Facebook can deploy breaking changes, new features, or potentially malicious code to all 800,000 users within 24 hours without any external oversight.

### 3. MEDIUM: Weak Content Security Policy
**Severity**: MEDIUM
**Files**: manifest.json (line 30)
**CWE**: CWE-1032 (Weakened Security for Remote Code Execution)
**Description**: The CSP includes `'unsafe-eval'` which allows the use of `eval()` and related dangerous JavaScript features.

**Evidence**:
```json
"content_security_policy": "script-src 'self' 'unsafe-eval' chrome-extension-resource: https://*.facebook.com https://*.fbcdn.net; object-src 'self' chrome-extension-resource: https://*.facebook.com https://*.fbcdn.net;"
```

**Verdict**: While `'unsafe-eval'` is necessary for some legitimate use cases, it increases the attack surface if the remotely loaded code is compromised or if there are XSS vulnerabilities in the loaded content. The CSP does properly restrict script sources to self and Facebook domains, which provides some mitigation.

## False Positives Analysis

**Random GUID in URL**: The code generates a random GUID and appends it as a cache-busting parameter (`?key=[guid]`). This is a legitimate technique to bypass browser caching and ensure fresh code is loaded. However, the comment `// TODO (#11999424): cache key in browser to take advantage of caching JS` suggests this may be an incomplete implementation or temporary workaround.

**Exponential Backoff**: The retry logic with exponential backoff (lines 134-136) is a standard network resilience pattern and not suspicious.

**Cookie Permission**: The `cookies` permission combined with `https://*.facebook.com/*` host permission allows reading/writing Facebook cookies. For a Facebook-branded extension that integrates with Facebook's save feature, this is expected and necessary functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://www.facebook.com/saved/extension/rsrc/js/` | Remote JavaScript loading | Random cache-busting key | **HIGH** - No integrity checks |
| `https://www.facebook.com/saved/extension/rsrc/css/` | Remote CSS loading | None | **LOW** - CSS has limited attack surface |
| `https://*.facebook.com/*` | Facebook API integration | Unknown (handled by remote JS) | **MEDIUM** - Depends on remote code behavior |
| `https://*.fbcdn.net` | Facebook CDN resources | None | **LOW** - Content delivery |

The remote JavaScript is loaded from `www.facebook.com` (configurable via `options.defaults.domain`) and likely handles all the actual save functionality, Facebook API calls, and user data transmission. Since this code is not bundled with the extension, its behavior cannot be analyzed statically.

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

While this extension appears to be officially published by Facebook (based on the extension key, name, and functionality), it employs an architecture that fundamentally bypasses Chrome Web Store security controls. The combination of:

1. **Remote code execution** - Arbitrary JavaScript loaded from Facebook servers without integrity checks
2. **Privileged access** - Extension has activeTab and cookie permissions
3. **Forced updates** - 24-hour reload cycle ensures rapid deployment of code changes
4. **No transparency** - Users and reviewers cannot audit the actual runtime behavior

This means users must place complete trust in Facebook's operational security, developer practices, and intentions. Any compromise of Facebook's infrastructure, malicious insider, or policy change could result in:

- Cookie theft and session hijacking for Facebook accounts
- Arbitrary code execution on any website the user visits (via activeTab)
- Silent surveillance of browsing activity
- Injection of malicious content into web pages

**Mitigating Factors**:
- Facebook is a well-established company with security teams and incident response capabilities
- The extension has 800,000 users and 4.0 rating, suggesting it functions as advertised
- Permissions are limited to activeTab and Facebook domains (not `<all_urls>`)
- The pattern may be intentional to enable rapid bug fixes and feature updates

**Recommendation**: This extension should be flagged as HIGH risk due to its architecture, not because of observed malicious behavior. Users should be aware that they are trusting Facebook with the ability to execute arbitrary code in their browser context. Organizations with strict security policies should consider blocking this extension or requiring exceptions.
