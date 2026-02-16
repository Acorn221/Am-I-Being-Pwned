# Vulnerability Report: Subtitles for Language Learning (Prime Video)

## Metadata
- **Extension ID**: hlofmmmlhfelbfhcpapoackkglljfcnb
- **Extension Name**: Subtitles for Language Learning (Prime Video)
- **Version**: 2.0.18
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension adds foreign language subtitle display and dictionary functionality to Amazon Prime Video. It intercepts XHR and fetch API calls to capture Amazon Prime Video playback resources and integrates with external subtitle services (OpenSubtitles.org and the developer's own api2.subtitlesfll.com). The static analyzer flagged 3 exfiltration flows involving chrome.storage.sync data being sent to external endpoints, but manual review reveals these are legitimate features. The extension hooks native browser APIs (XMLHttpRequest and fetch) to intercept Prime Video API responses, which is necessary for its functionality but represents an elevated attack surface. Overall, the extension appears to be a legitimate language learning tool with no hidden malicious behavior.

The extension stores OpenSubtitles.org user credentials in encrypted form in chrome.storage.sync, integrates with Google Translate API and the developer's own subtitle service, and uses postMessage for cross-script communication. While the XHR/fetch hooking technique is aggressive, it's limited to specific Amazon Prime Video endpoints and doesn't appear to capture sensitive user data beyond what's necessary for subtitle retrieval.

## Vulnerability Details

### 1. MEDIUM: XHR and Fetch API Hooking
**Severity**: MEDIUM
**Files**: js/scripts/xml-http-request.js
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)
**Description**: The extension overwrites the native `window.XMLHttpRequest.prototype.open` and `window.fetch` methods to intercept specific Amazon Prime Video API calls (`/GetPlaybackResources`, `/GetVodPlaybackResources`, `/getDetailPage`). This allows the extension to monitor and capture API responses from Amazon's backend.

**Evidence**:
```javascript
const h = window.XMLHttpRequest.prototype.open;
window.XMLHttpRequest.prototype.open = function(b, a, c, e, f) {
  a && (0 <= a.indexOf("/GetPlaybackResources") ? this.addEventListener("loadend", d => {
    window.postMessage({
      type: "/GetPlaybackResources",
      url: a,
      body: d.srcElement.response
    }, window.origin)
  }) : 0 <= a.indexOf("/GetVodPlaybackResources") && this.addEventListener("loadend", d => {
    window.postMessage({
      type: "/GetVodPlaybackResources",
      url: a,
      body: d.srcElement.response
    }, window.origin)
  }));
  h.apply(this, [].slice.call(arguments))
};

const g = window.fetch;
window.fetch = (b, a) => b && 0 <= b.indexOf("/getDetailPage") ? g(b, a).then(c => new Promise(e => {
  c.clone().json().then(f => {
    e(c);
    window.postMessage({
      type: "/getDetailPage",
      url: b,
      data: f
    }, window.origin)
  })
})) : g(b, a)
```

**Verdict**: While this technique is aggressive and could be abused, the implementation is narrowly scoped to specific Amazon Prime Video endpoints needed for subtitle functionality. The intercepted data is posted to `window.origin` (same-origin), not exfiltrated externally. This is a necessary evil for the extension's core functionality but increases the attack surface if the extension were compromised. Rated MEDIUM due to the powerful technique employed, though no actual misuse is detected.

## False Positives Analysis

The static analyzer flagged several flows as potential data exfiltration:

1. **chrome.storage.sync.get → fetch(clients5.google.com)** - This is the Google Translate API integration for dictionary lookups. The extension fetches translations from Google's public API endpoint, which is a disclosed and expected feature for a language learning tool.

2. **chrome.storage.sync.get → fetch** - This relates to fetching subtitle data from api2.subtitlesfll.com (the developer's own backend) and opensubtitles.org. The storage access is for retrieving user settings and preferences, not exfiltrating sensitive data.

3. **document.querySelectorAll → fetch** - This flow is part of the subtitle display and dictionary lookup functionality. The extension searches the DOM for subtitle text to provide translations.

4. **Message data → *.innerHTML / *.src / fetch** - These flows are part of the extension's message passing architecture between content scripts and the service worker. The extension uses postMessage to communicate intercepted Amazon API responses, which is necessary for coordinating subtitle retrieval.

All flagged exfiltration flows are legitimate features disclosed in the extension's description ("Add foreign language subtitle display and dictionary function on Amazon Prime Video").

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api2.subtitlesfll.com | Developer's subtitle service API | Video catalog IDs, subtitle info, dictionary lookups | Low - disclosed functionality |
| clients5.google.com | Google Translate API | Words/phrases for translation | Low - standard API usage |
| subtitlesfll.com | General subtitle service | Video information for subtitle matching | Low - disclosed functionality |
| opensubtitles.org | Third-party subtitle database | Video titles, search queries, user credentials (encrypted) | Low - legitimate integration with known service |

All external endpoints are relevant to the extension's stated purpose of providing subtitles and translation for language learning. User credentials for OpenSubtitles.org are stored in encrypted form using the Web Crypto API before being saved to chrome.storage.sync.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This extension employs aggressive techniques (XHR/fetch hooking) but uses them narrowly for legitimate subtitle functionality. The three main concerns that were investigated and cleared:

1. **XHR/Fetch Hooking** - While this is a powerful technique, it's scoped only to Amazon Prime Video API endpoints and uses same-origin postMessage for internal communication, not external exfiltration.

2. **Storage Access + Network Requests** - All flagged flows involve legitimate features: fetching translations from Google, retrieving subtitles from the developer's API and OpenSubtitles.org, and saving user preferences.

3. **Credential Storage** - OpenSubtitles.org credentials are properly encrypted using the Web Crypto API before storage, demonstrating security awareness.

The extension's permissions are appropriate for its functionality (storage for settings, host permissions for subtitle services). The code is minified but deobfuscates cleanly, showing standard webpack bundling rather than malicious obfuscation. No undisclosed data collection, no credential theft, no unauthorized API access beyond the stated Amazon Prime Video subtitle enhancement.

The MEDIUM vulnerability for API hooking prevents a CLEAN rating, but the extension poses low actual risk to users given its narrow scope and transparent behavior.
