# Vulnerability Report: Super PiP - Picture-in-Picture with playback controls and subtitles

## Metadata
- **Extension ID**: jjjpjmbnbdjhbkclajpagjkefefnednl
- **Extension Name**: Super PiP - Picture-in-Picture with playback controls and subtitles
- **Version**: 2.12
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Super PiP is a Picture-in-Picture video player extension that provides floating video windows with custom playback controls and subtitle support for various streaming platforms (YouTube, Netflix, Disney+, Prime Video, Twitch). The extension implements legitimate PiP functionality as advertised but includes analytics tracking that sends page view data to Google Analytics. While the core functionality is benign, the extension collects browsing data (page titles, URLs, referrers) without explicit disclosure in the manifest description. Additionally, it fetches remote configuration data for release notes from getsnip.cc.

The extension is assessed as LOW risk because the data collection appears to be for analytics purposes rather than malicious intent, and the core functionality matches the stated purpose. However, users may not be fully aware of the data being transmitted.

## Vulnerability Details

### 1. LOW: Undisclosed Analytics Data Collection

**Severity**: LOW
**Files**: background.js, common.js, google-analytics.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**:

The extension collects and transmits browsing data to Google Analytics without clear disclosure in the manifest description. The analytics implementation tracks:
- Page titles (`page_title`)
- Page URLs (`page_location`)
- Page referrers (`page_referrer`)
- Session IDs
- Client IDs (persistent UUID stored in local storage)
- Custom events and engagement metrics

**Evidence**:

```javascript
// background.js lines 29-46
async fireEvent(e, t = {}) {
  t.session_id || (t.session_id = await this.getOrCreateSessionId()),
  t.engagement_time_msec || (t.engagement_time_msec = 100);
  try {
    const s = await fetch((this.debug ? "https://www.google-analytics.com/debug/mp/collect" :
      "https://www.google-analytics.com/mp/collect") +
      "?measurement_id=G-6R0YJ1856Q&api_secret=t1n7oJRjTW-jrlXWW2XCOQ", {
      method: "POST",
      body: JSON.stringify({
        client_id: await this.getOrCreateClientId(),
        events: [{
          name: e,
          params: t
        }]
      })
    });
```

```javascript
// common.js lines 9-24
function t() {
  chrome.runtime?.id && n((() => {
    let s = {
      trim_version: "pictureinpicture",
      page_title: document.title,
      ...t
    };
    s.page_location ||= document.location.href,
    s.page_referrer ||= document.referrer,
    e.requestId && (s.request_id = e.requestId),
    chrome.runtime.sendMessage({
      action: "analyze",
      event: "page_view",
      params: s
    })
  }))
}
```

**Verdict**: While analytics tracking is common in browser extensions, the lack of clear disclosure in the manifest description means users may not be aware their browsing data is being collected. The Google Analytics API secret is hardcoded in the source, which is a minor security issue but not exploitable for privilege escalation.

### 2. LOW: Remote Configuration Fetching

**Severity**: LOW
**Files**: background.js, common.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**:

The extension fetches release note configuration from a remote server (getsnip.cc) and stores response data locally. While this doesn't appear to execute remote code, it does allow the remote server to influence extension behavior through configuration updates.

**Evidence**:

```javascript
// background.js lines 72-89
"getReleaseNoteVersion" === s.action ? async function(e) {
  e || (e = "");
  const s = await fetch("https://getsnip.cc/releasenoteversion", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      requestId: e
    })
  });
  let n = {};
  s.ok && (n = await s.json()), t({
    action: "releaseNoteVersionReceived",
    status: s.status,
    releaseNoteVersion: n
  })
}
```

```javascript
// background.js lines 90-103
"getReleaseNoteContent" === s.action && async function() {
  const e = await fetch("https://getsnip.cc/releasenotecontent", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    }
  });
  if (200 !== e.status) return;
  let s = {};
  e.ok && (s = await e.json()), t({
    action: "releaseNoteContentReceived",
    releaseNoteContent: s
  })
}
```

**Verdict**: The remote configuration mechanism appears to be limited to release notes and doesn't directly execute code. However, it does create a dependency on an external server and could potentially be used to change extension behavior if the remote endpoint were compromised. The risk is mitigated by the fact that only JSON data is fetched, not executable code.

## False Positives Analysis

1. **YouTube Ad Speedup**: The extension includes code that speeds up YouTube ads to 6.1x playback rate when detected. While this modifies video playback behavior, it's a user-beneficial feature and not malicious.

```javascript
// script.js lines 28-31
function i(e) {
  var t;
  t = e.playbackRate, Math.abs(t - 6.1) < 1e-6 ||
    (e.setAttribute("oldspeed", e.playbackRate),
     e.setAttribute("oldvolume", e.volume),
     e.playbackRate = 6.1,
     e.volume = .2)
}
```

2. **DOM Manipulation**: The extension extensively manipulates the DOM to create PiP windows with custom controls. This is expected behavior for a PiP extension and not a security concern.

3. **Cross-Origin Communication**: The extension uses various messaging mechanisms (postMessage, storage events, custom attributes) to communicate between different contexts. This is necessary for PiP functionality across different streaming platforms.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.google-analytics.com | Analytics tracking | Client ID (UUID), session ID, page title, page URL, page referrer, custom events | LOW - Standard analytics, but potentially privacy-invasive |
| getsnip.cc/releasenoteversion | Check for release note updates | Request ID | LOW - Only checking version, minimal data sent |
| getsnip.cc/releasenotecontent | Fetch release note content | None | LOW - No user data sent, receives JSON content |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

Super PiP is a legitimate Picture-in-Picture extension that provides the functionality advertised. The extension does not exhibit malicious behavior, credential theft, or undisclosed data exfiltration for nefarious purposes. However, it receives a LOW risk rating (rather than CLEAN) for the following reasons:

1. **Privacy Concerns**: The extension collects browsing data (page titles, URLs, referrers) and sends it to Google Analytics without explicit disclosure in the manifest description. Users may not be aware of this data collection.

2. **Broad Permissions**: The `<all_urls>` host permission is necessary for the extension's stated purpose (working on all video sites), but it does grant broad access to user browsing activity.

3. **Remote Configuration**: The extension fetches configuration data from an external server, creating a dependency and potential attack vector if the remote server were compromised.

4. **Hardcoded Secrets**: The Google Analytics API secret is hardcoded in the source code, which is a minor security issue but not directly exploitable.

The extension appears to be developed by a legitimate developer providing a useful service, with analytics implemented for product improvement rather than malicious data harvesting. Users who are concerned about privacy tracking may want to use alternative PiP solutions or review the extension's privacy practices.

**Recommendation**: The extension is suitable for users who accept analytics tracking in exchange for PiP functionality. For maximum privacy, users should review the extension's data collection practices or seek alternatives with no analytics implementation.
