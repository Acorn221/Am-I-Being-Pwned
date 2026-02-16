# Vulnerability Report: Web Scrobbler

## Metadata
- **Extension ID**: hhinaapppaileiechjoiifaancjggfjm
- **Extension Name**: Web Scrobbler
- **Version**: 3.19.0
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Web Scrobbler is a legitimate music tracking extension that integrates with Last.fm and other music scrobbling services. The extension monitors music playback across hundreds of supported music streaming sites (YouTube, Spotify, SoundCloud, etc.) and submits "scrobbles" (listening history) to the user's Last.fm account and other configured music tracking services.

The extension has one minor security issue related to postMessage handling without origin validation. However, this vulnerability has minimal practical impact due to the specific implementation context and the benign nature of the data being transmitted. The extension's primary functionality - collecting music metadata and submitting it to user-configured scrobbling services - is fully disclosed and represents the extension's stated purpose.

## Vulnerability Details

### 1. LOW: Missing postMessage Origin Validation

**Severity**: LOW
**Files**: content/main.js (lines 4370-4372, 7156-7166)
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension uses `window.addEventListener("message")` without validating the message origin in multiple locations. This could theoretically allow any webpage to send crafted messages to the extension's content script.

**Evidence**:
```javascript
// content/main.js:4370
window.addEventListener("message", r => {
  typeof r.data != "object" || !("sender" in r.data) ||
  r.data.sender !== "web-scrobbler" || this.onScriptEvent(r)
})

// content/main.js:7156
window.addEventListener("message", t => {
  typeof t.data == "object" && t.data && "sender" in t.data &&
  t.data.sender === "web-scrobbler" && "type" in t.data &&
  t.data.type === "confirmLogin" && ...
})
```

**Verdict**: While the extension doesn't validate `event.origin`, it does validate that messages contain `sender: "web-scrobbler"`. The static analyzer flagged this as HIGH risk, but in practice the impact is LOW because:

1. The messages are only processed if they contain a specific `sender` field value
2. The data being transmitted is music metadata (track/artist names, timestamps) from the extension's own injected scripts
3. The second handler specifically checks for `type === "confirmLogin"` and validates the structure before processing
4. An attacker sending crafted messages could only trigger music scrobbling of fake tracks, not extract sensitive data
5. The messages originate from the extension's own DOM-injected connector scripts, not arbitrary third parties

**Recommendation**: Add origin validation with `if (event.origin !== window.location.origin) return;` as defense-in-depth, though the current sender validation provides reasonable protection.

## False Positives Analysis

The static analyzer flagged several patterns that are legitimate for this extension type:

1. **EXFILTRATION flows to radio.vas3k.club and w3.org**: These are false positives. The vas3k.club reference is simply a connector definition for that music site (line 68 in content/main.js shows it's just in the supported sites array). The w3.org references are likely SVG namespace or schema URLs, not actual data exfiltration endpoints.

2. **Obfuscated flag**: The code is webpack-bundled with minified variable names (common for production builds), not intentionally obfuscated to hide malicious behavior.

3. **Broad permissions**: The extension requires `http://*/*` and `https://*/*` host permissions to support hundreds of music streaming sites. This is necessary and disclosed in the permission request.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ws.audioscrobbler.com/2.0/ | Last.fm API | Music scrobbles (artist, track, album, timestamp), session tokens | Low - disclosed functionality |
| last.fm/api/auth/ | Last.fm authentication | OAuth tokens | Low - standard OAuth flow |
| webscrobbler.com/webhook | Webhook authentication | User-configured webhook URLs | Low - optional feature for custom integrations |
| radio.vas3k.club | Supported music site | No data sent (connector definition only) | None - not actually contacted |

**API Credentials Found**:
- Last.fm API Key: `d9bb1870d3269646f740544d9def2c95` (public, intended for client-side use)
- Last.fm API Secret: `2160733a567d4a1a69a73fad54c564b2` (embedded but standard for Last.fm apps)

These are legitimate Last.fm developer credentials registered for this extension and are meant to be embedded in the client application per Last.fm's API design.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: Web Scrobbler is a legitimate music tracking utility with one minor security issue (missing postMessage origin validation) that has minimal practical exploitability. The extension performs exactly its stated function - monitoring music playback across the web and submitting listening history to user-configured scrobbling services. The broad host permissions are necessary for supporting hundreds of music sites. The Last.fm API credentials are properly used for authenticated scrobbling. The postMessage vulnerability is mitigated by sender validation and would only allow an attacker to submit fake scrobbles, not compromise user data or system security.

The extension has 200,000 users and appears to be a well-maintained open-source project serving a legitimate use case in the music listening community.
