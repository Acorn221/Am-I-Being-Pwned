# Vulnerability Report: Just Read

## Metadata
- **Extension ID**: dgmanlpmmkibanfdgjocnabmcaclkmod
- **Extension Name**: Just Read
- **Version**: 6.0.12
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Just Read is a customizable reader extension that simplifies web page content similar to Firefox's Reader View or Safari's Reader Mode. The extension primarily operates locally, extracting article content using Mozilla's Readability library and applying custom styles. It includes optional premium features that involve communication with justread.link for premium status verification and content sharing. The extension also supports optional AI summarization using user-provided OpenAI API keys.

The extension demonstrates good security practices overall, using DOMPurify for sanitization and operating primarily client-side. The main privacy consideration is the optional premium feature that sends article content to justread.link when users choose to share articles. This is an opt-in feature and requires premium subscription. The extension also has optional AI summarization that sends article content to OpenAI using user-provided API keys, which is clearly disclosed functionality.

## Vulnerability Details

### 1. LOW: Premium Feature Data Transmission

**Severity**: LOW
**Files**: content_script.js (lines 3081-3148)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: When users opt to share articles via the premium "share" feature, the extension sends article content (title, author, extracted content) along with the user's premium secret token to justread.link. This is an intentional feature but involves transmitting potentially sensitive reading material to a third-party server.

**Evidence**:
```javascript
fetch(jrDomain + "newEntry", {
  mode: "cors",
  method: "POST",
  headers: { "Content-type": "application/json; charset=UTF-8" },
  body: JSON.stringify({
    jrSecret: jrSecret,
    origURL: window.location.href,
    datetime: date.getFullYear() + "-" + (date.getMonth() + 1) + "-" + date.getDate() + ":" +
              date.getHours() + ":" + date.getMinutes() + ":" + date.getSeconds(),
    title: myTitle,
    author: myAuthor,
    content: copy.outerHTML,
  }),
})
```

**Verdict**: This is disclosed functionality for premium subscribers who explicitly click the share button. The feature is opt-in and requires premium subscription. However, it does expose reading habits and article content to justread.link. Rating as LOW severity because it's intentional, disclosed, and opt-in.

## False Positives Analysis

### Chrome Storage Sync Operations
The extension heavily uses `chrome.storage.sync.get()` which was flagged in the static analysis as potential exfiltration. However, this is the legitimate Chrome Storage API for syncing user preferences across devices, not network exfiltration.

### Local Resource Loading
Multiple XMLHttpRequest calls are used to load local CSS files (`default-styles.css`, `dark-styles.css`) from the extension bundle using `chrome.runtime.getURL()`. These are not security concerns.

### User-Provided OpenAI Integration
The extension allows users to configure their own OpenAI API keys for article summarization. While this sends article content to OpenAI, it:
- Requires explicit user setup with their own API key
- Only activates when users click the "Summarize" button
- Is clearly disclosed functionality for the extension's stated purpose
- Uses the user's own OpenAI account, not hidden third-party collection

### Premium Status Checks
The extension checks premium status daily by sending `jrSecret` to `justread.link/checkPremium`. This is reasonable for license verification and is rate-limited to once per 24 hours.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://justread.link/checkPremium | Verify premium subscription status | jrSecret (user token) | LOW - Necessary for license verification, rate-limited to 1/day |
| https://justread.link/newEntry | Share article content (premium feature) | jrSecret, URL, title, author, article HTML | LOW - Opt-in feature, requires user action and premium subscription |
| User-provided OpenAI endpoints | AI article summarization | Article content | LOW - User controls API key, explicit action required, disclosed functionality |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: Just Read is a legitimate reader extension that operates primarily client-side. The extension uses established libraries (Readability, DOMPurify, Rangy) for content extraction and sanitization. Network communications are limited to:

1. **Premium verification** - Reasonable license checking, rate-limited to daily
2. **Optional content sharing** - Explicit user action required, premium feature only
3. **Optional AI summarization** - User-provided API keys, explicit action required

The extension follows good security practices:
- Uses DOMPurify for HTML sanitization
- Implements proper postMessage origin validation in messager.js (checks `event.origin !== url`)
- Rate-limits API calls appropriately
- Uses chrome.storage.sync for legitimate preference syncing
- All external communications are for disclosed, opt-in features

The main privacy consideration is that premium users who choose to share articles will send content to justread.link, but this is the intended functionality and requires explicit user action. The extension does not perform hidden data collection, tracking, or undisclosed exfiltration.

**Recommendation**: ACCEPT with awareness that premium sharing feature transmits article content to justread.link.
