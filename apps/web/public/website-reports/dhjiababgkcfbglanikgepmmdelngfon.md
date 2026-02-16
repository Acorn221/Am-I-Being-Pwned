# Vulnerability Report: YouTube Transcriber and Summarizer

## Metadata
- **Extension ID**: dhjiababgkcfbglanikgepmmdelngfon
- **Extension Name**: YouTube Transcriber and Summarizer
- **Version**: 2.1.6
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

YouTube Transcriber and Summarizer by Scripsy is a browser extension designed to extract and summarize YouTube video transcripts using AI. The extension uses Google OAuth for user authentication and sends video transcripts to a remote server (`scripsy-server-production.up.railway.app`) for AI-based summarization.

While the extension appears to function as advertised and its data collection practices align with its stated purpose, it does collect and transmit potentially sensitive information (video viewing history, transcript data, user email) to third-party servers. The extension follows legitimate authentication patterns and does not exhibit malicious behavior, but users should be aware that their YouTube viewing data is being sent to external services.

## Vulnerability Details

### 1. LOW: User Data Collection and Transmission
**Severity**: LOW
**Files**: assets/index.ts-CKfZvNkd.js, assets/users-BcYEXWNR.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension collects user email addresses through Google OAuth and sends video transcript data along with user identifiers to the remote server at `scripsy-server-production.up.railway.app` for summarization purposes.

**Evidence**:
```javascript
// Google OAuth authentication flow
async function E(t, i, o, d = "en") {
  const u = await (await fetch(`${v}/summary`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      email: t,           // User email sent to server
      videoId: i,         // YouTube video ID
      text: o,            // Full transcript text
      decodedLanguage: d
    })
  })).json();
```

**Verdict**: This is expected behavior for an AI summarization service that requires server-side processing. The extension clearly states its purpose (transcription and summarization), and users authenticate explicitly. However, users should be aware their viewing history (video IDs) and email addresses are transmitted to third-party servers.

### 2. LOW: Broad Content Script Injection
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension injects content scripts on all URLs (`<all_urls>`), which is broader than necessary for a YouTube-specific extension.

**Evidence**:
```json
"content_scripts": [
  {
    "js": ["assets/index.tsx-loader-DML4CsFn.js"],
    "matches": [
      "http://*/*",
      "https://*/*",
      "<all_urls>"
    ]
  }
]
```

**Verdict**: While overly broad, the extension appears to only activate its UI on YouTube pages. This is a common pattern for extensions that want to ensure they load on all YouTube subdomains, though it could be scoped more narrowly to `https://*.youtube.com/*`.

## False Positives Analysis

The static analyzer flagged one exfiltration flow:
- **chrome.tabs.get → fetch(accounts.google.com)**: This is part of the legitimate Google OAuth authentication flow using Chrome's identity API. The extension uses `chrome.identity.launchWebAuthFlow()` to authenticate users, which is the standard approach for Chrome extensions requiring Google account access.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| scripsy-server-production.up.railway.app | AI summarization service | Email, video ID, transcript text, language | Medium - User PII and viewing history |
| accounts.google.com | Google OAuth authentication | OAuth tokens | Low - Standard auth flow |
| scripsy.ai | Extension website/checkout | Cookies for payment processing | Low - Payment workflow |
| googleapis.com | Google API services | YouTube data requests | Low - Standard YouTube API |
| google-analytics.com | Analytics tracking | Usage metrics | Low - Standard analytics |

## Privacy Considerations

1. **Data Collection**: The extension collects:
   - User email addresses (via Google OAuth)
   - YouTube video IDs and timestamps
   - Full transcript text
   - Summarization usage metrics

2. **Data Transmission**: All transcript data is sent to `scripsy-server-production.up.railway.app` for processing

3. **Third-Party Services**: Uses Google Analytics for usage tracking

4. **Cookie Usage**: Sets cookies on `scripsy.ai` domain for payment processing

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: The extension functions as advertised - providing YouTube transcript extraction and AI-based summarization. It uses legitimate authentication methods (Google OAuth via chrome.identity API) and the data collection aligns with its stated purpose.

The LOW risk classification is based on:
- **Disclosed functionality**: The extension's purpose clearly involves processing YouTube transcripts
- **Legitimate authentication**: Uses Chrome's official identity API for Google OAuth
- **No hidden malicious behavior**: No evidence of credential theft, session hijacking, or undisclosed data collection
- **Standard commercial model**: Freemium model with payment integration is transparent

**Concerns**:
- Overly broad content script injection (all URLs instead of YouTube-specific)
- User viewing history (video IDs) transmitted to third-party servers
- Requires trust in Scripsy's server-side data handling practices

**Recommendation**: Safe for users who understand and consent to their YouTube viewing data and transcripts being processed by Scripsy's servers for AI summarization purposes.
