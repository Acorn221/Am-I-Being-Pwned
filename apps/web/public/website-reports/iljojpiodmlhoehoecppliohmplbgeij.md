# Vulnerability Report: Kami - PDF and Document Annotation

## Metadata
| Field | Value |
|-------|-------|
| **Extension Name** | Kami - PDF and Document Annotation |
| **Extension ID** | iljojpiodmlhoehoecppliohmplbgeij |
| **Version** | 2.8 |
| **Manifest Version** | 2 |
| **Users** | ~6,000,000 |
| **Type** | Chrome Hosted App (not a traditional extension) |
| **Analysis Date** | 2026-02-08 |

## Executive Summary

Kami is a **Chrome hosted app**, not a traditional browser extension. The entire package consists of a manifest.json and icon files -- **zero JavaScript, zero HTML, zero CSS**. It contains no background scripts, no content scripts, no popup pages, and no web-accessible resources.

The extension functions solely as a Google Drive file handler that launches the Kami web application at `https://web.kamihq.com/web/viewer.html` when a user opens a PDF from Google Drive. All application logic runs server-side on Kami's infrastructure, completely outside the scope of extension-level analysis.

The only permission requested is `notifications`, which is minimal and appropriate for a document collaboration tool.

**No client-side code exists to analyze for vulnerabilities.** The attack surface within the extension package itself is effectively zero.

## Permissions Analysis

| Permission | Risk | Justification |
|-----------|------|---------------|
| `notifications` | LOW | Standard permission for document annotation/collaboration notifications. Minimal privilege. |

**No host permissions, no `<all_urls>`, no `tabs`, no `cookies`, no `webRequest`, no `storage`.**

## Vulnerability Details

### No Vulnerabilities Found

There is no executable code in this extension to contain vulnerabilities. The extension package is purely declarative:

- **No background scripts** -- nothing runs persistently
- **No content scripts** -- nothing injects into web pages
- **No popup/options pages** -- no user-facing extension UI
- **No web-accessible resources** -- nothing exposed to web pages
- **No CSP concerns** -- no HTML pages to apply CSP to
- **No dynamic code execution** -- no `eval()`, no `Function()`, no remote script loading
- **No XHR/fetch calls** -- no network requests from extension code
- **No chrome.* API usage** -- beyond the implicit `notifications` permission

### Architecture Note

This is a hosted app that uses:
- `"app.urls"`: `["https://web.kamihq.com/web/viewer.html"]` -- the hosted web app URL
- `"app.launch.web_url"`: `"https://web.kamihq.com/web/viewer.html"` -- launch target
- `"container"`: `["GOOGLE_DRIVE"]` -- Google Drive integration
- `"gdrive_mime_types"` -- registers as a handler for PDF files in Google Drive

All security considerations would be in the web application at `web.kamihq.com`, which is outside the scope of this CRX-level analysis.

## False Positive Table

| Pattern | Location | Verdict |
|---------|----------|---------|
| N/A | N/A | No code to analyze |

## API Endpoints Table

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `https://web.kamihq.com/web/viewer.html` | Hosted app launch URL (declared in manifest) | LOW -- standard web app, not called from extension code |
| `https://clients2.google.com/service/update2/crx` | Chrome Web Store auto-update URL | NONE -- standard CWS update mechanism |

## Data Flow Summary

```
User clicks PDF in Google Drive
    |
    v
Chrome recognizes Kami as registered handler (via gdrive_mime_types)
    |
    v
Browser navigates to https://web.kamihq.com/web/viewer.html
    |
    v
All processing happens server-side (outside extension scope)
```

There is **no data flow within the extension itself**. No data is collected, stored, transmitted, or processed by extension code because no extension code exists.

## Overall Risk: **CLEAN**

This extension is a minimal Chrome hosted app with no executable code. It requests only the `notifications` permission and serves as a Google Drive file handler that launches a web application. There is no attack surface within the extension package. Any security concerns would be with the hosted web application at `web.kamihq.com`, which is outside the scope of this analysis.
