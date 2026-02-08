# Vulnerability Report: ChatGPT search

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | ChatGPT search |
| Extension ID | ejcfepkfckglbgocfkanmcdngdijcgld |
| Version | 1.11 |
| Manifest Version | 3 |
| Approximate Users | 4,000,000 |
| Files Analyzed | manifest.json, content_script.js |
| Analysis Date | 2026-02-08 |

## Executive Summary

ChatGPT search is an extremely minimal extension that overrides the browser's default search engine to route queries to `chatgpt.com/?q={searchTerms}`. It consists of only a manifest file and a single one-line content script. The extension requests no special permissions, has no background script, no service worker, no network calls, no chrome.* API usage, and no dynamic code execution. The content script injects a single dataset attribute (`data-search-extension="1"`) on the `<html>` element of chatgpt.com pages, likely used by ChatGPT's frontend to detect the extension is installed.

**This is an official OpenAI extension.** The `update_url` points to the standard Google CRX update endpoint. The search URL routes exclusively to `chatgpt.com`. There is no indication of malicious behavior whatsoever.

## Vulnerability Details

**No vulnerabilities found.**

The extension has an extraordinarily small attack surface:

1. **No permissions requested** - The manifest declares zero `permissions` or `optional_permissions`.
2. **No background/service worker** - No persistent or event-based background processing.
3. **No host permissions** - Content script is narrowly scoped to `https://*.chatgpt.com/*` only.
4. **No CSP override** - Uses default Manifest V3 CSP.
5. **No remote code loading** - No `eval()`, `new Function()`, `import()`, or script injection.
6. **No network calls** - No `fetch()`, `XMLHttpRequest`, or WebSocket usage.
7. **No chrome.* API usage** - No storage, tabs, cookies, webRequest, or any other Chrome API calls.
8. **No data collection** - No telemetry, analytics, or data exfiltration.

### Content Script Analysis (`content_script.js`)

```javascript
document.documentElement.dataset.searchExtension = "1";
```

This single line sets `data-search-extension="1"` on the `<html>` element. This is a benign feature-detection flag allowing chatgpt.com to know the extension is installed, likely to customize the UI accordingly (e.g., showing search-specific features). The script runs at `document_start` and only on `chatgpt.com` pages.

### Search Provider Override

```json
"chrome_settings_overrides": {
  "search_provider": {
    "name": "ChatGPT",
    "search_url": "https://chatgpt.com/?q={searchTerms}&hints=search&ref=ext",
    "is_default": true
  }
}
```

This is the primary functionality of the extension. It redirects default search queries to ChatGPT's search feature. The URL is a first-party OpenAI domain. The `ref=ext` parameter is a standard referral tag, not a tracking concern.

## False Positive Table

| Pattern | Location | Reason for FP |
|---------|----------|---------------|
| N/A | N/A | No suspicious patterns detected |

## API Endpoints Table

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `https://chatgpt.com/?q={searchTerms}&hints=search&ref=ext` | Search query redirect (via omnibox) | None - first-party OpenAI domain |
| `https://chatgpt.com/faviconDark.ico` | Favicon for search provider | None - static asset |
| `https://clients2.google.com/service/update2/crx` | Standard Chrome extension auto-update | None - standard CRX update URL |

## Data Flow Summary

1. User types a search query in Chrome's address bar.
2. Chrome redirects to `https://chatgpt.com/?q={query}&hints=search&ref=ext`.
3. When a chatgpt.com page loads, the content script sets `data-search-extension="1"` on the document element.
4. No data leaves the browser through the extension itself; no background processing occurs.

## Overall Risk: **CLEAN**

This is a legitimate, minimal, officially-published OpenAI extension. It performs exactly one function (search engine override to ChatGPT) with a single-line content script for feature detection. It has zero permissions, zero API calls, zero data collection, and zero attack surface beyond the standard search redirect mechanism. No malicious behavior, no vulnerabilities, and no concerns identified.
