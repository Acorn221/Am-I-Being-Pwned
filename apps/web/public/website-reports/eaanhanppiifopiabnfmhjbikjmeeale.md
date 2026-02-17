# Vulnerability Report: LingQ Importer

## Metadata
- **Extension ID**: eaanhanppiifopiabnfmhjbikjmeeale
- **Extension Name**: LingQ Importer
- **Version**: 2.3.38
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

LingQ Importer is a legitimate language learning extension that allows users to import foreign language content from streaming platforms (Netflix, YouTube, Prime Video) into LingQ's language learning platform. The extension extracts subtitle/caption data from videos and sends it to the user's LingQ account via the official LingQ API.

After thorough analysis of the codebase, including static analysis with ext-analyzer and manual code review, no security or privacy concerns were identified. All data flows are consistent with the extension's stated purpose, and all network requests go to expected destinations (the streaming platforms for subtitle retrieval and lingq.com for content import).

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

### ext-analyzer Findings
The static analyzer flagged one "EXFILTRATION" flow: `document.getElementById → fetch` in `youtube/contentscript.js`. This is a false positive for the following reasons:

1. **Legitimate functionality**: The flow extracts subtitle data from DOM elements that were populated by the extension itself (stored in hidden div `#LQYTSUB`), then sends it to the user's LingQ account via authenticated API calls.

2. **User-initiated**: The subtitle upload only occurs when the user explicitly clicks the "Import" button in the extension popup, after selecting their target language and course.

3. **Expected destinations**: All fetch calls go to either:
   - `https://www.lingq.com/api/*` (the extension's legitimate backend, covered by host_permissions)
   - The streaming platform's own APIs to retrieve subtitle files (Netflix, YouTube, Prime Video)

### Attack Surface Finding
The analyzer also flagged: `message data → fetch` from `popup.js ⇒ youtube/contentscript.js`. This is also a false positive:

1. **Internal communication**: This is chrome.runtime.onMessage communication between the extension's own popup and content script, not an externally accessible message handler.
2. **Validated message types**: The content script only responds to specific message actions (`GetVideoInfo`, `GetVideoSubs`) and validates the request structure.
3. **No origin validation needed**: Chrome's runtime messaging is isolated to the extension's own components.

### Obfuscation Flag
The analyzer flagged the code as "obfuscated". However, upon manual review, the code is clean and readable. The extension includes standard minified libraries (jQuery, select2) which may have triggered the obfuscation detector, but the extension's own code is not obfuscated.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.lingq.com/api/v2/profiles/ | Get user profile/language settings | None (GET request) | None - legitimate API |
| www.lingq.com/api/v2/contexts/ | Fetch user's language learning contexts | None (GET request) | None - legitimate API |
| www.lingq.com/api/v2/{lang}/collections/recent/ | Fetch user's courses for selected language | None (GET request) | None - legitimate API |
| www.lingq.com/api/v3/{lang}/lessons/import/ | Import lesson content | URL, title, subtitle file, metadata, user tags | None - user-initiated, authenticated |
| www.youtube.com/youtubei/v1/player | Fetch video metadata and subtitle URLs | videoId | None - public YouTube API |
| Netflix/Prime Video subtitle URLs | Fetch subtitle files | None (GET request to URLs found in page) | None - accessing public subtitle data |

## Code Quality Observations

### Positive aspects:
1. **MV3 migration**: Uses modern Manifest V3 APIs (chrome.scripting, service workers)
2. **Minimal permissions**: Only requests necessary permissions (activeTab, cookies for auth, storage, scripting)
3. **Host permissions scoped**: Only requests host_permissions for their own API domain
4. **Content script scoping**: Each platform (Netflix/YouTube/Prime) has separate content scripts that only run on relevant domains
5. **CSRF protection**: Properly includes CSRF token in API POST requests
6. **Error handling**: Comprehensive error handling with user-friendly messages

### Architecture:
- Content scripts extract subtitle data from each streaming platform using platform-specific APIs
- Web-accessible worker scripts run in the page context to access streaming platform APIs
- Popup UI manages user interaction and authentication with LingQ
- All data flows through the content script → popup → LingQ API pipeline

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This extension serves its stated purpose (importing foreign language content into LingQ for learning) without any privacy or security concerns. All data collection is:
- Explicitly user-initiated
- Limited to subtitle/caption data the user is actively viewing
- Sent only to the user's own LingQ account via authenticated API calls
- Fully disclosed in the extension's description

The extension does not collect browsing history, does not inject ads, does not modify page content beyond its own UI elements, and does not exfiltrate any data beyond what is necessary for the language learning workflow. The permissions requested are minimal and appropriate for the functionality provided.

The static analyzer findings are false positives that result from the legitimate subtitle extraction and import workflow. No actual security vulnerabilities or privacy concerns were identified during manual code review.
