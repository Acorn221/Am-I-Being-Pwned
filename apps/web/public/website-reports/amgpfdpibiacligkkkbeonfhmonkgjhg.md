# Vulnerability Report: TikTok All Reposted Videos Remover

## Metadata
- **Extension ID**: amgpfdpibiacligkkkbeonfhmonkgjhg
- **Extension Name**: TikTok All Reposted Videos Remover
- **Version**: 2.0.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"TikTok All Reposted Videos Remover" is a clean, legitimate browser extension that helps TikTok users manage their reposted videos by providing an automated removal interface. The extension operates entirely within TikTok's official API framework, making authenticated requests to TikTok endpoints to list and delete reposted videos. The code is well-structured, includes proper error handling, and respects user privacy by not sending any data to third-party servers. All network communications are exclusively with official TikTok APIs and an optional PayPal donation link.

The extension demonstrates good security practices including proper CSP compliance (no inline scripts), use of manifest v3, scoped permissions, and secure message passing patterns. There are no security vulnerabilities, privacy concerns, or malicious behaviors present.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

### Network Requests to TikTok
The extension makes POST and GET requests to TikTok's API endpoints (`/api/repost/item_list/` and `/tiktok/v1/upvote/delete`). These are **legitimate** API calls:
- The extension's stated purpose is to manage TikTok reposts
- All requests use proper authentication via cookies
- The user's `secUid` is retrieved via a background script executing in the MAIN world context to read from TikTok's page data
- No data is exfiltrated to third parties

### Cookie Access
The extension requests `cookies` permission and reads TikTok cookies to:
- Check login status (`multi_sids`, `living_user_id` cookies)
- Make authenticated API requests for the user's own data
This is **necessary and appropriate** for the extension's functionality.

### Scripting Permission
The extension uses `chrome.scripting.executeScript` with `world: "MAIN"` to read the user's `secUid` from TikTok's page data object (`window.__$UNIVERSAL_DATA$__`). This is a **legitimate technique** to access data that would otherwise be blocked by Content Security Policy.

### PayPal Donation Link
The popup includes functionality to open a PayPal donation link with country-based currency detection. This is **legitimate monetization** and clearly optional - the donation button is user-activated and doesn't automatically collect or send any data.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://www.tiktok.com/api/repost/item_list/` | List user's reposted videos | secUid, pagination params | None - Official TikTok API |
| `https://www.tiktok.com/tiktok/v1/upvote/delete` | Remove a repost | item_id | None - Official TikTok API |
| `https://www.paypal.com/donate/` | Optional donation | None (user-initiated) | None - External but legitimate |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This extension is a well-designed utility that performs exactly as described with no security or privacy concerns. The code demonstrates good development practices including:

1. **Appropriate Permissions**: Only requests permissions necessary for its stated functionality (scripting, tabs, cookies, storage) scoped to `*.tiktok.com`
2. **No Third-Party Data Collection**: All network requests go to official TikTok APIs; no analytics, tracking, or data exfiltration
3. **Proper Architecture**: Uses manifest v3, secure message passing, and appropriate content script isolation
4. **User Control**: Provides an in-page control panel with pause/resume functionality and downloadable reports
5. **Transparency**: Clean, readable code with Portuguese comments indicating the author's identity
6. **Error Handling**: Implements proper retry logic and error boundaries
7. **Privacy Respecting**: Stores configuration locally, no external telemetry

The extension operates entirely as expected for a TikTok profile management tool and presents no risk to users.
