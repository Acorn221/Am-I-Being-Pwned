# Vulnerability Report: Notifier for Gmail™

## Metadata
- **Extension ID**: dcjichoefijpinlfnjghokpkojhlhkgl
- **Extension Name**: Notifier for Gmail™
- **Version**: 1.2.3
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Notifier for Gmail™" is a legitimate email notification extension by InBasic that monitors Gmail accounts and displays notifications for new emails. The extension uses Gmail's official Atom feed API (`/feed/atom`) and authenticated Gmail web interfaces to check for new mail, display notifications, and perform email actions (mark as read, archive, trash, star).

All network requests are exclusively to `mail.google.com` using the user's authenticated sessions. The extension includes proper credential handling, uses MV3 best practices with offscreen documents, and only accesses data necessary for its stated purpose. The static analyzer flagged obfuscation, but this appears to be standard webpack bundling, not intentional code obfuscation. No security or privacy concerns were identified beyond the extension's documented functionality.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

### Static Analyzer "obfuscated" Flag
The static analyzer flagged this extension as "obfuscated." However, code review reveals this is standard webpack/bundler output, not intentional obfuscation:
- Clear, readable variable names throughout deobfuscated code
- Well-structured modular architecture with `/core/` utilities
- Standard patterns for Chrome extension development
- No evidence of string encryption, control flow flattening, or other obfuscation techniques

### Sensitive API Access Patterns
The extension accesses Gmail cookies (`GMAIL_AT`) and makes authenticated requests to Gmail endpoints. This is legitimate because:
- **Purpose alignment**: The extension's stated purpose is monitoring Gmail accounts
- **Scope limitation**: Only accesses `mail.google.com` with host_permissions
- **Transparent behavior**: Uses Gmail's official Atom feed API and standard web interface
- **No exfiltration**: All data stays within the extension (notifications, storage)

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `mail.google.com/mail/u/*/feed/atom` | Gmail Atom feed (unread count, email metadata) | None (GET with cookies) | None - Official Gmail API |
| `mail.google.com/mail/u/*/s/` | Gmail web interface for actions | Action commands (read, archive, trash), thread IDs, GMAIL_AT token, ID_KEY | None - Authenticated Gmail API |
| `mail.google.com/mail/u/*/h/` | Basic HTML view fallback | None (GET with cookies) | None - Gmail fallback interface |
| `webextension.org/listing/gmail-notifier.html` | Homepage/FAQ updates | Version info on install/update | None - Author's website |

## Code Flow Analysis

### Email Checking Flow
1. **Feed Construction** (`core/check.js` buildFeeds): Constructs Gmail Atom feed URLs for configured accounts (default: u/0 through u/5)
2. **Feed Fetching** (`core/utils/feed.js` Feed.execute): Fetches Atom XML, parses with SAX parser, extracts email metadata (author, title, summary, link)
3. **Notification** (`core/check.js` notify): Creates Chrome notifications with email preview, buttons for actions (read, archive, trash)
4. **Local Storage**: Stores email IDs in `chrome.storage.local` to track which emails are "new"

### Email Actions Flow
1. **Action Trigger**: User clicks notification button or popup UI button
2. **Offscreen Context** (`core/offscreen.js`): Creates offscreen document to execute DOM-dependent operations
3. **Gmail API Call** (`core/offscreen/gmail/core.js` gmail.action):
   - Retrieves `GMAIL_AT` cookie and `ID_KEY` from Gmail pages
   - Constructs action POST request with thread ID and action code (3=read, 1=archive, 9=trash, 5=star)
   - Sends to `mail.google.com/mail/u/*/s/` endpoint

### Authentication Mechanism
- **GMAIL_AT Cookie**: Retrieved via `chrome.cookies.get()` - Gmail's action token
- **ID_KEY**: Extracted from Gmail page HTML - Gmail's internal key for actions
- All actions use `credentials: 'include'` to maintain user's authenticated session

## Permission Justification

| Permission | Usage | Justified |
|------------|-------|-----------|
| `notifications` | Display new email alerts | ✓ Core functionality |
| `contextMenus` | Right-click menus on extension icon | ✓ User interaction |
| `webRequest` | Not actively used in code (legacy?) | ⚠️ Possibly unnecessary |
| `storage` | Store email IDs, preferences | ✓ Required for tracking |
| `alarms` | Periodic email checks, notification timeout | ✓ Core functionality |
| `idle` | Respect user idle state for notifications | ✓ Privacy feature |
| `offscreen` | DOM parsing for Gmail APIs | ✓ MV3 requirement |
| `cookies` | Access GMAIL_AT cookie | ✓ Required for actions |
| `*://mail.google.com/mail/` | Access Gmail Atom feeds | ✓ Core functionality |
| `*://mail.google.com/sync/` | Declared but not used in code | ⚠️ Possibly legacy |

**Note**: `webRequest` and `sync/` host permission may be legacy permissions that are no longer actively used. This is common in extensions that have migrated through multiple manifest versions.

## Privacy Analysis

**Data Collection**:
- Email metadata (sender, subject, summary) stored locally in `chrome.storage.local`
- User preferences (notification settings, feed URLs, ignored accounts)
- All data remains local - no remote servers contacted except Gmail

**Third-Party Access**: None

**User Consent**: Extension's stated purpose is email notification, which necessarily requires reading email metadata

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This is a well-designed, legitimate Gmail notification extension with no security or privacy concerns. All behavior aligns with the extension's stated purpose. Network requests are limited exclusively to Gmail domains using the user's authenticated session. The extension uses official Gmail APIs (Atom feeds) and standard web interface endpoints with proper authentication. Code quality is good with clear structure and no evidence of malicious patterns. The MV3 migration appears properly implemented with offscreen documents for DOM operations. No data exfiltration, no suspicious external endpoints, and no concerning permissions beyond what's necessary for Gmail monitoring functionality.
