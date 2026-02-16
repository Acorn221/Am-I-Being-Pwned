# Vulnerability Report: Grepper

## Metadata
- **Extension ID**: amaaokahonnfjjemodnpmeenfpnnbkco
- **Extension Name**: Grepper
- **Version**: 0.1.0.3
- **Users**: ~100,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Grepper is a coding Q&A browser extension that integrates with Google search and other developer-focused websites. The extension provides code snippet answers from the grepper.com platform directly within search results and on coding documentation pages. After thorough analysis of the extension's source code, permissions, and network behavior, no security or privacy concerns were identified. The extension operates transparently within its stated purpose and does not engage in undisclosed data collection, tracking, or malicious activities.

The extension uses the `<all_urls>` permission to inject content scripts on Google search pages and popular coding websites (Stack Overflow, W3Schools, MDN, etc.) to display relevant code snippets. All network communications are directed to the legitimate grepper.com API for fetching answers and managing user accounts. The extension includes standard features for a developer tool: user authentication, answer saving, keyboard shortcuts, and notification badges.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

**Obfuscated Code Flag**: The static analyzer flagged "obfuscated" code, but examination reveals this is standard webpack-bundled JavaScript from legitimate libraries (CodeMirror, Prism syntax highlighter). The bundling/minification is typical for production browser extensions and not indicative of malicious obfuscation.

**<all_urls> Permission**: While this permission is broad, it is necessary for the extension's core functionality of displaying code answers on any webpage where a user might be viewing coding documentation. The extension's content scripts only activate on Google search pages and specific coding sites (manifest lines 33-166).

**Third-Party Script Injection**: The extension injects CodeMirror and Prism.js libraries into web pages to enable syntax-highlighted code editing. This is expected behavior for a code snippet tool and these are well-known, legitimate open-source libraries.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.grepper.com/api/get_answers_1.php | Fetch code answers | Search query, user ID | Low - disclosed functionality |
| www.grepper.com/api/check_auth.php | User authentication check | User ID, access token | Low - standard auth |
| www.grepper.com/api/install2.php | Extension installation hook | User email or generated ID | Low - user registration |
| www.grepper.com/api/feedback.php | Answer feedback (vote) | Vote type, answer ID, user ID | Low - disclosed feature |
| www.grepper.com/api/get_user_notifications.php | Check for notifications | User ID, access token | Low - notification system |
| www.grepper.com/api/blacklist.php | Site preference management | URL, blacklist type, user ID | Low - user settings |

All endpoints are HTTPS and part of the grepper.com service, which is the extension's stated backend. No unexpected third-party domains are contacted.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

Grepper is a legitimate developer productivity tool with no identified security or privacy issues. The extension:

1. **Transparent Functionality**: All observed behaviors align with the stated purpose of providing code snippet answers from grepper.com
2. **Appropriate Permissions**: While `<all_urls>` is broad, it's justified for the extension's use case and the content scripts are selectively injected
3. **No Undisclosed Tracking**: Network analysis shows all communications go to grepper.com API endpoints for legitimate purposes
4. **Standard User Authentication**: Uses conventional auth tokens stored in chrome.storage.sync
5. **No Data Exfiltration**: No sensitive user data (browsing history, credentials, personal information) is collected or transmitted
6. **No Code Injection Risks**: Does not use eval() or Function() constructor with dynamic/remote code
7. **User Control**: Provides blacklist functionality for users to disable the extension on specific domains
8. **Open Source Dependencies**: Uses well-known libraries (CodeMirror, Prism.js) for code editing/highlighting

The extension represents a low-risk tool for developers seeking quick access to code snippets and programming answers.
