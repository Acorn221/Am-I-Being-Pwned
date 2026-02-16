# Vulnerability Report: Redirector

## Metadata
- **Extension ID**: ocgpenflpmgnfapjedencafcfakcekcd
- **Extension Name**: Redirector
- **Version**: 3.5.3
- **Users**: ~70,000
- **Manifest Version**: 2
- **Rating**: 4.3/5 (358 ratings)
- **Analysis Date**: 2026-02-15

## Executive Summary

Redirector is a legitimate browser extension that allows users to automatically redirect web content based on user-defined rules using wildcard or regex patterns. The extension intercepts web requests via the `webRequest` API and redirects them according to patterns configured by the user.

After thorough code analysis, this extension demonstrates clean security practices with no data exfiltration, no external network requests, and full user control over all functionality. The extension operates entirely locally, stores redirect rules in Chrome's storage API (local or sync), and does not collect or transmit any user data. The privacy policy explicitly states no data collection occurs.

## Vulnerability Details

No security vulnerabilities were identified in this extension.

## False Positives Analysis

The extension legitimately uses several powerful permissions that could appear suspicious but are required for its core functionality:

1. **webRequest/webRequestBlocking permissions on all URLs**: Required to intercept and redirect web requests according to user-defined rules. This is the core functionality of the extension.

2. **tabs permission**: Used only to update tab URLs when handling history state redirects (for single-page applications like Facebook/Twitter) and to switch between existing settings tabs to avoid conflicts.

3. **broad host permissions (http://*/*, https://*/*)**: Necessary because users can define redirect rules for any website. The extension only acts on URLs matching user-configured patterns.

4. **chrome.runtime.sendMessage calls**: These are internal messages between the extension's popup/options pages and background script to retrieve and save redirect configurations. No external communication occurs.

## Code Quality Observations

### Positive Security Practices

1. **No external network requests**: The entire codebase operates locally with no fetch(), XMLHttpRequest, or any external API calls.

2. **GET-only redirects**: The extension specifically prevents redirecting POST requests to avoid accidentally leaking sensitive form data (line 59 in background.js).

3. **Loop prevention**: Implements safeguards against infinite redirect loops by tracking recently redirected URLs and limiting redirects to 3 per 3-second window.

4. **Open source and transparent**: The extension includes a comprehensive README with examples and links to the GitHub repository (https://github.com/einaregilsson/Redirector).

5. **Privacy policy compliance**: Includes a clear privacy policy stating no data collection occurs.

6. **Storage flexibility**: Allows users to choose between local and sync storage for their redirect rules.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | N/A | N/A |

This extension does not communicate with any external endpoints.

## Permissions Analysis

- **webRequest/webRequestBlocking**: Required for core redirect functionality - justified
- **webNavigation**: Used for handling history state updates in single-page applications - justified
- **storage**: Stores user-defined redirect rules locally or in sync storage - justified
- **tabs**: Updates tab URLs for history-based redirects and manages settings tabs - justified
- **notifications**: Optional feature allowing visual notifications when redirects occur - justified
- **http://*/*, https://*/***: Necessary to allow redirects on any user-specified domain - justified

All permissions are appropriate for the extension's documented functionality.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

Redirector is a well-designed, legitimate browser utility with no security or privacy concerns. The extension:

1. Does not collect, transmit, or exfiltrate any user data
2. Does not make any external network requests
3. Operates entirely locally using only Chrome storage APIs
4. Has appropriate safeguards against misuse (POST request blocking, loop prevention)
5. Is open source with transparent functionality
6. Has a clear privacy policy stating no data collection
7. All permissions are justified and necessary for documented functionality
8. Demonstrates good security practices (e.g., GET-only redirects to prevent data leaks)

The extension has been available since at least 2015 (based on GitHub issue references) with 70,000 users and maintains a 4.3/5 rating, indicating stable and trusted operation. The codebase shows no signs of malicious intent, obfuscation beyond standard webpack bundling, or privacy-invasive behavior.

This extension is safe for users who want to customize their web browsing experience with custom redirect rules.
