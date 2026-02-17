# Vulnerability Report: ClearURLs

## Metadata
- **Extension ID**: lckanjgmijmafbedllaakclkaicjfmnk
- **Extension Name**: ClearURLs
- **Version**: 1.26.0
- **Users**: ~70,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

ClearURLs is a legitimate privacy-focused browser extension that automatically removes tracking parameters from URLs. The extension downloads rule sets from the official ClearURLs project servers (rules2.clearurls.xyz) and applies them locally to clean tracking parameters from URLs as users browse. The extension is open-source (LGPL v3 license) and maintained by Kevin Röbert.

After thorough code analysis, no security vulnerabilities or malicious behavior were identified. The extension operates entirely client-side after downloading its rule sets, uses proper security practices (CSP, hash verification), and only communicates with its own official servers to fetch updated URL cleaning rules. All network requests are legitimate and necessary for the extension's functionality.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

Several patterns that might appear suspicious in other contexts are legitimate for this extension:

1. **Broad Permissions (`<all_urls>`, `webRequest`, `webRequestBlocking`)**: These are necessary for ClearURLs to inspect and modify URLs across all websites. This is the core functionality of a URL cleaning extension.

2. **Remote Rule Downloads**: The extension downloads rule sets from `https://rules2.clearurls.xyz/`. This is expected behavior for a rule-based privacy tool that needs to stay updated with new tracking parameters. The downloads include:
   - Hash verification using SHA-256 to ensure rule integrity
   - Fallback to cached rules if download fails
   - No user data is sent to these servers

3. **Dynamic URL Modification**: The extension uses `webRequest.onBeforeRequest` to intercept and modify URLs. This is the intended functionality - removing tracking parameters before requests are sent.

4. **Message Handler Dynamic Function Calls**: The `message_handler.js` file uses `window[request.function]` to call functions dynamically. While this pattern can be dangerous, inspection shows it's only used for internal communication between content scripts and background scripts, with no external input.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://rules2.clearurls.xyz/rules.minify.hash | Download hash for rule file integrity verification | None | None - Read-only, no user data transmitted |
| https://rules2.clearurls.xyz/data.minify.json | Download URL cleaning rules (regex patterns) | None | None - Read-only, no user data transmitted |

## Code Quality & Security Observations

**Positive Security Practices:**
- Strong Content Security Policy: `script-src 'self'; object-src 'none'`
- Hash verification (SHA-256) for downloaded rule files
- Local storage of rules with graceful fallback if network fails
- No eval() usage in core functionality
- Proper error handling throughout
- No data exfiltration - all processing is local
- Open-source code with clear licensing (LGPL v3)

**Architecture:**
- Background script intercepts web requests via `webRequest` API
- Applies regex-based rules to remove tracking parameters
- Content scripts for specific fixes (Google, Yandex link fixes)
- Rules stored locally in browser storage
- Statistics tracking is opt-in and stored locally only

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

ClearURLs is a well-designed, legitimate privacy extension with no security or privacy concerns. The extension:

1. **Does what it claims**: Removes tracking parameters from URLs to enhance user privacy
2. **Uses minimal necessary permissions**: All requested permissions are required for core functionality
3. **Transparent operation**: Open-source code with clear documentation
4. **No data collection**: Does not collect, store, or transmit user browsing data
5. **Secure implementation**: Proper CSP, hash verification, and error handling
6. **Trusted source**: Official extension from a known privacy-focused project

The extension actually enhances user privacy rather than compromising it. There are no indicators of malicious behavior, undisclosed data collection, or security vulnerabilities. This is a clean, trustworthy extension that serves its stated purpose effectively.
