# Vulnerability Report: Proxy Helper

## Metadata
- **Extension ID**: mnloefcpaepkpmhaoipjkpikbnkmbnic
- **Extension Name**: Proxy Helper
- **Version**: 2.0.1
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Proxy Helper is a straightforward Chrome extension that provides a user interface for configuring browser proxy settings. The extension allows users to configure HTTP, HTTPS, SOCKS4/5, QUIC proxies, or PAC (Proxy Auto-Configuration) scripts through an options page and toggle proxy configurations via a popup interface.

After analyzing the source code and running static analysis, no security vulnerabilities or privacy concerns were identified. The extension operates entirely locally, modifying only Chrome's proxy settings based on user input. There is no data collection, no tracking, and no unexpected network communications beyond an optional (currently disabled) feature to fetch a bypass list from GitHub.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

Several patterns that might appear suspicious in other contexts are legitimate for a proxy configuration tool:

1. **Broad Permissions**: The extension requests `proxy`, `tabs`, `storage`, `webRequest`, `webRequestAuthProvider`, `offscreen`, and `*://*/*` permissions. These are all necessary for its stated purpose:
   - `proxy`: Required to read and modify Chrome's proxy settings
   - `webRequest` + `webRequestAuthProvider`: Required to inject authentication credentials for authenticated proxies
   - `*://*/*`: Required for webRequest to work across all URLs
   - `offscreen`: Used for MV2 to MV3 migration (localStorage to chrome.storage)

2. **XMLHttpRequest to GitHub**: The code contains a function `getBypass()` (line 105-119 in background.js) that fetches a China bypass list from `https://raw.github.com/henices/Chrome-proxy-helper/master/data/cn.bypasslist`. However, this function is **never called** - it's commented out on line 187. This is not a security concern.

3. **onAuthRequired Listener**: The extension listens to `chrome.webRequest.onAuthRequired` to inject proxy authentication credentials. This is the standard mechanism for authenticated proxies and is documented behavior.

4. **localStorage Usage**: The extension uses localStorage heavily through a local variable named `localStorage` that is actually backed by `chrome.storage.local`. This is a clean pattern for MV3 migration.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://raw.github.com/henices/Chrome-proxy-helper/master/data/cn.bypasslist | (Unused) Fetch China bypass list | None (disabled) | None |

The GitHub endpoint is the only external communication found in the code, and it is currently disabled (commented out). If enabled, it would only fetch a static list of domains to bypass for Chinese users, with no user data transmitted.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This extension is a legitimate proxy configuration utility with clean, well-documented code. The codebase is open source on GitHub (https://github.com/henices/Chrome-proxy-helper) and shows no signs of malicious intent. All functionality aligns with the extension's stated purpose of helping users configure browser proxy settings.

Key findings supporting the CLEAN verdict:
- No data exfiltration or collection
- No tracking or analytics
- No remote code execution or eval usage
- No content scripts injecting into pages
- No communication with external servers (the GitHub fetch is disabled)
- Proper handling of sensitive data (proxy credentials stored only in chrome.storage.local)
- Clean migration from MV2 to MV3 with proper offscreen document usage

The extension does exactly what it claims to do and nothing more.
