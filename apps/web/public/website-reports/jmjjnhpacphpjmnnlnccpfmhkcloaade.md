# Vulnerability Report: Browsing Protection by F-Secure

## Metadata
- **Extension ID**: jmjjnhpacphpjmnnlnccpfmhkcloaade
- **Extension Name**: Browsing Protection by F-Secure
- **Version**: 7.0.11
- **Users**: ~2,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Browsing Protection by F-Secure is a legitimate security extension from a well-established cybersecurity vendor. The extension serves as a browser companion to F-Secure's desktop security products, providing real-time web threat protection, safe search enforcement, ad blocking, and banking/shopping site security features. All core functionality operates through native messaging with the desktop application, meaning the extension itself does not perform data collection or exfiltration.

After thorough analysis of the codebase, including static analysis and manual code review, no security vulnerabilities or privacy concerns were identified. The extension follows security best practices appropriate for its stated purpose as an enterprise security tool.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

Several patterns that might initially appear suspicious are actually legitimate for this type of security extension:

### 1. Broad Host Permissions (`<all_urls>`)
**Pattern**: The extension requests access to all websites via `http://*/*` and `https://*/*`.
**Legitimacy**: Required for real-time web threat scanning and URL reputation checking. Security extensions must monitor all navigation to protect users from malicious sites.

### 2. Native Messaging
**Pattern**: Heavy use of `chrome.runtime.connectNative()` to communicate with `com.fsecure.netprot.nativehost`.
**Legitimacy**: This is the core architecture - the browser extension acts as a lightweight client while the native desktop application handles threat intelligence, URL reputation lookups, and security decisions. This is a standard pattern for enterprise security tools (similar to antivirus browser extensions).

### 3. Tab Monitoring and Navigation Interception
**Pattern**: Extensive listeners on `webNavigation.onBeforeNavigate`, `webRequest.onBeforeRequest`, `tabs.onUpdated`, etc.
**Legitimacy**: Essential for real-time threat protection. The extension must intercept navigation events to check URLs against threat databases before the user reaches potentially malicious sites.

### 4. Data Sent to Native Host
**Pattern**: URLs, tab IDs, referrers, and browsing context sent via native messaging.
**Legitimacy**: All data is sent to the local native application (running on the same machine), not to remote servers. The native app performs reputation lookups and returns verdicts. This architecture keeps sensitive data local.

### 5. Search Result Manipulation
**Pattern**: Modifying Google, Bing, DuckDuckGo search results to add safety ratings.
**Legitimacy**: This is a disclosed feature ("search results" rating icons) that helps users identify safe/unsafe sites before clicking. Common practice for security extensions.

### 6. URL Blocking and Redirects
**Pattern**: Redirecting users to block pages when visiting flagged sites.
**Legitimacy**: Core security functionality - preventing access to phishing, malware, or category-blocked sites (parental controls).

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| f-secure.com | Homepage URL (static) | None | None |
| Native messaging host | URL reputation checks | URLs, tab metadata (local only) | None - local IPC |

**Note**: The extension does NOT make direct HTTP/HTTPS requests to external servers. All threat intelligence queries go through the native messaging host to the desktop application, which then communicates with F-Secure's cloud services. This architecture provides better security and privacy control.

## Data Collection and Telemetry

The extension includes a `DataPipeline` module that sends telemetry events to the native host:
- Trusted shopping popup events (URL sanitized for privacy)
- Unsafe iframe removal events
- Ad blocking statistics
- Consent rejection events (for cookie consent manager feature)
- Dev tools opened events

**Privacy considerations**:
- All telemetry goes through native messaging (local IPC), not direct to internet
- URLs are sanitized via `sanitizeUrlForPrivacy()` before inclusion in telemetry
- User consent is required (Firefox only; other browsers inherit consent from desktop product)

## Security Features (Positive Findings)

1. **Privacy Protection**: The `sanitizeUrlForPrivacy()` function is used before sending URLs in telemetry
2. **Consent Management**: Firefox users must explicitly accept consent; other browsers rely on desktop product consent
3. **Connection Throttling**: Native messaging connection has retry limits to prevent resource exhaustion
4. **Payment Form Detection**: Detects payment forms and performs enhanced security checks on banking/payment sites
5. **CSP**: The extension loads only local scripts via `importScripts()` in service worker
6. **No eval()**: No dynamic code execution found in deobfuscated sources
7. **Message Validation**: Message handlers validate message types and tab IDs before processing

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This is a legitimate security extension from F-Secure, a reputable cybersecurity company. The extension's behavior is appropriate for its stated purpose and follows industry-standard architecture for browser security tools:

1. **No malicious functionality**: No hidden data exfiltration, no credential theft, no unwanted ad injection
2. **Appropriate permissions**: All requested permissions are necessary for the extension's security features
3. **Privacy-conscious design**: Architecture keeps sensitive data local via native messaging; telemetry sanitizes URLs
4. **Transparent operation**: Features match the published description; no hidden behavior
5. **Enterprise-grade**: Similar architecture to other enterprise security tools (Symantec, McAfee browser extensions)

The low user rating (2.8) appears related to functional issues (compatibility problems, feature limitations, desktop app dependencies) rather than security or privacy concerns.

**Recommendation**: Safe for use when paired with F-Secure desktop security product. The extension requires the native desktop application to function.
