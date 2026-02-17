# Vulnerability Report: IPvFoo

## Metadata
- **Extension ID**: ecanpcehffngcegjmadlcijfolapggal
- **Extension Name**: IPvFoo
- **Version**: 2.31
- **Users**: Unknown (CWS data unavailable)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

IPvFoo is a legitimate, open-source browser extension developed by Paul Marks for network debugging and educational purposes. The extension displays the server IP address for websites, along with real-time summaries of IPv4, IPv6, and HTTPS information across all page elements. All code is clearly written, well-documented, and published under the Apache License 2.0 at https://github.com/pmarks-net/ipvfoo.

The extension uses `<all_urls>` host permissions and webRequest API solely to monitor network traffic and extract IP addresses, which is the core functionality advertised to users. No data is collected, transmitted, or exfiltrated. All storage is local (chrome.storage.local and chrome.storage.session). The extension contains no vulnerabilities or privacy concerns.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

### webRequest with <all_urls>
The extension uses `webRequest` permission with `<all_urls>` host permissions to monitor all network requests. This is necessary for the extension's core purpose: displaying IP addresses for all resources loaded by a webpage. The extension:
- Only reads request metadata (URL, IP address, cache status)
- Does not modify requests or responses
- Does not access request/response bodies
- Stores data only in local session storage

### Storage Usage
The extension uses chrome.storage.session and chrome.storage.sync:
- **Session storage**: Temporary storage of tab-specific IP data that clears on browser restart
- **Sync storage**: Only stores user preferences (icon color scheme, lookup provider settings, NAT64 prefixes)
- No sensitive data is stored
- No data is transmitted externally

### Offscreen Document
Creates an offscreen document (`detectdarkmode.html`) to detect system dark mode preferences on Chrome (Firefox can detect this from the background page). This is a legitimate MV3 pattern for accessing matchMedia API. The document is immediately closed after detection.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | N/A | None |

The extension makes no external network requests. The only URLs referenced are:
- **Third-party lookup services** (bgp.he.net, info.addr.tools, ipinfo.io): These are only opened when the user explicitly right-clicks an IP/domain and selects "Lookup on [provider]". No automatic requests are made; the extension only constructs URLs for user-initiated navigation.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
IPvFoo is a well-maintained, open-source developer tool with transparent functionality. The extension's behavior perfectly aligns with its stated purpose of displaying IP address information for network debugging. Key security indicators:

1. **No data exfiltration**: All data stays local; no external API calls
2. **No malicious behavior**: Clean codebase with proper error handling
3. **Transparent permissions**: All permissions justified by core functionality
4. **Open source**: Code publicly auditable at https://github.com/pmarks-net/ipvfoo
5. **Professional development**: Well-documented, Apache 2.0 licensed, proper copyright notices
6. **MV3 compliant**: Updated to Manifest V3 with service workers

The static analyzer flagged "obfuscated" but this is a false positive - the code uses standard JavaScript minification/bundling patterns common in open-source projects. The deobfuscated code is clean and readable.

This extension poses no security or privacy risk to users and serves its intended purpose as a legitimate network debugging tool for developers.
