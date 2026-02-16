# Vulnerability Report: Random User-Agent (Switcher)

## Metadata
- **Extension ID**: einpaelgookohagofgnnkcfjbkkgepnp
- **Extension Name**: Random User-Agent (Switcher)
- **Version**: 4.3.2
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Random User-Agent (Switcher) is a legitimate privacy-enhancing browser extension developed by tarampampam (https://github.com/tarampampam/random-user-agent). The extension's stated purpose is to automatically randomize the browser's user-agent string to enhance anonymity online. The extension operates as expected with transparent functionality, open-source code, and no hidden malicious behavior.

The extension modifies both HTTP request headers (User-Agent, Sec-CH-UA headers) and JavaScript-accessible navigator properties to present a consistent spoofed browser identity. All network requests are limited to fetching browser version data from cdn.jsdelivr.net to keep user-agent strings current. No user data is exfiltrated, and all functionality aligns with the extension's stated privacy-enhancement purpose.

## Vulnerability Details

No security vulnerabilities were identified. The extension operates transparently with all code matching its open-source repository.

## False Positives Analysis

**Navigator Property Modification**: The extension extensively modifies navigator properties (userAgent, platform, vendor, userAgentData, etc.) via injected scripts. This is the core legitimate functionality of a user-agent switcher and is not malicious. The modifications are:
- Documented in the codebase with friendly comments ("Hey there! Nothing to hide from your scrutiny, right?")
- Necessary to prevent fingerprinting through JavaScript
- Applied consistently across all frames and iframes to avoid leaks

**DeclarativeNetRequest Usage**: The extension uses chrome.declarativeNetRequest to modify request headers including User-Agent and Client Hints headers. This is the standard MV3 approach for header modification and is transparent to users.

**Script Injection into Main World**: The extension injects mbEGGjir.js into the MAIN execution context to override navigator properties before page scripts run. This is necessary for effective user-agent spoofing and is a legitimate use case, not code injection for malicious purposes.

**Remote Configuration**: The extension supports fetching custom user-agent lists from remote URLs. However, this is:
- An optional feature explicitly configured by users
- Used only to download text lists of user-agent strings
- Does not execute remote code or scripts
- Protected by appropriate fetch configuration (no-referrer policy)

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| cdn.jsdelivr.net/gh/mdn/browser-compat-data@5/browsers/*.json | Fetch current browser version data from MDN's official browser compatibility database | Browser type only (chrome, firefox, opera, safari, edge) | None - read-only access to public data |
| User-configured remote URL (optional) | Download custom user-agent string lists if user enables this feature | None - GET request only | None - user controls URL, only text downloaded |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This extension is a well-designed, legitimate privacy tool with no security or privacy concerns. Key findings supporting this assessment:

1. **Transparent Functionality**: All code matches the stated purpose of user-agent randomization. Friendly developer comments throughout indicate nothing to hide.

2. **No Data Exfiltration**: The extension does not collect, transmit, or exfiltrate any user data. All network requests are limited to:
   - Fetching browser version metadata from MDN's public CDN
   - Optional user-configured custom user-agent lists

3. **Open Source**: The extension references its GitHub repository (https://github.com/tarampampam/random-user-agent) in code comments and encourages bug reports.

4. **Appropriate Permissions**: All requested permissions are necessary and used appropriately:
   - `<all_urls>` - Required to inject scripts and modify headers across all sites
   - `declarativeNetRequest` - Used to modify request headers (User-Agent, Client Hints)
   - `scripting` - Used to inject navigator property overrides
   - `tabs`, `alarms`, `storage` - Standard extension functionality

5. **Clean Implementation**: The code uses modern MV3 APIs appropriately, implements blacklist/whitelist domain filtering, and provides comprehensive user configuration options.

6. **No Malicious Patterns**: No eval usage, no credential harvesting, no hidden C2 communication, no obfuscation beyond standard webpack bundling, no tracking or analytics.

The extension serves its stated privacy-enhancement purpose effectively without introducing any security risks. It represents legitimate functionality in the browser privacy tools category.
