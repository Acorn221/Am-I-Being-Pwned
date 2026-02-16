# Vulnerability Report: Scratch Addons

## Metadata
- **Extension ID**: fbeffbjdlemaoicjdapfpikkikjoneco
- **Extension Name**: Scratch Addons
- **Version**: 1.44.5
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Scratch Addons is a legitimate, well-maintained browser extension that enhances the Scratch programming platform (scratch.mit.edu) with customizable features and themes. The extension demonstrates excellent security practices including proper permission scoping, transparent functionality, and careful handling of user data.

All permissions and host access are strictly limited to the Scratch ecosystem domains (scratch.mit.edu, api.scratch.mit.edu, clouddata.scratch.mit.edu). The extension operates as a modular addon system that provides productivity features for Scratch users, such as editor enhancements, messaging tools, and UI customizations. External network requests are limited to legitimate Scratch infrastructure and one third-party service (my-ocular.jeffalo.net) for user status features.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

Several patterns that might appear suspicious in other contexts are legitimate for this extension:

1. **Cookie Access**: The extension uses chrome.cookies API to read Scratch session cookies (scratchsessionsid, scratchlanguage, scratchcsrftoken). This is legitimate and necessary for:
   - Maintaining user authentication state across addon features
   - Providing proper localization based on user language preferences
   - Enabling authenticated API calls to Scratch services
   - The extension never sends these cookies to unauthorized domains

2. **WebRequest Manipulation**: The extension modifies HTTP headers (Referer) for requests to Scratch domains using declarativeNetRequest. This is a legitimate workaround to ensure proper API functionality when requests originate from the extension context rather than the main page.

3. **Obfuscated Flag**: The static analyzer flagged some code as obfuscated, but inspection reveals this is standard webpack-bundled third-party libraries (Vue.js, Chart.js, Fuse.js, etc.) that are minified but not maliciously obfuscated.

4. **External Endpoint (my-ocular.jeffalo.net)**: This is a legitimate Scratch community service that provides user status features. The extension only fetches public user status information and does not send any sensitive data to this endpoint.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| scratch.mit.edu | Primary Scratch website interaction | User session cookies (legitimate) | None - Same domain as extension purpose |
| api.scratch.mit.edu | Scratch API for user data, projects, messaging | Authentication tokens via cookies | None - Official Scratch API |
| clouddata.scratch.mit.edu | Scratch cloud data service | Project-related data | None - Official Scratch service |
| scratchaddons.com | Extension's official website | None (documentation/changelog only) | None - Extension's own domain |
| uploads.scratch.mit.edu | Scratch asset uploads | User-generated content | None - Official Scratch CDN |
| my-ocular.jeffalo.net | Third-party Scratch community status service | Username (public info) | Low - Read-only public data fetch |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This extension exhibits no security or privacy concerns. It is a well-architected, legitimate tool for enhancing the Scratch platform with:
- Proper permission scoping (all host permissions limited to Scratch domains)
- Transparent functionality that matches its stated purpose
- No data exfiltration or unauthorized tracking
- Standard security practices (MV3 compliance, proper cookie handling)
- Active maintenance and strong community reputation (300K users, 4.7 rating)
- All network requests go to legitimate Scratch infrastructure or documented third-party services
- Clean, readable codebase with modular architecture

The extension represents a trustworthy enhancement to the Scratch ecosystem with no malicious intent or privacy violations.
