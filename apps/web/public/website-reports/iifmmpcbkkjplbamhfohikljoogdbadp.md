# Vulnerability Report: ID.me Shop: Discover Community Discounts

## Metadata
- **Extension ID**: iifmmpcbkkjplbamhfohikljoogdbadp
- **Extension Name**: ID.me Shop: Discover Community Discounts
- **Version**: 3.10.1
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

ID.me Shop is a legitimate shopping discount extension from ID.me, a verified identity platform. The extension monitors user browsing activity on shopping websites to automatically identify available discounts for verified community members (military personnel, teachers, nurses, first responders, students, etc.).

The extension sends visited URLs to the ID.me Shop API to check if the merchant offers community discounts. This data collection is consistent with the extension's stated purpose and privacy policy. The code is webpack-bundled (not maliciously obfuscated), uses Sentry for error tracking, and communicates only with legitimate ID.me services.

## Vulnerability Details

No security or privacy vulnerabilities were identified. The extension operates as disclosed.

## False Positives Analysis

The static analyzer flagged one potential exfiltration flow: `chrome.tabs.query → fetch(${a}.id.me${e})`. This is a **false positive** for the following reasons:

1. **Disclosed functionality**: The extension's description explicitly states it helps users "find Military, Nurse, Teacher, Responder discounts and more while you shop" - which requires sending browsing URLs to check for available discounts.

2. **Legitimate API endpoint**: The fetch destination is `shop.id.me/api/browser_extension/v2/stores/store.json`, which is ID.me's official shopping discount API.

3. **Appropriate data scope**: The extension sends:
   - Current tab URLs (to identify the merchant)
   - User's verified community group memberships (military, teacher, etc.)
   - Extension ID and version (for analytics)
   - Redirect status (to track navigation)

4. **Expected behavior for discount extensions**: Shopping assistant extensions inherently need to know which sites the user visits to provide relevant offers. This is standard functionality, not covert surveillance.

5. **Webpack bundling vs obfuscation**: The analyzer flagged "obfuscated" code, but this is standard webpack module bundling with Sentry debug IDs embedded. The deobfuscated code shows clear, professional development patterns.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| shop.id.me/api/browser_extension/v2/* | Discount lookup API | Visited URLs, user groups, extension metadata | Low - disclosed and appropriate |
| o52232.ingest.us.sentry.io | Error tracking (Sentry) | Error logs and stack traces | Low - standard monitoring service |

## Privacy Considerations

**Browsing Data Collection**: The extension monitors `<all_urls>` and sends visited URLs to ID.me's servers. This is:
- **Disclosed**: Privacy policy explains data collection for discount identification
- **Necessary**: Cannot match discounts without knowing which merchant sites are visited
- **Limited scope**: Only sends URL and basic navigation data, not page content
- **Legitimate vendor**: ID.me is a well-established identity verification company used by government agencies and major retailers

**Permissions Analysis**:
- `<all_urls>` - Required to monitor shopping across all merchant sites
- `webRequest` - Used to track navigation and redirects for accurate merchant detection
- `cookies` - Declared but minimal usage observed in code
- `storage` - Used for caching discount data and user preferences

## Code Quality

- Professional webpack build with source maps
- ES module architecture (MV3 service worker)
- Proper CSP: `script-src 'self'; object-src 'self'`
- Sentry integration for production monitoring
- No eval(), Function(), or dynamic code execution
- No externally_connectable directive

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This is a legitimate shopping discount extension from a reputable company (ID.me). The browsing data collection is fully disclosed, appropriate for the stated functionality, and limited in scope. The code shows professional development practices with no security vulnerabilities, no malicious behavior, and no privacy violations beyond what is necessary for core functionality. The static analyzer's exfiltration flag is a false positive - the extension does exactly what it claims to do in helping verified community members find discounts while shopping online.
