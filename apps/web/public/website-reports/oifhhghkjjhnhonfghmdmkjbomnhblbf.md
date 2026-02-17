# Vulnerability Report: RoValk - The Roblox Trading Addon

## Metadata
- **Extension ID**: oifhhghkjjhnhonfghmdmkjbomnhblbf
- **Extension Name**: RoValk - The Roblox Trading Addon
- **Version**: 3.5.8
- **Users**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

RoValk is a legitimate Roblox trading assistant extension that enhances the trading experience by displaying item values, trade statistics, and quick links to Rolimons (a third-party Roblox item valuation service). The extension operates entirely within its disclosed functionality and makes network requests only to documented Roblox and Rolimons API endpoints. All data flows are consistent with the extension's stated purpose of providing trading analytics and item valuations.

The extension properly handles authentication by including credentials in requests to Roblox APIs (standard practice for authenticated API calls) and implements proper CSRF token handling. There is no evidence of credential theft, hidden data exfiltration, or malicious behavior.

## Vulnerability Details

No vulnerabilities identified. All flagged behaviors are false positives related to the extension's legitimate functionality.

## False Positives Analysis

### Static Analyzer "Exfiltration" Flags
The ext-analyzer tool flagged 15 "exfiltration" flows, but these are all false positives:

1. **User Inventory Requests**: The extension fetches user inventory data from `inventory.roblox.com` to calculate total portfolio values. This is the core feature - displaying aggregate values of Roblox limited items.
   - **Files**: csUserProfile.5a72ebb0.js, csTrade.db3b9c60.js, csCatalog.eefd0247.js
   - **Purpose**: Disclosed feature to show user inventory values using Rolimons pricing data
   - **Verdict**: Legitimate functionality, not exfiltration

2. **Rolimons API Integration**: The extension sends item IDs to `api.rolimons.com` to fetch current market values.
   - **Files**: background.ebed9f14.js (line 7), all content scripts
   - **Purpose**: Core feature - item valuation using third-party pricing API
   - **Evidence**: Manifest declares host permission for `https://api.rolimons.com/items/v2/itemdetails`
   - **Verdict**: Disclosed and expected behavior for a trading value calculator

3. **Chrome Storage → Network**: Data from chrome.storage.local is used in network requests, but this is configuration data (user preferences, cached values) not sensitive data.
   - **Evidence**: Background script line 104-107 shows cached trade data being returned to content scripts
   - **Verdict**: Standard extension architecture for performance optimization

### CSRF Token Usage
The extension reads CSRF tokens from `<meta name="csrf-token">` tags and includes them in POST requests to Roblox APIs:
- **Files**: csUserProfile.5a72ebb0.js (line 368-377), csTrade.db3b9c60.js (line 272-281)
- **Purpose**: Required for authenticated Roblox API calls (catalog item details)
- **Verdict**: Legitimate - CSRF tokens are meant to be used by first-party scripts, and this extension is acting as an enhancement layer on Roblox.com pages

### Credentials: "include"
All fetch requests to Roblox domains use `credentials: "include"` to send cookies:
- **Purpose**: Required for authenticated user actions (viewing own inventory, trades)
- **Verdict**: Standard practice for extensions that interact with authenticated APIs on the host site

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.rolimons.com/items/v2/itemdetails | Fetch item market values | None (GET request with From-Extension header) | Low - read-only public data |
| api.rolimons.com/players/v1/playerinfo/{userId} | Fetch user trading stats/badges | User ID (public info) | Low - disclosed feature |
| inventory.roblox.com/v1/users/{userId}/assets/collectibles | Fetch user's limited items | User ID | Low - requires authentication, used for stated purpose |
| trades.roblox.com/v1/trades/* | Fetch trade status for notifications | None (user's own trades) | Low - authenticated, disclosed feature |
| users.roblox.com/v1/users/authenticated | Check if user is logged in | None | Low - standard auth check |
| catalog.roblox.com/v1/catalog/items/details | Get item metadata | Item IDs (CSRF protected) | Low - public catalog data |
| thumbnails.roblox.com/v1/users/avatar-headshot | User avatar for notifications | User ID | Low - public thumbnails |
| discordapp.com/api/v6/invite/* | Discord server invite widget | None (GET) | Low - embedded Discord widget in popup |

## Code Quality Observations

### Positive Indicators
- **Manifest V3**: Uses modern service worker architecture
- **Minimal permissions**: Only requests `storage`, `alarms`, and single host permission
- **Optional permissions**: Notifications are opt-in via `optional_permissions`
- **Content script scoping**: Scripts only run on relevant Roblox pages (trades, catalog, profiles)
- **Error handling**: Proper checks for chrome.runtime.lastError throughout

### Webpack Bundling
The code is bundled with Parcel (parcelRequire94c2), which is standard build tooling, not obfuscation. Variable names are minified but code structure is intact.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This extension is a legitimate utility for Roblox traders. All network activity is consistent with its disclosed purpose of providing item valuations and trading analytics via Rolimons integration. The extension:
- Does not collect or exfiltrate data beyond its stated features
- Only accesses Roblox APIs in the same way the Roblox website would
- Uses proper authentication patterns (CSRF tokens, credentials)
- Clearly discloses its integration with Rolimons
- Implements no tracking, ad injection, or credential harvesting

The static analyzer flags are false positives caused by legitimate data flows that are core to the extension's advertised functionality. There are no security or privacy concerns beyond the inherent trust users place in Rolimons as a third-party valuation service (which is explicitly stated in the extension's description).
