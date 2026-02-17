# Vulnerability Report: AutoSBC

## Metadata
- **Extension ID**: jpjlphemcdmgimfmlmjlnfebflgaaoic
- **Extension Name**: AutoSBC
- **Version**: 26.1.14
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

AutoSBC is a Chrome extension designed to enhance the EA Sports FC Ultimate Team web app experience by providing automated Squad Building Challenge (SBC) solving functionality and other companion features. The extension collects FIFA/FC Ultimate Team player card pricing data (player ratings, rarity, positions, team/league affiliations, and market prices) and uploads this information to `www.autosbc.app` to maintain an accurate pricing database.

The data collection is **opt-in** through a setting called "Anonymously share usage and price data" (logPacksPicks), and users are presented with a consent dialog explaining the anonymous nature of the data collection. The extension uploads player card metadata including ratings, positions, leagues, teams, and observed market prices. While this behavior is disclosed and consensual, it represents a data collection mechanism that users should be aware of.

## Vulnerability Details

### 1. MEDIUM: Disclosed Data Collection and Upload

**Severity**: MEDIUM
**Files**: autosbc.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects detailed player card data from the EA Sports FC Ultimate Team web app and uploads it to a remote server at `www.autosbc.app/api/upload`. This includes player metadata (IDs, names, ratings, positions, nations, leagues, teams, icon status) and market pricing information (minimum/maximum price limits and buy-now prices).

**Evidence**:
```javascript
// Line 26065: Data structure uploaded
bt[e] = [e, A._metaData.id, A._staticData.name, A._rareflag, A._rating,
  A.preferredPosition, A.nationId, A.leagueId, A.teamId,
  null != A._playStyles.find(A => !0 === A.isIcon) ? "true" : "false",
  null != A._itemPriceLimits?.minimum ? A._itemPriceLimits?.minimum : -1,
  null != A._itemPriceLimits?.maximum ? A._itemPriceLimits?.maximum : -1,
  -1, n]

// Line 25950: Upload via fetch
FA().logPacksPicks && Object.values(bt).length > 0 && await fetch(a + "/api/upload", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify(Bt())
})

// Line 25974: Upload via sendBeacon when page hidden
navigator.sendBeacon(a + "/api/upload", A)
```

**Consent Mechanism**:
```javascript
// Lines 640-641: English consent dialog text
"price-uploader.title": "AutoSBC needs you!",
"price-uploader.explanation": "Help us make AutoSBC even better! By allowing us to
  collect anonymous data about your usage, you'll be contributing to improvements and
  future features.<br><br>This data is completely anonymous and doesn't identify you
  personally. You can change this behavior at any time in your settings."

// Line 675: Settings label
"settings.logPacksPicks": "Anonymously share usage and price data"
```

**Configuration**:
```javascript
// Lines 82-83: Upload filters
upload_min_rating: 78,
upload_include_common: !1  // false by default

// Line 26021: Upload condition checks rating threshold
e._rating >= A.upload_min_rating && (!0 === A.upload_include_common || e._rareflag >= 1)
```

**Verdict**: This is a **disclosed, opt-in data collection mechanism** for maintaining a pricing database. The extension clearly explains the data collection in its settings and presents a consent dialog to users. The data collected (player card statistics and market prices) is game-related metadata rather than personal user information. However, it still constitutes data exfiltration that users should be aware of. The practice is comparable to other gaming companion tools that crowdsource market data. Rating: MEDIUM due to disclosure and consent, but flagged for transparency.

## False Positives Analysis

1. **Obfuscation Flag**: The ext-analyzer flagged the code as "obfuscated," but this appears to be standard minification/bundling rather than intentional obfuscation. The code uses standard JavaScript patterns and variable names typical of bundled applications.

2. **Data Exfiltration Flows**: While ext-analyzer correctly identified data flows to remote endpoints, these flows are part of the disclosed functionality. The extension's purpose includes uploading pricing data to improve the service.

3. **Document.getElementById Sinks**: Many getElementById calls are for UI manipulation (button labels, text content updates) and are not security-relevant. Only the flows leading to network requests are meaningful for security analysis.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.autosbc.app/config/config.json | Fetch remote configuration | None (GET) | Low - standard remote config |
| www.autosbc.app/api/user | User authentication/management | Login credentials (when user initiates) | Low - expected functionality |
| www.autosbc.app/api/logout | User logout | Session data | Low - expected functionality |
| www.autosbc.app/authenticate | Authentication | Login credentials | Low - expected functionality |
| www.autosbc.app/data/cheapest_pc.json | Fetch pricing data | None (GET) | Low - data download |
| www.autosbc.app/data/cheapest_console.json | Fetch pricing data | None (GET) | Low - data download |
| www.autosbc.app/api/config_upload | Upload user settings | User configuration | Low - optional feature |
| www.autosbc.app/api/config_download | Download user settings | None (GET) | Low - optional feature |
| www.autosbc.app/api/upload | **Upload player pricing data** | **Player card metadata and prices** | **Medium - disclosed data collection** |
| www.autosbc.app/data/pr_pc.json | Fetch price references | None (GET) | Low - data download |
| www.autosbc.app/data/pr_console.json | Fetch price references | None (GET) | Low - data download |
| www.autosbc.app/api/diagnostic | Upload diagnostic data | Error/diagnostic information | Low - troubleshooting |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: AutoSBC implements disclosed, opt-in data collection of FIFA/FC Ultimate Team player card pricing information. The extension clearly communicates this functionality through consent dialogs and settings controls. Users can opt out at any time. The data collected (player ratings, positions, market prices) is game-related metadata rather than personally identifiable information.

The MEDIUM rating reflects:
- **Positive factors**: Clear disclosure, opt-in consent, user control, legitimate use case (crowdsourced pricing data), transparent purpose
- **Concerns**: Data upload to remote server, potential for future misuse if server-side practices change, breadcrumb tracking of user gameplay patterns

This extension follows better practices than many by implementing consent and disclosure. Users who enable the "Anonymously share usage and price data" setting should understand they are contributing to a crowdsourced pricing database. The extension appears to serve its stated purpose without hidden malicious functionality.
