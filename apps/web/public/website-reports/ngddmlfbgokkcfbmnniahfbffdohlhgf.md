# Vulnerability Report: Seller Assistant — Amazon Product Research Tool

## Extension Metadata

- **Extension Name**: Seller Assistant — Amazon Product Research Tool
- **Extension ID**: ngddmlfbgokkcfbmnniahfbffdohlhgf
- **Version**: 1.29.1
- **User Count**: ~40,000
- **Author**: Linen Art, LLC
- **Homepage**: https://sellerassistant.app
- **Analysis Date**: 2026-02-08

## Executive Summary

Seller Assistant is a legitimate Amazon product research tool designed for Amazon sellers. The extension provides FBA/FBM calculators, IP alerts, quick view features, stock checking, restrictions checking, ASIN grabbing, and side panel views across Amazon marketplaces globally.

The extension demonstrates **proper security practices** with legitimate functionality, appropriate permissions for its use case, and integration with vendor's own backend services. While it uses extensive permissions and processes sensitive Amazon seller data, all functionality aligns with the stated purpose of the extension. **No malicious behavior, vulnerabilities, or concerning patterns were identified**.

**Risk Level: CLEAN**

## Manifest Analysis

### Permissions Assessment

**Declared Permissions:**
- `storage` - For saving user preferences and extension state
- `activeTab` - For interacting with current Amazon pages
- `sidePanel` - For side panel UI functionality (legitimate MV3 feature)
- `contextMenus` - For right-click context menu features

**Host Permissions:**
- Amazon domains (20 country-specific TLDs): `.amazon.com`, `.amazon.ca`, `.amazon.co.uk`, `.amazon.de`, etc.
- `https://*.sellerassistant.app/` - Vendor's backend service

**Assessment**: Permissions are minimal and appropriate for an Amazon seller tool. No excessive permissions requested.

### Content Security Policy

**CSP Directive**: `block-all-mixed-content`

This is a positive security feature that prevents mixed HTTP/HTTPS content loading.

### Externally Connectable

The extension allows communication from:
- `*://*.sellerassistant.app/*` (vendor's domain)
- Extension IDs: `nocegffaflllclilhgngcfejmfbdahno`, `bccpegbeakkofioonldfbhgdcdjmkfnk`

These appear to be related extension IDs, likely for development/staging versions or complementary tools by the same vendor.

## Background Script Analysis

**File**: `background.js` (1.8MB, single-line minified/bundled)

### Key Findings

**Legitimate Libraries Detected:**
- Sentry SDK for error monitoring (DSN: `https://cbae3bc4fee9da7f8948663953a3f3c5@o4505363730989056.ingest.sentry.io/4506044489662464`)
- ExcelJS (19-10-2023) - For Excel export functionality
- jQuery 3.7.1 - UI framework
- JSZip 3.10.1 - For ZIP file handling (likely for bulk data export)

### Network Activity

**Primary Endpoints:**
- `https://app.sellerassistant.app` - Main backend API
- `https://sellerassistant.app/saa-uninstalled` - Uninstall tracking
- `https://sellercentral.amazon.*` - Amazon Seller Central API calls
- `https://m.media-amazon.com/images/I/*` - Amazon product images (via Keepa integration)
- Sentry.io error reporting

**Assessment**: All network activity is to legitimate, expected endpoints. No suspicious third-party tracking or data exfiltration detected.

### Code Quality

- Modern bundled/minified code (Webpack/Rollup-style)
- Sentry release ID: `c6f48977f5a08f93cdb1008eeb388020ecedf1eb`
- No obfuscation beyond standard minification
- No dynamic code execution (`eval`, `Function()`) detected
- No base64 encoding/decoding patterns for code obfuscation

## Content Script Analysis

### Content Scripts Deployed

1. **content/content.js** (1.7MB, single-line) - Runs on all Amazon product pages at `document_start`
2. **content/quickView/contentView.js** (1.2MB) - Runs on Amazon pages at `document_end`
3. **content/sellercentral/contentSellercentral.js** (1.1MB) - Runs on Amazon Seller Central inventory pages

### Functionality

- Product data extraction from Amazon pages
- UI injection for seller tools (calculators, quick view panels)
- Amazon Seller Central integration for inventory management
- DOM manipulation limited to Amazon domains

### Security Assessment

- **No credential harvesting** - No password/token interception patterns
- **No keylogging** - No keyboard event listeners for sensitive data capture
- **No XHR/fetch hooking** - No request interception mechanisms
- **No cookie theft** - No chrome.cookies API usage
- **No extension enumeration** - No detection of other installed extensions
- **No ad injection** - No advertisement or coupon injection patterns

## Side Panel & UI Components

**Side Panel**: `sidepanel/sidepanel.html` + `sidepanel.js` (2.3MB)

**Technologies:**
- Vue.js 2.7.16 - UI framework
- Vuex 3.6.2 - State management
- Vue-i18n 8.28.2 - Internationalization
- Font Awesome 6.7.2 - Icons
- Sortable.js 1.10.2 - Drag-and-drop functionality

**Purpose**: Provides an in-browser panel for product research, likely displaying parsed Amazon data, Keepa price history, and seller metrics.

## Data Flow Analysis

### Data Collection

The extension collects:
- Amazon product ASINs
- Product pricing and availability
- Seller restrictions data from Seller Central
- Stock levels and inventory information
- Amazon marketplace identifiers (US, CA, UK, DE, etc.)

### Data Processing

- Product data is sent to `https://app.sellerassistant.app` for analysis
- Keepa integration for historical pricing data (Keepa is a legitimate Amazon price tracking service)
- Data is processed to provide seller profitability calculations

### Data Storage

- Uses `chrome.storage` API for local preferences
- No evidence of IndexedDB or excessive local storage usage
- No persistent credential storage detected

**Assessment**: Data flow is consistent with an Amazon seller research tool. All data transmission is to the vendor's backend for legitimate analysis purposes.

## Third-Party SDKs & Services

### Identified SDKs

| SDK | Purpose | Risk Level |
|-----|---------|------------|
| Sentry | Error monitoring/crash reporting | Low - Standard development practice |
| Keepa | Amazon price history service | Low - Legitimate Amazon data provider |
| ExcelJS | Excel export functionality | Low - Legitimate library for data export |

### No Concerning SDKs Detected

- ✅ No Sensor Tower or market intelligence SDKs
- ✅ No ad injection frameworks
- ✅ No residential proxy infrastructure
- ✅ No cryptocurrency miners
- ✅ No AI conversation scrapers

## API Endpoints Summary

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `app.sellerassistant.app` | Main backend API | Low |
| `sellercentral.amazon.*` | Amazon Seller Central API | Low |
| `m.media-amazon.com` | Amazon product images | Low |
| `sentry.io` | Error reporting | Low |
| `sellerassistant.app/saa-uninstalled` | Uninstall tracking | Low |

## Known False Positives Checked

- ✅ Sentry SDK hooks present but expected for error monitoring
- ✅ No React SVG innerHTML patterns
- ✅ No Floating UI focus trapping
- ✅ No uBlock/AdGuard scriptlets
- ✅ No Vue querySelector issues (Vue 2.7.16 used appropriately)
- ✅ No MobX Proxy objects
- ✅ No Firebase public keys exposed
- ✅ No OpenTelemetry hooks beyond Sentry

## Vulnerability Details

### No Vulnerabilities Identified

After comprehensive analysis, **no security vulnerabilities, malicious behavior, or concerning patterns were detected**.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Justification

1. **Invasive but Legitimate**: The extension requires broad access to Amazon pages and Seller Central, but this is necessary for its stated functionality as a seller research tool.

2. **Appropriate Permissions**: All requested permissions align with the extension's purpose. No excessive or suspicious permissions.

3. **Transparent Data Handling**: All data transmission is to the vendor's own backend (`sellerassistant.app`) for legitimate product research and profitability analysis.

4. **Professional Development**:
   - Proper error monitoring (Sentry)
   - Modern tech stack (Vue.js, Webpack bundling)
   - Manifest V3 compliance
   - CSP implementation

5. **No Malicious Patterns**: Extensive analysis revealed no:
   - Data exfiltration to third parties
   - Credential harvesting
   - Ad/coupon injection
   - Extension killing/enumeration
   - Keylogging or input monitoring
   - Proxy infrastructure
   - Obfuscated malicious code

6. **Legitimate Business Model**: The extension serves Amazon sellers who need market research tools. The functionality (FBA calculator, IP alerts, stock checking) is exactly as advertised.

### Recommendations

For users:
- Extension is safe to use for its intended purpose
- Review vendor's privacy policy at sellerassistant.app regarding data handling
- Understand that product research data is processed by vendor's servers

For developers:
- Consider implementing Content Security Policy with stricter directives
- Document what data is sent to backend in privacy policy
- Consider code splitting to reduce bundle sizes (1.8MB background script)

## Conclusion

Seller Assistant is a **legitimate, professionally-developed Amazon seller tool** with no security concerns. While it processes sensitive Amazon seller data and communicates with backend servers, this is inherent to its functionality and does not constitute malicious behavior. The extension serves its stated purpose without privacy violations or security risks.

**Final Verdict: CLEAN** - Safe for use by Amazon sellers.
