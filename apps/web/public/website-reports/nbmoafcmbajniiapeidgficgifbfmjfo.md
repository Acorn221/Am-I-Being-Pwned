# Security Analysis: AVG Online Security

**Extension ID:** nbmoafcmbajniiapeidgficgifbfmjfo
**Name:** AVG Online Security
**Version:** 21.1.9
**Users:** 600,000
**Risk Level:** LOW
**Manifest Version:** 3

## Executive Summary

AVG Online Security is a legitimate browser security extension published by AVG/Norton (owned by Gen Digital). The extension provides URL reputation checking, anti-tracking capabilities via declarativeNetRequest rules, phishing protection, and search result annotations. While the extension functions as advertised and comes from a reputable security vendor, it exhibits privacy-invasive behavior by transmitting visited URLs to AVG/Avast servers for reputation analysis and collecting detailed usage telemetry.

The extension is classified as LOW risk because:
- It is published by a well-known security company (AVG/Norton/Avast)
- The data collection serves its stated security functionality
- No evidence of malicious behavior or undisclosed data exfiltration
- Privacy trade-offs are inherent to URL reputation services

However, users should be aware that using this extension means sharing browsing activity with AVG/Avast infrastructure.

## Technical Analysis

### Permissions Analysis

**Declared Permissions:**
- `tabs` - Access to tab information
- `activeTab` - Access to currently active tab
- `scripting` - Inject content scripts
- `storage` - Store configuration and state
- `alarms` - Schedule periodic tasks
- `declarativeNetRequest` - Block tracking requests via rules
- `declarativeNetRequestFeedback` - Monitor blocking statistics

**Host Permissions:**
- `https://*/*` - All HTTPS sites
- `http://*/*` - All HTTP sites

The broad host permissions are necessary for the extension's core functionality (URL reputation checking and anti-tracking on all websites). The permissions are appropriate for a security extension.

### Core Functionality

#### 1. URL Reputation Service (URLite)

The extension implements a URL reputation checking service that queries AVG/Avast servers:

**Endpoint:** `https://urlite.ff.avast.com/v1/urlinfo`

**Data Flow:**
- Background service worker monitors tab navigation
- Visited URLs are sent to AVG's URLite service for reputation analysis
- Service returns reputation scores, phishing warnings, and categorization
- Results are displayed via content script overlays on search results and page indicators

**Implementation Details:**
- Uses Protocol Buffers (protobuf) for efficient serialization
- Throttles requests with 250ms delay to manage API load
- Phishing detections redirect to: `https://www.avg.com?utm_source=OnlineSecurity&utm_medium=redirect&utm_campaign=avg`

#### 2. Anti-Tracking via declarativeNetRequest

The extension uses MV3's declarativeNetRequest API to block tracking requests across four categories:

**Rule Categories:**
- AdTracking - Advertising trackers
- WebAnalytics - Analytics services
- Social - Social media tracking pixels
- Others - Miscellaneous trackers

**Configuration:**
- 8 ruleset files (4 blocking rulesets + 4 allowlist rulesets)
- User can toggle categories on/off
- Default state: all categories disabled (user must opt-in)
- Blocking rules are stored in `/rulesets/*.json` files

**Mock JavaScript Injection:**
The extension also includes mock script injection to prevent breakage:
- `ga.js` - Google Analytics mock
- `omniture.js` - Adobe Analytics mock
- `gpt.js` - Google Publisher Tag mock
- `empty.js` - Generic empty script

This pattern is common in privacy extensions to replace tracking scripts with harmless stubs, preventing site breakage.

#### 3. Telemetry and Analytics

**Endpoint:** `https://analytics.ff.avast.com/v4/receive/gpb`

The extension sends detailed usage telemetry to AVG/Avast's "Burger" analytics platform:

**Data Collected:**
- Extension usage events (installs, uninstalls, feature toggling)
- Session IDs (24-character hex, randomly generated per session)
- Timestamp data
- Error states and HTTP status codes
- A/B test group assignments
- Extension product identity and license information
- Settings and configuration changes

**Transmission Details:**
- Events are batched and sent every 30 minutes (`batchTimeout: 30 * 60 * 1000`)
- Critical events (types 1, 2, 6, 11) are sent immediately without batching
- Uses Protocol Buffers for serialization
- Implements retry logic (max 3 retries) for failed transmissions
- Events cached in `chrome.storage.local` for persistence across restarts

**Burger Client Configuration:**
```javascript
burger: {
  id: 147,
  callerId: 1100,
  batchTimeout: 30 * 60 * 1000,
  production: "https://analytics.ff.avast.com/v4/receive/gpb",
  stage: "https://analytics-stage.ff.avast.com/v4/receive/gpb",
  defaultState: {
    trackingEnabled: true
  }
}
```

Notably, telemetry is **enabled by default** (`trackingEnabled: true`).

#### 4. Geolocation and Compliance

**Endpoints:**
- `https://geolocation.norton.com/api/v2/GeoLocation`
- `https://www.avast.com/geo-a1-data`

The extension fetches the user's country code from Norton/Avast geolocation services to:
- Determine compliance requirements (GDPR, regional regulations)
- Customize feature availability by region
- Localize content and privacy notices

**Data Stored:**
- Country code stored with UUID key: `553c0724-d1aa-4d9c-a67b-a5bd87ab66b8`
- Last fetch timestamp and error states
- Fetch interval: 15 minutes (`FETCH_GEO_LOCATION_FETCH_DELAY = 900000ms`)
- Separate fetch interval for URLite service: 7 days

The geolocation request includes custom header: `X-NLOK-USER-AGENT: AOSP`

#### 5. Configuration Management (Shepherd)

**Endpoint:** `https://shepherd.ff.avast.com/`

The "Shepherd" service provides remote configuration updates:
- Refresh delay: 24 hours (default)
- Fail refresh delay: 5 minutes
- Provides dynamic updates to blocking rules, feature flags, and A/B test assignments
- Allows AVG to remotely modify extension behavior without user updates

#### 6. Content Scripts and Search Result Annotations

Content scripts inject UI elements into web pages:

**Files:**
- `client/main.js` - Main content script (runs on all URLs)
- `client/searchResults.js` - Search result annotation
- `client/advisor.js` - Page reputation advisor
- `client/advertiser.js` - Advertiser opt-out UI
- Cookie consent handlers (`client/cookie/*.js`)

**Web Accessible Resources:**
- CSS files for overlays and warnings
- Locale JSON files (25 languages)
- Icons and fonts
- All resources are accessible to all websites (`matches: ["<all_urls>"]`)

This is a potential fingerprinting vector - malicious sites can detect the extension by probing for web-accessible resources.

### Data Exfiltration Analysis

The ext-analyzer identified 1 exfiltration flow:

**Flow: chrome.storage.local.get → fetch**

This flow represents the telemetry system:
1. Extension reads configuration from `chrome.storage.local` (license info, settings, A/B test assignments)
2. Data is bundled with usage events
3. Transmitted via `fetch()` to `https://analytics.ff.avast.com/v4/receive/gpb`

**Assessment:** This is expected behavior for a legitimate analytics system. The data collected supports product improvement and license validation. However, it represents ongoing data transmission to third-party servers (AVG/Avast/Norton).

### Obfuscation

The extension code is bundled via esbuild/webpack and includes:
- Minified variable names (`__async`, `__spreadValues`, etc.)
- Inline library code (tslib, protobufjs)
- ~42,000 lines of minified background.js

This is standard build tooling, not malicious obfuscation. The deobfuscated code is readable and contains no evidence of intentionally hidden malicious logic.

## Findings

### LOW: Privacy-Invasive Telemetry and URL Sharing

**Severity:** Low
**Category:** Privacy Concern

**Description:**
The extension collects and transmits:
1. **All visited URLs** to `urlite.ff.avast.com` for reputation checking
2. **Detailed usage telemetry** to `analytics.ff.avast.com` including:
   - Extension events and feature usage
   - Session identifiers
   - Configuration and settings
   - Geolocation (country code)
   - A/B test assignments

**Why This Matters:**
- Browsing activity is shared with AVG/Avast/Norton/Gen Digital infrastructure
- URL reputation services inherently require sharing URLs, but users may not realize this
- Telemetry is enabled by default with no clear opt-out mechanism
- Creates a detailed profile of user behavior and browsing patterns

**Mitigation:**
- This is expected behavior for a URL reputation service
- Users concerned about privacy should be aware that using this extension means sharing browsing data with AVG/Avast
- The extension is from a reputable security vendor (Gen Digital/Norton/AVG/Avast)
- No evidence of data being used for purposes beyond security and product improvement

**Risk Assessment:**
The privacy trade-off is inherent to the service. Users seeking web protection through URL reputation must accept that URLs are shared with the service provider. The vendor (AVG/Norton) is reputable and subject to privacy regulations. However, privacy-conscious users may prefer local-only solutions.

## Additional Observations

### Positive Security Practices

1. **Manifest V3 Adoption:** Uses modern MV3 APIs (declarativeNetRequest, service workers)
2. **No eval() or dynamic code execution:** All code is static
3. **HTTPS-only for sensitive endpoints:** All AVG/Avast APIs use HTTPS
4. **Error handling:** Comprehensive error handling and retry logic
5. **Localization:** Supports 25 languages with proper i18n

### Concerns

1. **Web Accessible Resources fingerprinting:** All resources accessible to all websites creates fingerprinting vector
2. **Broad permissions:** `<all_urls>` is necessary but powerful
3. **Remote configuration:** Shepherd service can modify behavior remotely
4. **Default telemetry:** Analytics enabled by default, unclear opt-out
5. **Geolocation tracking:** Country code detection every 15 minutes seems excessive

### Legitimate Business Use Cases

All identified behaviors serve legitimate purposes:
- URL reputation checking provides phishing/malware protection
- Anti-tracking features protect user privacy (ironic given telemetry)
- Telemetry supports product development and A/B testing
- Geolocation enables compliance with regional regulations
- Search result annotations help users avoid malicious sites

## Conclusion

AVG Online Security is a **legitimate security extension** from a well-known vendor (Gen Digital, owner of Norton, AVG, and Avast). It provides real security value through URL reputation checking, anti-tracking, and phishing protection.

**Risk Classification: LOW**

The extension is not malicious, but users should understand the privacy implications:
- **All visited URLs are sent to AVG/Avast servers** for reputation analysis
- **Detailed usage telemetry** is collected and transmitted
- **Geolocation** is tracked to determine country/region

This is the expected behavior for a cloud-based URL reputation service. Users who trust AVG/Norton/Avast and want their security services will find this extension appropriate. Users concerned about sharing browsing data with third parties should avoid URL reputation extensions entirely or use local-only alternatives.

**Recommendation:**
No action required. The extension functions as advertised and comes from a reputable publisher. Users should be aware of the data sharing inherent to URL reputation services when choosing to install such extensions.

## Indicators of Compromise

None. This is a legitimate extension from a verified publisher.

## References

- Extension Store: https://chromewebstore.google.com/detail/nbmoafcmbajniiapeidgficgifbfmjfo
- Publisher: AVG (Gen Digital Inc.)
- Support: https://www.avg.com
- Privacy Policy: https://www.avg.com/privacy (assumed, not verified in extension)
