# Vulnerability Report: Avast Online Security & Privacy

## Extension Metadata
- **Extension Name**: Avast Online Security & Privacy
- **Extension ID**: gomekmidlodglbbmalcneegieacbdmki
- **Version**: 22.12.9
- **User Count**: ~6,000,000
- **Developer**: Avast
- **Manifest Version**: 3

## Executive Summary

Avast Online Security & Privacy is a legitimate security extension from a well-established antivirus vendor. The extension implements comprehensive telemetry, analytics, and user tracking as part of its intended functionality. While the extension exhibits extensive data collection and "phones home" behavior, this is consistent with security software that requires cloud-based threat detection and user behavior analysis for threat intelligence. The extension has broad permissions appropriate for its security functions but collects extensive user data including browsing patterns, installed extensions, system information, and user identifiers.

**Risk Assessment**: CLEAN (with privacy considerations)

The extension is rated CLEAN because all observed behavior appears to be part of the intended security/privacy functionality, albeit with significant telemetry. The data collection is extensive but serves legitimate security purposes for a cloud-connected threat detection system.

## Vulnerability Analysis

### 1. Extensive Telemetry and Analytics Infrastructure

**Severity**: INFORMATIONAL (Privacy Concern)
**Files**: `background.js` (lines 29500-29570, 16565-17062)
**Code Evidence**:
```javascript
this.burger = {
  id: 146,
  callerId: 1100,
  batchTimeout: 30 * 60 * 1e3,
  production: "https://analytics.ff.avast.com/v4/receive/gpb",
  stage: "https://analytics-stage.ff.avast.com/v4/receive/gpb",
  defaultState: {
    trackingEnabled: true
  }
};
```

**Analysis**: The extension implements the "@avast/burger-client" analytics library that sends protobuf-encoded telemetry to Avast's analytics infrastructure. This includes:
- Install/update events
- Extension usage patterns
- Browser and OS information
- User identifiers (extensionGUID, localAppGUID, localAppHWID)

**Verdict**: NOT MALICIOUS - This is standard telemetry for security products that require threat intelligence data. The analytics infrastructure is owned by Avast and serves legitimate product improvement and threat detection purposes.

### 2. Comprehensive User and System Fingerprinting

**Severity**: INFORMATIONAL (Privacy Concern)
**Files**: `background.js` (lines 29630-29670, 40100-40140)
**Code Evidence**:
```javascript
this.client = {
  defaultState: {
    extensionGUID: null,
    identifiers: {
      localAppGUID: null,
      localAppHWID: null,
      localAppPluginGUID: null,
      localAppVersion: null,
      localAppType: null,
      successTimestamp: 0
    },
    localEnabled: true,
    a1GeoAvailable: false,
    language: "en",
    installDate: 0,
    callerID: 1e4,
    version: "22.11.177",
    extVersion: "0",
    os: "",
    osVersion: "0",
    osBuild: null,
    browserType: "CHROMIUMEDGE"
  }
};
```

**Analysis**: The extension collects extensive system and user information including:
- Hardware ID (HWID) from local Avast products
- Extension GUID and install date
- Browser type, OS version, and build
- Integration with locally installed Avast products via localhost API (ports 27275, 18821, 7754)

**Verdict**: NOT MALICIOUS - This fingerprinting serves legitimate purposes: (1) detecting if Avast desktop software is installed, (2) coordinating between extension and desktop product, (3) tracking installation lifecycle for support purposes.

### 3. Shepherd Configuration and Remote Code Updates

**Severity**: INFORMATIONAL (Standard Feature)
**Files**: `background.js` (lines 29563-29570)
**Code Evidence**:
```javascript
this.shepherd = {
  id: 46,
  production: "https://shepherd.ff.avast.com/",
  stage: "https://shepherd-preview.ff.avast.com/",
  test: "https://shepherd-test-mobile.ff.avast.com/",
  failRefreshDelay: 5 * 60 * 1e3,
  defaultRefreshDelay: 24 * 60 * 60 * 1e3
};
```

**Analysis**: The "Shepherd" service provides remote configuration updates every 24 hours. This is commonly used to update:
- Privacy guide scenarios (Facebook, Google, LinkedIn, Twitter, Amazon settings)
- Advertiser opt-out automation scripts
- Cookie consent rules
- Anti-tracking rules

**Verdict**: NOT MALICIOUS - Remote configuration is standard for security extensions that need to adapt to changing web threats without requiring full extension updates. The configuration appears to control privacy automation features, not inject malicious code.

### 4. URL Reputation Checking with Complete Browsing Data

**Severity**: INFORMATIONAL (Privacy Trade-off)
**Files**: `background.js` (lines 29571-29575, 2495-4310)
**Code Evidence**:
```javascript
this.urlInfo = {
  throttle: 250,
  phishingRedirect: "https://www.avast.com?utm_source=OnlineSecurity&utm_medium=redirect&utm_campaign=avast",
  production: "https://urlite.ff.avast.com/v1/urlinfo"
};
```

**Analysis**: The extension sends visited URLs to Avast's "urlite" service for reputation checking. This is the core anti-phishing functionality but means:
- All visited URLs are potentially sent to Avast servers
- Includes clientInfo with user identifiers
- Uses protobuf encoding for efficiency
- Provides malware/phishing detection responses

**Verdict**: NOT MALICIOUS - This is the primary security function of the extension. URL reputation checking is how modern anti-phishing extensions work, requiring cloud-based threat intelligence. Users installing a security extension should expect this behavior.

### 5. Geolocation Tracking

**Severity**: INFORMATIONAL (Privacy Feature)
**Files**: `background.js` (lines 44011-44174)
**Code Evidence**:
```javascript
var GEO_LOCATION_API = "https://geolocation.norton.com/api/v2/GeoLocation";
```

**Analysis**: The extension fetches user geolocation (country code) from Norton (Avast's parent company) API. This data is used for:
- Compliance with regional privacy laws (GDPR, CCPA)
- Regional threat intelligence
- Locale-specific features

**Verdict**: NOT MALICIOUS - Geolocation for compliance purposes is a legitimate privacy feature, though the API endpoint being Norton-owned is notable.

### 6. Native App Communication

**Severity**: INFORMATIONAL (Product Integration)
**Files**: `background.js` (lines 40050-40447)
**Code Evidence**:
```javascript
this.LOCAL_PORTS = [27275, 18821, 7754];
```

**Analysis**: The extension attempts to communicate with locally installed Avast products via localhost HTTP on multiple ports. This allows:
- Synchronization between browser extension and desktop product
- Enhanced threat detection using desktop AV capabilities
- Unified product identity management

**Verdict**: NOT MALICIOUS - Legitimate integration feature. The extension gracefully handles cases where no local product is installed.

### 7. Declarative Net Request Rules for Ad/Tracker Blocking

**Severity**: NONE
**Files**: `manifest.json` (lines 86-128), `rulesets/AdTracking.json`
**Analysis**: The extension uses Manifest V3's declarativeNetRequest API to block tracking domains. Rulesets include:
- AdTracking.json - blocks ad networks (doubleclick.net, adnxs.com, etc.)
- Social.json - blocks social media trackers
- WebAnalytics.json - blocks analytics trackers
- Others.json - miscellaneous trackers

All rulesets have "_Allowed" variants that are enabled by default (allowing trackers), while blocking rulesets are disabled by default. Users must opt-in to enable blocking.

**Verdict**: CLEAN - Standard content blocking functionality with conservative defaults.

## False Positives

| Pattern | Context | Why It's Not Malicious |
|---------|---------|----------------------|
| Extensive telemetry to analytics.ff.avast.com | burger-client library | Standard product analytics for security software; required for threat intelligence |
| GUID/HWID collection | Client identity tracking | Necessary for coordinating with desktop product and tracking installation lifecycle |
| All URLs sent to urlite.ff.avast.com | URL reputation checking | Core anti-phishing functionality; how cloud-based threat detection works |
| Remote "shepherd" configuration | Feature updates | Standard for security extensions that need to adapt to changing threats |
| Localhost port scanning | Native app detection | Looking for installed Avast desktop products for integration |
| Geolocation API calls | Privacy compliance | Required for GDPR/regional compliance features |
| Privacy guide automation | Facebook/Google/LinkedIn | Legitimate privacy helper feature to automate privacy settings |

## API Endpoints and External Communications

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| https://analytics.ff.avast.com/v4/receive/gpb | Telemetry | Protobuf-encoded usage events, system info, identifiers | LOW |
| https://shepherd.ff.avast.com/ | Remote config | Extension version, browser type | LOW |
| https://urlite.ff.avast.com/v1/urlinfo | URL reputation | Visited URLs, client identifiers | MEDIUM |
| https://geolocation.norton.com/api/v2/GeoLocation | Geolocation | None (IP-based) | LOW |
| http://localhost:27275,18821,7754/get-info | Local app detection | Browser type, extension version | NONE |
| https://s-install.avcdn.net/aos/assets/prod/translations | Localization | Language preference | NONE |
| https://www.avast.com/geo-a1-data | Geolocation (alt) | None (IP-based) | LOW |

## Data Flow Summary

1. **On Install**: Extension generates GUID, sends install event to analytics, attempts localhost connection to detect Avast desktop products
2. **During Browsing**: URLs are throttled (250ms) and sent to urlite service for reputation checking; results displayed as page ratings
3. **Daily**: Shepherd configuration refreshed to update privacy guides, advertiser opt-out scripts, and blocking rules
4. **Every 30 Minutes**: Analytics batch sent to burger endpoint with aggregated usage data
5. **Periodic**: Geolocation fetched (weekly for urlite, on-demand for compliance features)

## Privacy Concerns

While not malicious, users should be aware:
- **Browsing History**: All visited URLs potentially sent to Avast for reputation checking
- **User Fingerprinting**: Extensive device/software fingerprinting via GUIDs and HWIDs
- **Persistent Tracking**: Install date and extension GUID enable long-term user tracking
- **Third-party Integration**: Norton (parent company) geolocation API usage
- **Desktop Product Detection**: Extension scans localhost to detect other Avast products

These are inherent to how cloud-based security extensions work but represent significant privacy trade-offs.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Justification
Avast Online Security & Privacy is a legitimate security extension from a major antivirus vendor. All observed behaviors are consistent with:
1. Cloud-based threat detection (URL reputation checking)
2. Product telemetry and improvement (analytics)
3. Privacy helper features (automated privacy settings on social media)
4. Ad/tracker blocking (declarativeNetRequest rules)
5. Desktop product integration (localhost API)

The extension is invasive by design - it requires extensive data collection to function as intended. However, this is disclosed behavior for security software, not covert malware.

### Key Mitigating Factors
- Owned by established security company (Avast/Norton)
- 6 million users with public Chrome Web Store presence
- Transparent permissions matching functionality
- No dynamic code execution or obfuscation
- No cryptocurrency mining or residential proxy behavior
- No extension killing or market intelligence SDKs
- No credential theft or form field monitoring

### Recommendation
The extension performs its stated security functions but with significant privacy implications. Users uncomfortable with sending browsing data to Avast should not install it. For users who trust Avast and want cloud-based phishing protection, the extension is operating as designed.
