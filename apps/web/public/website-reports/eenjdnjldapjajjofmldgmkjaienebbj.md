# Security Analysis Report: Copyfish Free OCR Software

## Extension Metadata

- **Extension ID**: eenjdnjldapjajjofmldgmkjaienebbj
- **Name**: Copyfish Free OCR Software
- **Version**: 6.2.0
- **User Count**: 800,000
- **Manifest Version**: 3
- **Publisher**: UI.Vision/ocr.space

## Executive Summary

Copyfish is a legitimate OCR (Optical Character Recognition) extension that enables users to extract text from images on web pages and desktop screenshots. The extension communicates with external OCR APIs (ocr.space) and translation services to provide its core functionality.

**Risk Level: LOW**

The extension demonstrates standard behavior for an OCR utility. While it requests several powerful permissions including `nativeMessaging` and `clipboardRead`, these are appropriately used for the extension's advertised desktop screenshot OCR features. The code is well-structured, uses legitimate third-party APIs, and shows no evidence of malicious data exfiltration or privacy violations.

## Findings Summary

- **Critical**: 0
- **High**: 0
- **Medium**: 0
- **Low**: 1

---

## LOW: Hardcoded API Keys in Configuration

**Severity**: Low
**Category**: Information Disclosure

### Description

The extension embeds API keys directly in its `config/config.json` file that is bundled with the extension. While these keys appear to be intended for the free tier of the service, hardcoding credentials in client-side code is generally discouraged as they can be extracted and potentially abused.

### Evidence

From `/config/config.json`:

```json
"ocr_api_list": [
    {
        "id": "1",
        "ocr_api_key": "copyfishonly_24bbbbb",
        "ocr_api_url": "https://apipro1.ocr.space/parse/image"
    },
    {
        "id": "2",
        "ocr_api_key": "copyfishonly_24",
        "ocr_api_url": "https://apipro2.ocr.space/parse/image"
    },
    {
        "id": "3",
        "ocr_api_key": "copyfishonly_24",
        "ocr_api_url": "https://apipro3.ocr.space/parse/image"
    }
],
"yandex_api_key": "trnsl.1.1.k1.86128cd59209eaf8.513c1afcbd4eaa561318196f5d48450fcfa42215"
```

### Impact

- Potential for key exhaustion if extracted and abused by third parties
- Rate limiting could affect all Copyfish users if keys are shared
- No direct security risk to end users, but could impact service availability

### Recommendation

While this is standard practice for free-tier API services, the publisher should consider:
- Implementing server-side proxy for API calls to hide keys
- Using per-user API key generation for premium users
- Rate limiting per-installation to prevent abuse

---

## Network Analysis

### External Domains Contacted

The extension communicates with the following external services:

1. **OCR Processing**:
   - `apipro1.ocr.space` - Primary OCR API endpoint
   - `apipro2.ocr.space` - Secondary OCR API endpoint
   - `apipro3.ocr.space` - Tertiary OCR API endpoint
   - Uses round-robin server selection based on response times

2. **License Verification**:
   - `license1.ocr.space` - PRO/PRO+ subscription validation
   - `ui.vision/xcopyfish/` - Legacy license validation endpoint

3. **Translation Services**:
   - `translation.googleapis.com` - Google Translate API (PRO+ tier)
   - `api.deepl.com` - DeepL translation API (PRO+ tier)

4. **Informational Pages**:
   - `ocr.space/copyfish/welcome` - Welcome page after installation
   - `ocr.space/copyfish/whatsnew` - Update notification page
   - `ocr.space/copyfish/why` - Uninstall feedback page

5. **CORS Proxy** (Concerning but Limited Use):
   - `cors-anywhere.herokuapp.com` - Used only when processing images from external HTTP/HTTPS URLs via context menu

### Data Flow Analysis

From `background.js` (lines 425-653), the license check flow:

```javascript
function checkLicenseKey(keyData, urlApi = 'https://ui.vision/xcopyfish/', legacy = true) {
    // Sends 20-character license key to validation endpoint
    // Returns: google_ocr_api_key, google_ocr_api_url, deepl_api_key, etc.
    // No personal data beyond the license key is transmitted
}
```

OCR processing flow:
1. User selects area on page or captures desktop screenshot
2. Image data converted to base64
3. Sent to ocr.space API with selected language parameter
4. Parsed text returned and displayed in extension UI
5. Optional translation via Google/DeepL APIs (PRO+ only)

**No evidence of unauthorized data collection or transmission**.

---

## Permission Analysis

### Declared Permissions

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `contextMenus` | Creates right-click menu for OCR operations | Low |
| `activeTab` | Captures visible tab for OCR processing | Low |
| `scripting` | Injects content scripts for selection UI | Low |
| `storage` | Stores user preferences and license keys | Low |
| `notifications` | Alerts for license expiration, OCR completion | Low |
| `nativeMessaging` | Desktop screenshot capture via native helper | Medium |
| `clipboardRead` | Allows OCR from clipboard images | Medium |
| `commands` | Keyboard shortcuts for desktop capture | Low |

### Native Messaging Analysis

The extension uses native messaging to communicate with two companion applications:

1. **com.a9t9.kantu.file_access** - File system access for desktop screenshots
2. **NMHOST** (XModules) - Desktop screen capture via native screenshot tool

From `background.js` (lines 208-286):

```javascript
const connectAsync = () => {
    port = browser.runtime.connectNative("com.a9t9.kantu.file_access");
    let imageCapturePort = browser.runtime.connectNative(NMHOST);
    // Used for: saveScreenshot, get_version, read_file_range, delete_file
    // Local OCR processing path: UserProfile/AppData/Roaming/UI.Vision/XModules/ocr
}
```

**Assessment**: Native messaging is appropriately used for desktop screenshot functionality. The native modules are optional and only installed if users want desktop OCR features. Operations are limited to screenshot capture and local OCR processing.

---

## Code Quality & Architecture

### Positive Indicators

1. **Clean MV3 Migration**: Properly migrated to Manifest V3 with service worker background
2. **Error Handling**: Comprehensive error handling for API failures and native messaging disconnects
3. **User Consent**: Desktop capture requires explicit user action (toolbar click or keyboard shortcut)
4. **Deferred Promise Pattern**: Uses custom deferred implementation for async operations
5. **Browser Compatibility**: Cross-browser support (Chrome/Firefox) with feature detection

### Code Organization

- `background.js` - Service worker, API communication, license validation
- `cs.js` - Content script for in-page OCR selection UI
- `screencapture.js` - Screenshot processing and display
- `options.js` - Settings page UI
- `config/config.json` - Configuration, API endpoints, language mappings

---

## ext-analyzer Static Analysis Results

```
EXFILTRATION (1 flow):
  [HIGH] chrome.tabs.query → fetch    scripts/background.js
```

### Analysis of Flagged Flow

The flagged exfiltration flow is **false positive**. The `chrome.tabs.query → fetch` pattern occurs in the license validation function:

**Line 323** in `background.js`:
```javascript
browser.tabs.query({}, function (tabs) {
    for (var i = 0; i < tabs.length; i++) {
        var tab = tabs[i];
        enableIcon(tab.id);
    }
});
```

**Lines 451-459** (separate code path):
```javascript
fetch(ApiUrl, { method: "GET" })
    .then((response) => {
        if (response.ok) {
            return response.json();
        }
        return Promise.reject(response);
    })
```

These operations are **not connected** in a data flow. The `tabs.query` is used solely for UI management (enabling extension icon on valid tabs), while `fetch` is used for license key validation. No tab data reaches the network.

---

## Privacy Assessment

### Data Collection Practices

1. **User-Initiated Only**: OCR processing occurs only when user explicitly selects area or captures screen
2. **Image Data**: Screenshots/selections sent to ocr.space API for processing (stated purpose)
3. **License Keys**: 20-character keys sent to validation endpoints for PRO/PRO+ features
4. **No Tracking**: No analytics, telemetry, or user profiling observed
5. **Local Storage Only**: User preferences stored in `chrome.storage.sync` (synced across devices)

### Third-Party Services

All third-party services are directly related to advertised functionality:
- OCR.space - OCR processing
- Google Translate API - Translation (PRO+ only)
- DeepL API - Translation (PRO+ only)

**No advertising networks, tracking pixels, or analytics SDKs detected**.

---

## Web Accessible Resources

The extension exposes the following resources to web pages (via `web_accessible_resources`):

```json
"resources": [
    "message-dialog.html",
    "dialog.html",
    "config/config.json",
    "images/gear.png",
    "images/outside.png",
    "images/close.png",
    "images/translate.png",
    "images/deepl.jpg",
    "images/copyfish-32.png"
]
```

**Risk Assessment**: Low. These are UI assets and HTML dialogs used by content scripts. The config.json contains API keys but these are already public (bundled in extension). No sensitive user data exposed.

Accessible via: `chrome-extension://eenjdnjldapjajjofmldgmkjaienebbj/<resource>`

Potential for extension fingerprinting, but standard for extensions with injected UI.

---

## Behavioral Analysis

### Installation Flow

1. Opens welcome page: `https://ocr.space/copyfish/welcome?b=chrome`
2. Initializes default settings in chrome.storage.sync
3. Connects to native messaging host (if installed)
4. Enables extension icon on all tabs

### Update Flow

1. Sets `isUpdated` flag on extension update
2. Shows badge "New" on extension icon
3. Opens whatsnew page when user clicks icon: `https://ocr.space/copyfish/whatsnew?b=chrome`

### Uninstallation Flow

Redirects to feedback survey: `https://ocr.space/copyfish/why?b=chrome`

**Assessment**: Standard extension lifecycle behavior. No persistent tracking or data retention concerns.

---

## Subscription Model Analysis

The extension operates on a freemium model:

### Free Plan
- OCR.space API with hardcoded shared keys
- Basic OCR in ~20 languages
- No translation features
- Rate limited by shared API quotas

### PRO Plan (license key starts with 'p')
- Dedicated Google Vision API access
- Higher accuracy OCR
- No rate limits
- Requires 20-character license key

### PRO+ Plan (license key starts with 't')
- All PRO features
- Google Translate API access
- DeepL translation API access
- Requires 20-character license key

License validation occurs:
- On extension installation
- Every 24 hours (background check)
- Manually via "Check Key" button in settings

**Expired licenses automatically revert to Free Plan** - no data loss or lockout.

---

## Security Recommendations

### For Users

1. **Trust Assessment**: Extension appears legitimate and safe for its stated purpose
2. **Native Modules**: Only install XModules if you need desktop screenshot OCR
3. **Free Tier Adequate**: Most users don't need PRO/PRO+ subscriptions
4. **Alternative**: Consider local-only OCR tools if privacy is paramount

### For Developers

1. **API Key Management**: Move hardcoded keys to server-side proxy
2. **CORS Proxy**: Replace `cors-anywhere.herokuapp.com` with self-hosted solution
3. **CSP Headers**: Add Content Security Policy to extension pages
4. **Subresource Integrity**: Use SRI hashes for third-party libraries (jQuery, Material Design)
5. **Native Messaging Validation**: Add signature verification for native module communications

---

## Comparison to Similar Extensions

Copyfish's security profile is **better than average** for OCR extensions:

- **No trackers or analytics** (many competitors include Google Analytics)
- **Open about API usage** (configuration clearly documents all endpoints)
- **Optional native components** (some force bundled native modules)
- **No broad host permissions** (uses activeTab instead of <all_urls>)
- **Transparent freemium model** (clearly documents free vs. paid features)

---

## Conclusion

**Final Risk Assessment: LOW**

Copyfish Free OCR Software is a legitimate, well-designed extension that performs its advertised function without privacy violations or malicious behavior. The requested permissions are appropriate for an OCR tool with desktop screenshot capabilities. Network communication is limited to necessary OCR/translation APIs and license validation.

The single low-severity finding (hardcoded API keys) is an industry-standard practice for free-tier API access and poses minimal risk to end users. The ext-analyzer's flagged "exfiltration flow" is a false positive resulting from separate code paths being incorrectly linked.

**Recommendation**: SAFE FOR USE by general users. Power users concerned about cloud OCR processing should investigate local-only alternatives or use the optional local OCR module (XModules).

---

## Technical Appendix

### Key Functions Analysis

**License Validation** (`background.js:444-653`):
- Checks against two endpoints (license1.ocr.space, ui.vision)
- Falls back to legacy endpoint if new one fails
- Stores API credentials in chrome.storage.sync for PRO/PRO+ users
- Notifies user of expiration and reverts to free tier

**Desktop Screenshot** (`background.js:658-715`):
- Requires native messaging connection
- Sends `saveScreenshot` command to NMHOST
- Reads file in chunks via `read_file_range`
- Processes locally or sends to OCR API based on settings
- Deletes temporary file after processing

**In-Page OCR** (`cs.js`):
- User drags selection rectangle on page
- Captures visible tab via `chrome.tabs.captureVisibleTab`
- Adjusts for devicePixelRatio and zoom level
- Sends cropped image data to OCR API
- Displays results in injected overlay UI

### Cryptographic Analysis

**Base64 Encoding** (`background.js:8`):
- Custom Base64 implementation for image data encoding
- Standard RFC 4648 compliant
- No encryption applied to transmitted data
- OCR APIs use HTTPS for transport security

---

**Report Generated**: 2026-02-15
**Analyst**: Claude Opus 4.6
**Analysis Method**: Manual code review + ext-analyzer static analysis
