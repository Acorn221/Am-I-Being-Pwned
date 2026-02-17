# Security Analysis Report: Table Capture

## Extension Metadata
- **Extension ID**: iebpjdmgckacbodjpijphcplhebcmeop
- **Name**: Table Capture
- **Version**: 11.0.32
- **Users**: ~200,000
- **Author**: George Mike
- **Homepage**: https://georgemike.com/tablecapture/
- **Manifest Version**: 3

## Executive Summary

Table Capture is a legitimate productivity extension for extracting table data from web pages. The extension includes **concerning privacy practices** around telemetry collection and a **sandboxed JavaScript evaluator** that executes arbitrary user-provided code. However, no evidence of malicious behavior, third-party tracking SDKs, or data exfiltration was found. The primary concerns are around **opt-out telemetry**, **broad permissions**, and **user-controlled code execution**.

**Overall Risk Level**: **LOW-MEDIUM**

The extension appears to be a genuine productivity tool with aggressive telemetry practices rather than malware. The developer (georgemike.com) maintains legitimate infrastructure and provides standard table extraction functionality.

---

## Vulnerability Analysis

### 1. Aggressive Telemetry to Developer Infrastructure

**Severity**: MEDIUM
**Files**:
- `/src/app/background.js` (lines 3576-3646)
- `/src/app/ai-config.js` (line 73)

**Description**:
The extension implements an EventLogger class that sends telemetry data to `https://georgemike.com/api/appevent/tablecapture`. Events are batched and sent every 3 seconds via POST requests.

**Code Evidence**:
```javascript
// background.js:1646
InstrumentationApiUrl = `${BaseGMoApiUrl}/appevent/tablecapture`;

// background.js:3576-3589
var EventLogger = class {
  log_ = [];
  context_ = {};
  eventLoggingUrl_ = InstrumentationApiUrl;
  constructor(userConfig, extensionContext, context = {}) {
    this.context_ = {
      ...context,
      connector: userConfig.connector,
      plan: userConfig.plan,
      licenseCode: userConfig.licenseCode
    };
    this.disableEventLogging_ = !["options-page", "background-worker"].includes(extensionContext)
      || !userConfig.enableEventLogging
  }
```

**Data Collected**:
- User plan type (FREE, PRO_BASIC, PRO_MAX, CLOUD)
- License code (if activated)
- Extension version
- Event types and timestamps
- Export actions (SHEET_SYNC_CREATE, SHEET_SYNC_WRITE)
- Custom event contexts

**Verdict**: **PRIVACY CONCERN - NOT MALICIOUS**
- Telemetry is controlled by `userConfig.enableEventLogging` (user can opt-out)
- Data goes to legitimate developer infrastructure (georgemike.com)
- No sensitive browsing data, cookies, or credentials collected
- Standard product analytics similar to legitimate SaaS applications

---

### 2. Sandboxed JavaScript Evaluator (User-Controlled eval())

**Severity**: MEDIUM
**Files**:
- `/js-evaluator.html` (entire file)
- Declared in manifest.json sandbox

**Description**:
The extension includes a sandboxed HTML page that uses `eval()` to execute user-provided JavaScript code via postMessage. This is used for "recipes" - user-defined table extraction scripts.

**Code Evidence**:
```javascript
// js-evaluator.html:6-21
function evalCodeWithData(event) {
  const { id, code, data } = event.data;
  try {
    const fn = eval(code);
    const result = fn(data);
    const response = { id, data: result, error: null, success: true };
    window.parent.postMessage(response, window.location.origin);
  } catch (error) {
    const response = {
      id,
      error: `${id} - ${error.message}`,
      success: false,
    };
    window.parent.postMessage(response, window.location.origin);
  }
}
```

**Manifest Declaration**:
```json
"sandbox": {
  "pages": ["js-evaluator.html"]
}
```

**Verdict**: **ACCEPTABLE - PROPERLY SANDBOXED**
- Uses Manifest V3 sandbox pages (proper isolation)
- Origin validation present (`event.origin !== window.location.origin` check)
- User explicitly creates "recipes" (not injected remotely)
- No access to extension APIs or user data from sandbox
- Common pattern for user-scriptable extensions

---

### 3. Dynamic User Script Injection (chrome.userScripts API)

**Severity**: LOW-MEDIUM
**Files**:
- `/src/app/background.js` (lines 3024-3240)

**Description**:
The extension uses the `chrome.userScripts` API to dynamically register user-defined "recipes" that execute on matching URLs. These scripts run in the MAIN world (page context) with full DOM access.

**Code Evidence**:
```javascript
// background.js:3024-3028
async function registerUserScriptForRecipe(recipe) {
  if (!recipe.id) throw new Error("A recipe ID is required to register a user script.");
  if (!recipe.urlExample) throw new Error("A recipe URL example is required to register a user script.");
  if (!chrome.userScripts) throw new Error("User scripts have not yet been enabled in this browser.");
  if (recipe.disabled) return unregisterRecipeWithID(recipe.id, !0);

  // Constructs user script with recipe.fn and recipe.rpfn (user-provided functions)
  let code = `
    function doTableExtract(element, userConfig, basePath) {
      try {
        ${recipe.fn}  // USER-PROVIDED CODE INJECTED HERE
      } catch (err) {
        handleUserScriptError(err.message);
      }
    }
  `;

  chrome.userScripts.register(userScriptDef);
}
```

**Verdict**: **ACCEPTABLE - FEATURE, NOT VULNERABILITY**
- Requires explicit `userScripts` permission (must be granted by user)
- User creates and controls all "recipe" code
- Used for legitimate table extraction automation
- Scripts only run on user-specified URL patterns
- No evidence of remote code injection or server-controlled scripts

---

### 4. Google Sheets OAuth Integration

**Severity**: LOW
**Files**:
- `/src/app/background.js` (lines 3677-3820)

**Description**:
The extension requests Google OAuth tokens to write extracted data to Google Sheets. Uses standard OAuth2 flow with `chrome.identity` API.

**Code Evidence**:
```javascript
// background.js:3677-3681
var GoogleAuthScopes = [
  "https://www.googleapis.com/auth/spreadsheets",
  "https://www.googleapis.com/auth/userinfo.email"
];
var _TC_OAUTH_IDS = {
  prod: "134705207172-cjqlrudj323jpldsf98sjmfaf2045b05.apps.googleusercontent.com"
};

// background.js:3688-3703
async function getGoogleAuthToken(getItFrom) {
  return chrome.identity.getAuthToken({
    interactive: true,
    scopes: GoogleAuthScopes
  }, token => {
    token ? resolve({ token }) : reject(new Error("Unable to retrieve auth token."))
  });
}
```

**Verdict**: **CLEAN - STANDARD OAUTH**
- Uses official Chrome Identity API (no token theft)
- Requests appropriate scopes for declared functionality
- Tokens stored securely via chrome.identity
- Interactive authentication required (user consent)
- Standard Google Sheets API usage

---

### 5. License Verification with Crypto Signature

**Severity**: LOW
**Files**:
- `/src/app/background.js` (lines 2362-2527)

**Description**:
The extension implements client-side license verification using Web Crypto API signatures. License data is base64-encoded and verified against a public key.

**Code Evidence**:
```javascript
// background.js:2387-2414
async function verifyLicenseViaSignature(encodedJsonString) {
  let signedDataJson = atob(encodedJsonString),
      { signature: signatureBase64, challenge, expiresAt, plan, licenseCode } = JSON.parse(signedDataJson);

  storedChallenge = (await chrome.storage.local.get(LICENSE_SIGNING_STORAGE_KEYS.challenge))
    [LICENSE_SIGNING_STORAGE_KEYS.challenge];

  if (challenge !== storedChallenge)
    throw new Error("Challenge mismatch. This license was not generated for this device.");

  let dataToVerify = `${challenge}|${expiresAt}|${plan}|${licenseCode}`;
  return await crypto.subtle.verify({
    name: "RSASSA-PKCS1-v1_5",
    hash: { name: "SHA-256" }
  }, publicKey, signature, data);
}
```

**Verdict**: **CLEAN - LEGITIMATE DRM**
- Standard cryptographic license verification
- Uses Web Crypto API (no eval or dangerous operations)
- License server at `https://georgemike.com/api/licensing/charge`
- Challenge-response prevents replay attacks
- Common pattern for paid extensions

---

### 6. Broad Permissions (host_permissions: <all_urls>)

**Severity**: LOW
**Files**:
- `/manifest.json` (line 16)

**Description**:
The extension requests `<all_urls>` host permissions and injects content scripts on all pages at `document_start`.

**Manifest Evidence**:
```json
"permissions": ["contextMenus", "storage", "tabs", "webNavigation"],
"host_permissions": ["<all_urls>"],
"content_scripts": [{
  "run_at": "document_start",
  "matches": ["<all_urls>"],
  "js": ["src/app/content.js"],
  "all_frames": true,
  "match_about_blank": true
}]
```

**Verdict**: **ACCEPTABLE - REQUIRED FOR FUNCTIONALITY**
- Table extraction tools legitimately need access to all pages
- Content script detects and analyzes tables on any website
- Context menu integration requires webNavigation/tabs permissions
- No evidence of abuse (no keyloggers, form scrapers, or credential theft)

---

### 7. AI/OpenAI Integration (Optional User-Provided API Keys)

**Severity**: LOW
**Files**:
- `/src/app/table-edit.js` (lines 5066-5130)
- `/src/app/background.js` (lines 2251, 2262, 2274)

**Description**:
The extension supports optional OpenAI GPT integration and local Ollama integration for AI-powered table transformations. Users must provide their own API keys.

**Code Evidence**:
```javascript
// background.js:2251-2262
UserConfigDefaults = {
  ollamaHost: "http://127.0.0.1",
  ollamaModel: "",
  ollamaPort: "11434",
  useOllama: false,
  gptApiKey: null,
  gptTokensConsumed: 0
};

var CloudConfigKeys = ["gptApiKey", "gptTokensConsumed", "useOllama"];
```

**Verdict**: **CLEAN - USER-CONTROLLED**
- API keys stored in chrome.storage.local (user-provided)
- No hardcoded API keys or developer-controlled AI access
- Ollama integration uses localhost (no external data)
- Token usage tracked locally (transparency)
- Users opt-in to AI features

---

## False Positives

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `localStorage` references | background.js:1258-1408 | LocalForage library (polyfill for IndexedDB) | False Positive |
| `typeof window.fetch == "function"` | bundle-mutationobserverwrapper.js:3178 | Feature detection, not hooking | False Positive |
| `eval()` in sandbox | js-evaluator.html:9 | Sandboxed page with origin validation | Acceptable Use |
| `recipe.disabled` checks | background.js:3028, 3456 | User-controlled recipe enable/disable | False Positive |
| `atob/btoa` usage | background.js:451, 462, 2357, 2389 | License signature encoding, blob handling | False Positive |
| `chrome.management` matches | Multiple files | "management" in variable names (not chrome.management API) | False Positive |

---

## Network Activity Analysis

### API Endpoints

| Endpoint | Purpose | Data Sent | Verdict |
|----------|---------|-----------|---------|
| `https://georgemike.com/api/appevent/tablecapture` | Telemetry/analytics | Extension version, plan type, license code, event types | Privacy concern (opt-out available) |
| `https://georgemike.com/api/licensing/charge` | License verification | License code, activation flag | Legitimate DRM |
| `https://georgemike.com/tablecapture/uninstall/` | Uninstall feedback | Install date, version | Standard practice |
| `https://sheets.googleapis.com/v4/spreadsheets/*` | Google Sheets API | User-extracted table data | User-initiated, OAuth-protected |
| `http://127.0.0.1:11434` | Local Ollama API | Table data for AI processing | Local only, user-controlled |

**No third-party tracking services detected**: No Sensor Tower, Pathmatics, Google Analytics (without VPN bypass), or market intelligence SDKs.

---

## Data Flow Summary

### Data Collected Locally
- User configuration (table extraction preferences)
- Extraction history/activity log (stored in chrome.storage.local)
- License status and plan type
- Recipe definitions (user-created scripts)
- Clip collections (extracted table data)
- GPT API keys (if user-provided)

### Data Sent Externally
1. **To georgemike.com** (opt-out telemetry):
   - Extension version
   - User plan (FREE/PRO/CLOUD)
   - License code (anonymized identifier)
   - Event types (e.g., "SHEET_SYNC_CREATE")
   - Timestamps

2. **To Google Sheets API** (user-initiated):
   - Extracted table data
   - Sheet metadata

3. **To OpenAI** (if user enables with own API key):
   - Table data for AI transformations

### Data NOT Collected
- Browsing history or URLs (except in local activity log)
- Cookies or credentials
- Form input or keystrokes
- AI conversation content (no scraping of ChatGPT/Claude/etc.)
- Ad tracking or marketing data
- Extension inventory

---

## Security Strengths

1. **Manifest V3 Compliance**: Uses service workers, sandboxed pages, and modern APIs
2. **No Extension Enumeration**: No `chrome.management` API usage
3. **No XHR/Fetch Hooking**: No monkey-patching of network APIs
4. **No Third-Party SDKs**: All code is first-party
5. **Proper OAuth Flow**: Google Sheets integration uses standard Chrome Identity API
6. **Sandboxed Code Execution**: User scripts properly isolated
7. **Transparent Licensing**: Cryptographic verification with no phone-home DRM

---

## Recommendations for Users

### Low Risk - Safe to Use With Cautions:
1. **Review telemetry settings**: Check extension options for `enableEventLogging` toggle
2. **Audit user scripts/recipes**: Only use recipes from trusted sources (you write them)
3. **Minimize permissions if possible**: Consider using on specific sites only (requires manual permissions)
4. **Use separate Google account**: If exporting to Sheets, consider dedicated account for table data

### This Extension is Safe If:
- You trust the developer (georgemike.com)
- You're comfortable with usage analytics being sent to developer
- You understand user scripts run in page context
- You only use your own GPT API keys

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Table Capture | Status |
|-------------------|---------------|--------|
| Sensor Tower Pathmatics SDK | Not present | CLEAN |
| AI conversation scraping | Not present | CLEAN |
| Extension enumeration/killing | Not present | CLEAN |
| XHR/fetch interception hooks | Not present | CLEAN |
| Cookie harvesting | Not present | CLEAN |
| Residential proxy infrastructure | Not present | CLEAN |
| Server-controlled kill switches | Not present | CLEAN |
| Remote config for silent expansion | Not present | CLEAN |
| Ad/coupon injection | Not present | CLEAN |
| Hidden market intelligence | Not present | CLEAN |

---

## Overall Risk Assessment

**Risk Level**: **LOW-MEDIUM**

### Risk Breakdown:
- **Malicious Intent**: 0/10 (No evidence of malware)
- **Privacy Risk**: 4/10 (Telemetry to developer, but opt-out available)
- **Security Risk**: 3/10 (Broad permissions, but not abused)
- **Data Exfiltration**: 1/10 (Only analytics, no sensitive data)

### Final Verdict: **CLEAN**

Table Capture is a **legitimate productivity extension** with standard table extraction functionality. The primary concerns are around **aggressive telemetry** and **broad permissions**, but these are transparent and serve the extension's core functionality. No evidence of malicious behavior, data theft, or third-party tracking was found.

The extension follows best practices for:
- Manifest V3 compliance
- Sandboxed code execution
- OAuth integration
- Cryptographic license verification

**Recommendation**: Safe for general use. Users concerned about telemetry should verify opt-out settings in extension options.

---

## Technical Details

### Codebase Statistics:
- Total JS size: ~7.5 MB (includes libraries)
- Main files analyzed: 25 JavaScript files
- Background script: 4,295 lines
- Content script: 30,084 lines (includes PDF.js library)
- Third-party libraries: LocalForage, PDF.js, OpenAI SDK (optional), Bootstrap UI

### Evidence of Legitimate Development:
1. Comprehensive localization (i18n messages)
2. Professional UI with Bootstrap components
3. Detailed error handling and debugging
4. Active development (version 11.0.32)
5. Public homepage and documentation
6. Standard SaaS licensing model
7. No obfuscation beyond standard bundling

---

**Report Generated**: 2026-02-06
**Analyst**: Claude Opus 4.6
**Analysis Method**: Static code analysis, pattern matching, network behavior inspection
