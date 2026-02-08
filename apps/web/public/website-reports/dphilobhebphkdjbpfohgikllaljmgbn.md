# Security Analysis Report: SimpleLogin by Proton

## Extension Metadata

- **Name**: SimpleLogin by Proton: Secure Email Aliases
- **Extension ID**: dphilobhebphkdjbpfohgikllaljmgbn
- **Version**: 3.0.7
- **Users**: ~70,000
- **Manifest Version**: 3
- **Developer**: Proton AG (SimpleLogin)

## Executive Summary

SimpleLogin is a legitimate email alias service developed by Proton AG. The extension provides functionality to generate disposable email aliases to protect user privacy. The security analysis reveals a **clean implementation** with privacy-focused design, legitimate API communication restricted to the SimpleLogin domain, and no malicious behavior detected.

The extension uses broad host permissions to inject email alias generation buttons on all websites, which is necessary for its core functionality. All sensitive API communications occur over HTTPS to verified SimpleLogin domains. No third-party tracking, analytics SDKs, or suspicious data exfiltration was detected.

**Overall Risk: LOW**

## Vulnerability Details

### 1. Broad Host Permissions

**Severity**: LOW (False Positive)
**Files**: `manifest.json`
**Code**:
```json
"host_permissions": [
  "https://*.simplelogin.io/*",
  "http://*/*",
  "https://*/*"
]
```

**Analysis**: The extension requires broad host permissions (`http://*/*`, `https://*/*`) to inject email alias buttons into email input fields across all websites. This is necessary for the core functionality of the service.

**Verdict**: **FALSE POSITIVE** - Broad permissions are functionally required and properly utilized. The extension only accesses email input fields and communicates with SimpleLogin APIs.

---

### 2. Content Script Access to All Pages

**Severity**: LOW (False Positive)
**Files**: `manifest.json`, `content_script/input_tools.js`
**Code**:
```json
"content_scripts": [{
  "js": ["content_script/input_tools.js"],
  "matches": ["http://*/*", "https://*/*"],
  "exclude_matches": ["https://app.simplelogin.io/dashboard/*"],
  "run_at": "document_idle"
}]
```

**Analysis**: Content script runs on all pages to detect email input fields via `querySelectorAll("input[type='email'],input[name*='email'],input[id*='email']")` and inject alias generation buttons. The script:
- Only reads email input field properties (visibility, position)
- Sends current URL to background script when generating aliases (for alias context)
- Does not harvest form data, passwords, or cookies
- Does not monitor keystrokes or general DOM content

**Verdict**: **FALSE POSITIVE** - Content script behavior is legitimate and minimal. URL collection is necessary for contextual alias generation.

---

### 3. Current URL Collection

**Severity**: LOW (False Positive)
**Files**: `content_script/input_tools.js` (line 174-176)
**Code**:
```javascript
let res = await sendMessageToBackground("NEW_RANDOM_ALIAS", {
  currentUrl: window.location.href,
});
```

**Analysis**: The extension collects `window.location.href` when users click the alias generation button. This URL is sent to the SimpleLogin API to associate the generated alias with the website context (allowing users to track which aliases are used on which sites).

**Verdict**: **FALSE POSITIVE** - URL collection is disclosed in the extension description ("create a different email for each website") and is a core privacy feature, not a vulnerability.

---

## False Positive Table

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `tracking` keyword | `content_script/input_tools.js:57` | Comment "remove element from tracking list" refers to internal element tracking for UI management | False Positive |
| Broad permissions `http://*/*` | `manifest.json` | Required to inject email alias buttons on all websites | False Positive |
| URL collection | `content_script/input_tools.js:175` | Needed for contextual alias generation (core feature) | False Positive |
| `postMessage` usage | `content_script/input_tools.js:303` | Safari-specific extension setup, posts extension version info | False Positive |
| React library | `background.js` | Standard React framework for UI, not malicious | False Positive |

## API Endpoints

All API communication is restricted to `https://*.simplelogin.io/*` domains.

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `/api/alias/random/new?hostname=:hostname` | POST | Create random alias | Current URL hostname |
| `/api/v2/alias/custom/new?hostname=:hostname` | POST | Create custom alias | Custom alias prefix, hostname |
| `/api/v4/alias/options?hostname=:hostname` | GET | Fetch alias options for domain | Current URL hostname |
| `/api/aliases/:alias_id` | GET | Fetch alias details | Alias ID |
| `/api/aliases/:alias_id/toggle` | POST | Enable/disable alias | Alias ID |
| `/api/aliases/:alias_id/contacts` | GET | Fetch alias contacts | Alias ID |
| `/api/user_info` | GET | Fetch user profile | API key (auth header) |
| `/api/auth/login` | POST | User login | Email, password |
| `/api/auth/mfa` | POST | MFA verification | MFA token |
| `/api/logout` | POST | User logout | API key |
| `/api/api_key` | POST | Generate API key (Safari) | Device identifier |

**Security**: All endpoints use HTTPS. Authentication via API key stored in `chrome.storage.sync`. No third-party domains contacted.

## Data Flow Summary

### Inbound Data (User → Extension)
1. User clicks alias generation button on email input field
2. Content script sends current URL to background script
3. Background script makes authenticated API call to SimpleLogin
4. SimpleLogin generates alias and returns it
5. Extension populates email input with alias

### Outbound Data (Extension → External)
- **To SimpleLogin API only**:
  - Current URL hostname (for alias context)
  - User authentication credentials (email/password during login)
  - API key (for authenticated requests)
  - Alias management commands (toggle, delete, etc.)

### Storage
- `chrome.storage.sync`: API key, user settings, login state
- No localStorage, no cookies set by extension
- No data sent to third parties

### Content Script Permissions
- Reads: Email input field positions, visibility, current URL
- Writes: Email input field values (with generated aliases)
- Does NOT access: Passwords, cookies, form data, general page content

## Security Strengths

1. **No Dynamic Code Execution**: No `eval()`, `new Function()`, or `innerHTML` assignments detected
2. **No Third-Party Analytics**: No Sentry, Mixpanel, Google Analytics, or other tracking SDKs
3. **HTTPS-Only Communication**: All API calls use HTTPS to verified SimpleLogin domains
4. **Minimal Content Script**: Content script only manipulates email input fields, no broader DOM access
5. **No External Domains**: Zero communication with non-SimpleLogin domains
6. **Open Source**: Extension code appears to match SimpleLogin's open-source repository
7. **Legitimate Developer**: Developed by Proton AG, a privacy-focused company
8. **Modern Architecture**: Uses Manifest V3, service worker background script

## Overall Risk Assessment

**Risk Level: LOW**

**Rationale**:
- Legitimate privacy-enhancing service from reputable developer (Proton AG)
- All code behavior aligns with stated functionality (email alias generation)
- No malicious patterns: no obfuscation, no third-party tracking, no data exfiltration
- Broad permissions are functionally justified and properly used
- All sensitive communication over HTTPS to first-party domain only
- Source code appears to match SimpleLogin's open-source repository

**Recommendation**: **APPROVED FOR USE**

SimpleLogin is a legitimate, privacy-focused extension. The "LOW" risk designation is conservative due to broad host permissions, but these are necessary for core functionality and are not abused. No security vulnerabilities or malicious behavior detected.
