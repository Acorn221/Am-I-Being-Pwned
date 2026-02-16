# Vulnerability Report: Sticky Notes 3.8 - Super Quick & Personal

## Extension Metadata
- **Extension ID**: plpdjbappofmfbgdmhoaabefbobddchk
- **Extension Name**: Sticky Notes 3.8 - Super Quick & Personal
- **Version**: 3.8
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Sticky Notes 3.8 is a legitimate note-taking Chrome extension with cloud backup functionality. The extension uses Firebase for authentication and data synchronization, along with Amplitude for analytics and Sentry for error tracking. After comprehensive analysis, **no malicious behavior or critical security vulnerabilities were identified**. The extension follows standard development practices for a cloud-enabled productivity tool.

The extension's primary risk comes from its extensive use of third-party analytics (Amplitude) and error tracking (Sentry), which collect detailed usage telemetry including device IDs, email addresses, and behavioral patterns. While this is typical for freemium applications, privacy-conscious users should be aware of the data collection scope.

## Vulnerability Analysis

### 1. Data Collection & Privacy Concerns
**Severity**: LOW
**Files**:
- `/deobfuscated/background/init.js`
- `/deobfuscated/background/backgroundHelpers/trackingHelper.js`
- `/deobfuscated/service_worker.js`

**Details**:
The extension implements comprehensive analytics tracking via Amplitude (API key: `634a0a3e7d1454005c1f8271b3cbbf01`) and error reporting via Sentry (DSN: `https://e02d62397c7040f4a2f5bc37a4960765@sentry.io/1342449`). Tracked data includes:

- Device ID (Amplitude)
- Email addresses (when users sign in)
- Extension version and release tracking
- Screen dimensions via `chrome.system.display` permission
- Popup open/close events with duration tracking
- User interaction patterns (clicks, typing bursts, settings changes)
- Installation/update events
- Premium status and license key validation

**Code Evidence**:
```javascript
// service_worker.js
Init.initSentry();
Init.initAmplitude();

// init.js lines 52-66
static initAmplitude(){
    if(typeof amplitude !="undefined"){
        amplitude.getInstance().init("634a0a3e7d1454005c1f8271b3cbbf01");
        TrackingHelper.setAmplitudeUserPropertyIfExists({
            installDate: (new Date()).toLocaleDateString()
        });
    }
}

// trackingHelper.js lines 4-21
static getAmplitudeProperties() {
    let amp_device_id = "";
    let email = "";
    if (typeof amplitude != "undefined" && amplitude.getInstance()) {
        const instance = amplitude.getInstance();
        if (instance.options && instance.options.deviceId) {
            amp_device_id = instance.options.deviceId;
        }
    }
    return new Promise((resolve) => {
        chrome.storage.local.get("email", (data) => {
            resolve({
                amp_device_id: amp_device_id,
                email: data.email,
            });
        });
    });
}
```

**Verdict**: EXPECTED BEHAVIOR - Standard analytics implementation for a freemium SaaS product. All data collection is related to legitimate product analytics and error tracking. No evidence of data exfiltration beyond documented third-party services.

---

### 2. Firebase Cloud Storage Integration
**Severity**: LOW
**Files**:
- `/deobfuscated/common/commonHelpers/firestoreHelper.js`
- `/deobfuscated/common/commonHelpers/authHelper.js`
- `/deobfuscated/background/config.js`

**Details**:
The extension uses Firebase (project: `ukiv-com-sticky-notes`) for user authentication and cloud backup of notes. Firebase credentials are properly scoped:

**Firebase Config**:
```javascript
// background/config.js
const CONFIG = {
    apiKey: "AIzaSyA0CLjauhF99hnfWNHb4szln7QsbrgVmLM",
    authDomain: "ukiv-com-sticky-notes.firebaseapp.com",
    databaseURL: "https://ukiv-com-sticky-notes.firebaseio.com",
    projectId: "ukiv-com-sticky-notes",
    storageBucket: "ukiv-com-sticky-notes.appspot.com",
    messagingSenderId: "220361635393"
};
```

**OAuth2 Scopes** (manifest.json):
```json
"oauth2": {
    "client_id": "220361635393-rnidgv34iqk26kmtke92djhsqo2uff7r.apps.googleusercontent.com",
    "scopes": [
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ]
}
```

Authentication methods:
1. Google OAuth via `chrome.identity.getAuthToken`
2. Email/password via Firebase Auth
3. License key validation for premium features

**Backup Functionality** (firestoreHelper.js lines 125-187):
- Browser token validation to prevent cross-device conflicts
- Premium users can backup all notes to Firestore collections
- Secondary backup mechanism for data redundancy
- Merge conflict resolution when restoring data

**Verdict**: EXPECTED BEHAVIOR - Standard Firebase integration for cloud-enabled productivity apps. Authentication uses proper OAuth flows. The Firebase API key is public (as expected for client-side Firebase apps) and secured via Firebase security rules server-side.

---

### 3. License Key Validation System
**Severity**: LOW
**Files**: `/deobfuscated/common/commonHelpers/firestoreHelper.js`

**Details**:
Premium features are gated behind license key validation stored in Firebase Firestore (`licenses` collection). License activation checks:

```javascript
// firestoreHelper.js lines 745-821
static makeUserPremium(licenseKey) {
    const licenseDoc = doc(this.db, "licenses", licenseKey);
    return getDoc(licenseDoc).then((docObj) => {
        if (docObj.exists()) {
            const data = docObj.data();
            if (data.status == "active") {
                if (data.activatedTo && data.activatedTo.trim().length > 0) {
                    return Promise.reject({
                        code: "license-already-in-use",
                        message: "This License key is assigned to someone else."
                    });
                }
                return updateDoc(licenseDoc, {
                    activatedTo: currentUser.email,
                    activatedToUid: currentUser.uid,
                });
            }
        }
    });
}
```

**Verdict**: EXPECTED BEHAVIOR - Standard freemium licensing model. No license key theft or unauthorized premium activation mechanisms detected.

---

### 4. External Network Endpoints
**Severity**: LOW
**Files**:
- `/deobfuscated/common/commonConstants.js`
- `/deobfuscated/common/commonHelpers/authHelper.js`

**Details**:
The extension communicates with the following external endpoints:

**Legitimate Business Domains**:
- `https://www.getstickynotes.com/*` - Product website, payment, help, installation pages
- `https://storage.googleapis.com/ukiv-stickynotes/static/dynamic_content.json` - Remote configuration
- `https://us-central1-ukiv-com-sticky-notes.cloudfunctions.net/provider?email=X` - OAuth provider lookup

**Third-Party Services**:
- Amplitude analytics: `634a0a3e7d1454005c1f8271b3cbbf01`
- Sentry error tracking: `https://e02d62397c7040f4a2f5bc37a4960765@sentry.io/1342449`
- Firebase services (auth, firestore)

**Remote Config** (commonConstants.js line 27):
```javascript
DYNAMIC_DATA_CALL_URL: "https://storage.googleapis.com/ukiv-stickynotes/static/dynamic_content.json"
```

This endpoint could be used for remote configuration updates. No evidence of malicious remote code execution, but the content is dynamically loaded.

**Verdict**: EXPECTED BEHAVIOR - All endpoints are owned by the extension developer or documented third-party services. No unauthorized data exfiltration detected.

---

### 5. Permissions Analysis
**Severity**: CLEAN
**File**: `/deobfuscated/manifest.json`

**Declared Permissions**:
```json
"permissions": ["storage", "identity", "system.display"]
```

**Analysis**:
- **storage**: Required for local note storage and settings (appropriate)
- **identity**: Required for Google OAuth authentication (appropriate)
- **system.display**: Used to capture screen dimensions for UI layout (init.js lines 13-20)

**No Content Scripts**: The extension does NOT inject content scripts into web pages, eliminating risks of:
- DOM manipulation on user-visited sites
- Cookie/credential harvesting
- Keylogging
- Ad injection

**Verdict**: CLEAN - Minimal permission set appropriate for the extension's functionality. No excessive or suspicious permissions requested.

---

### 6. Dynamic Code Execution
**Severity**: CLEAN
**Files**: All JavaScript files analyzed

**Search Results**:
- No `eval()` calls detected
- No `Function()` constructor usage
- No `setTimeout(string)` or `setInterval(string)` with string arguments
- No dynamic script injection via `<script>` tag manipulation
- No WebAssembly modules
- No `chrome.webRequest` API usage for network interception

**Verdict**: CLEAN - No dynamic code execution mechanisms identified. All code is static and reviewable.

---

### 7. Obfuscation Analysis
**Severity**: CLEAN
**Files**: Bundled files `bundle.29032.js`, `bundle.f1817.js`, `bundle.c83fb.css`

**Details**:
The extension uses standard webpack bundling for React components (39,572 total lines across bundles). Code is minified but not obfuscated beyond typical build tools. Library files are clearly identifiable:
- Amplitude 8.21.1
- Sentry 7.13.0
- Firebase 9.9.3 (auth, app, firestore modules)
- Quill 1.3.6 (rich text editor)
- Shepherd.js (tour library)

**Verdict**: CLEAN - Standard production build process. No malicious obfuscation detected.

---

## False Positives Table

| Pattern | File | Explanation |
|---------|------|-------------|
| Firebase API Key | `background/config.js` | Public client-side Firebase key (secured via Firestore rules) |
| OAuth Client ID | `manifest.json` | Standard Google OAuth configuration for `chrome.identity` |
| Sentry DSN | Multiple files | Public error tracking endpoint (no sensitive data in DSN) |
| Amplitude API Key | `init.js` | Public analytics key for client-side event tracking |
| `innerHTML` usage | `bundle.29032.js` | React/Vue DOM rendering (SVG namespace creation line 1307) |
| Google Identity API | `authHelper.js` | Legitimate Chrome OAuth via `chrome.identity.getAuthToken` |
| XMLHttpRequest | `authHelper.js` lines 107-130 | Provider lookup for OAuth (legitimate Firebase auth flow) |

---

## API Endpoints Summary

| Endpoint | Purpose | Method | Data Sent |
|----------|---------|--------|-----------|
| `https://www.getstickynotes.com/*` | Product website, payment flows | GET | URL parameters (tracking codes) |
| `https://storage.googleapis.com/ukiv-stickynotes/static/dynamic_content.json` | Remote config/feature flags | GET | None |
| `https://us-central1-ukiv-com-sticky-notes.cloudfunctions.net/provider?email=X` | OAuth provider detection | GET | Email address |
| Firebase Firestore | Note backup/sync, user management | Read/Write | User notes, settings, license validation |
| Amplitude | Analytics events | POST | Device ID, email, usage events, screen size |
| Sentry | Error tracking | POST | Exception stack traces, release version |
| Google Identity API | OAuth authentication | Chrome API | Email, profile info (via OAuth scopes) |

---

## Data Flow Summary

### Local Storage:
- **chrome.storage.local**: Notes data, settings, folder configurations, user authentication state
- **localStorage**: Tracking flags, popup counts, backup timestamps, feature toggles

### Network Flow:
1. **User installs extension** → Opens `https://www.getstickynotes.com/installed-on-chrome?__from=apps`
2. **User signs in** → Google OAuth via `chrome.identity` → Firebase Auth token exchange
3. **Analytics events** → Amplitude (install, open, usage patterns)
4. **Errors/crashes** → Sentry exception reporting
5. **Premium backup** → Firestore (note content, settings encrypted in transit via HTTPS)
6. **License validation** → Firestore `licenses` collection lookup
7. **Uninstall** → Opens `https://www.getstickynotes.com/confirm-uninstall-from-chrome?u=TIMESTAMP&r=VERSION&amp_device_id=X`

### No External Data Access:
- ✅ No access to browsing history
- ✅ No access to cookies
- ✅ No access to other websites' content
- ✅ No web request interception
- ✅ No content script injection

---

## Overall Risk Assessment

**RISK LEVEL**: **LOW**

### Justification:
Sticky Notes 3.8 is a **legitimate productivity extension** with appropriate cloud backup and premium licensing features. All identified behaviors are consistent with a standard freemium SaaS application:

1. **No malicious behavior detected**: No credential theft, ad injection, proxy infrastructure, or data exfiltration beyond documented services.

2. **Minimal permissions**: Only requests storage, identity, and system.display - all justified by functionality.

3. **No web page interaction**: Extension operates independently without content scripts, eliminating risks to user browsing.

4. **Standard third-party integrations**: Uses industry-standard tools (Firebase, Amplitude, Sentry) in expected ways.

5. **Privacy considerations**: Users should be aware that usage telemetry (including email and device ID) is collected by Amplitude for product analytics. This is disclosed in the extension's privacy practices.

### Recommendations:
- ✅ **SAFE for general use** - No immediate security concerns for users
- ⚠️ **Privacy notice**: Extension collects detailed usage analytics (email, device ID, interaction patterns)
- ℹ️ **Premium model**: Cloud backup requires paid license - standard freemium pattern
- 🔒 **Data security**: Notes are backed up to Firebase with OAuth authentication; users should trust Google's Firebase infrastructure

### No Action Required:
This extension does not warrant flagging, removal, or user warnings based on security grounds. Privacy-conscious users may prefer local-only note-taking apps without analytics.

---

## Conclusion

Sticky Notes 3.8 is a **CLEAN** extension from a security perspective. It implements a standard cloud-enabled note-taking service with appropriate authentication, analytics, and error tracking. No evidence of malicious intent, excessive data collection beyond stated features, or security vulnerabilities requiring remediation.

**Final Verdict**: ✅ **LOW RISK** - Safe for continued use with awareness of analytics data collection.
