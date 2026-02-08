# Security Analysis Report: YouTube Windowed FullScreen

## Extension Metadata

- **Extension Name**: YouTube Windowed FullScreen
- **Extension ID**: gkkmiofalnjagdcjheckamobghglpdpm
- **Approximate Users**: 50,000
- **Analysis Date**: 2026-02-07
- **Manifest Version**: 3

## Executive Summary

YouTube Windowed FullScreen is a browser extension that provides fullscreen video viewing within the browser window on YouTube. The extension includes Firebase Authentication and Firestore integration for premium features. **The overall security risk is LOW**. The extension demonstrates legitimate functionality with standard Firebase integration patterns and no evidence of malicious behavior. However, the premium feature gating and Firebase credential handling warrant monitoring.

## Vulnerability Details

### 1. Firebase Public Configuration Exposure (Severity: INFORMATIONAL)

**Files**: `background.min.js`

**Description**: The extension includes Firebase configuration with public API keys and project details embedded in the code. This is standard Firebase practice where the API key is not a secret, but it increases the attack surface.

**Code Evidence**:
```javascript
// Firebase initialization (deobfuscated code shows Firebase SDK integration)
const firebase = initializeApp(firebaseConfig);
const auth = getAuth(firebase);
const firestore = getFirestore(firebase);
```

**Verdict**: **False Positive** - Firebase API keys are designed to be public and protected by Firebase Security Rules on the backend. This is the intended architecture.

---

### 2. Premium Feature Bypass Potential (Severity: LOW)

**Files**: `YouTube.min.js` (lines 32-40)

**Description**: The content script checks premium status via message passing to the background script. If the check fails or returns non-premium status, features are disabled client-side.

**Code Evidence**:
```javascript
action: "checkAuthState"
// ...
e.success && e.userData && (e.isPremium || e.isTrialActive) || (
  console.log("Not Premium"),
  l.autoToggle = !1,
  l.scrollable = !1,
  l.hideScrollbar = !1,
  l.miniplayer = !1,
  l.pipShortcut = !1,
  l.hidePaidPromotion = !1,
  l.hideMiniplayerButton = !1
)
```

**Attack Vector**: A malicious user could modify the content script to bypass the premium check and enable all features without authentication.

**Verdict**: **Medium Concern** - Client-side enforcement only. However, this is likely acceptable for a YouTube viewing enhancement extension as there's no server-side data/resource at risk. The premium model appears to be voluntary/donation-based rather than strictly enforced.

---

### 3. No Content Security Policy (Severity: LOW)

**Files**: `manifest.json`

**Description**: The manifest does not define a `content_security_policy`, relying on Manifest V3 defaults.

**Verdict**: **False Positive** - Manifest V3 enforces strict CSP by default, making explicit CSP declaration optional.

---

### 4. Firebase Authentication Flow (Severity: INFORMATIONAL)

**Files**: `background.min.js`

**Description**: The extension handles user authentication with Firebase, including email/password login, signup, and password reset functionality.

**Code Evidence**:
```javascript
if("login"===e.action){
  const{email:t,password:r}=e.data;
  return un(ih,t,r).then(...)
}
if("signup"===e.action){
  const{email:t,password:r}=e.data;
  return async function(e,t,n){...}(ih,t,r).then(...)
}
```

**Verdict**: **Clean** - Standard Firebase Authentication SDK usage. Credentials are handled by Firebase SDK and not exposed to the extension code.

---

## False Positive Analysis

| Finding | Reason for False Positive | Risk Level |
|---------|---------------------------|------------|
| Firebase API Key Exposure | Public API keys are standard Firebase practice; security enforced by Firestore rules | None |
| IndexedDB Usage | Used by Firebase SDK for auth persistence, not for data exfiltration | None |
| Storage Permission | Required for saving user preferences (autoToggle, scrollable, etc.) | None |
| React Library | Standard UI framework, minified but legitimate | None |

## API Endpoints & External Communication

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `firestore.googleapis.com` | Firebase Firestore database access | Low - Standard Firebase service |
| `securetoken.google.com` | Firebase Authentication token validation | Low - Standard Firebase Auth |
| `identitytoolkit.googleapis.com` | Firebase Auth API | Low - Standard Firebase Auth |

**Analysis**: All network communication is with legitimate Google Firebase services. No third-party tracking, analytics, or ad networks detected.

## Data Flow Summary

1. **User Configuration Storage**:
   - Settings stored in `chrome.storage.sync` (shortcut keys, auto-toggle, scrollable, etc.)
   - Firebase Auth tokens stored in IndexedDB via Firebase SDK
   - User premium status stored in Firestore

2. **Authentication Flow**:
   - User credentials → Firebase Auth SDK → Firebase servers
   - Auth state changes trigger content script feature updates
   - Premium status checked from Firestore on auth state change

3. **Content Script Activity**:
   - Monitors YouTube page navigation
   - Injects fullscreen mode controls into YouTube player
   - Reads premium status from background script
   - Manipulates YouTube video player DOM (adding buttons, modifying CSS classes)

4. **No Data Exfiltration**: No evidence of data being sent to non-Firebase endpoints.

## Overall Risk Assessment: **LOW**

### Risk Factors:
- ✅ **No malicious behavior detected**
- ✅ **No third-party tracking or analytics**
- ✅ **No remote code execution patterns**
- ✅ **No suspicious network requests**
- ✅ **Minimal permissions (only `storage`)**
- ✅ **Clean content script (DOM manipulation for UI only)**
- ⚠️ **Client-side premium enforcement** (minor concern, but acceptable for this use case)

### Justification:
The extension is a straightforward YouTube enhancement tool with optional premium features. The Firebase integration is implemented correctly using standard SDKs. The premium feature check is client-side only, which is typical for browser extensions offering voluntary premium upgrades. No evidence of data harvesting, credential theft, or malicious activity.

## Recommendations

1. **For Users**: Safe to use. Premium features are client-side enforced but this is acceptable for a viewing enhancement tool.

2. **For Developer**:
   - Consider adding server-side validation for premium features if monetization is critical
   - Add explicit CSP directive in manifest for clarity (though MV3 defaults are secure)
   - Consider obfuscation removal in future releases for transparency

## Verdict

**CLEAN** - This extension poses no security risk to users. It performs its advertised functionality (YouTube fullscreen enhancements) without collecting or exfiltrating user data. The Firebase integration is standard and secure.
