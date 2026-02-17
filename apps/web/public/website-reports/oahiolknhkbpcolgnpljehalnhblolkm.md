# Vulnerability Report: ShortsBlocker - Remove Shorts from YouTube

## Extension Metadata
- **Extension Name**: ShortsBlocker - Remove Shorts from YouTube
- **Extension ID**: oahiolknhkbpcolgnpljehalnhblolkm
- **User Count**: ~100,000 users
- **Version**: 3.6.0
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

ShortsBlocker is a Chrome extension that removes YouTube Shorts from the user's YouTube experience. The extension implements a **freemium business model with external authentication and payment processing**. While the core functionality (blocking YouTube Shorts) appears legitimate, the extension exhibits **multiple security and privacy concerns** related to plaintext password storage, broad permissions, and external API dependencies.

**Overall Risk Level: MEDIUM**

The extension does not appear to contain malicious code intended to harm users, but it has significant security design flaws that could expose user credentials and create privacy risks.

## Vulnerability Details

### 1. PLAINTEXT PASSWORD STORAGE (CRITICAL SEVERITY)

**Severity**: CRITICAL
**Files**: `popup.js` (lines 1316, 1439)
**CWE**: CWE-256 (Unprotected Storage of Credentials)

**Description**:
The extension stores user passwords in **plaintext** in Chrome's sync storage for token refresh functionality. This is a severe security vulnerability.

**Evidence**:
```javascript
// Line 1316 in popup.js - Login form
const userAuth = {
  uid: userData.uid,
  email: userData.email,
  name: userData.name,
  token: userData.token,
  password: password, // Store password for token refresh
  is_premium: userData.is_premium || false,
  loginDate: new Date().toISOString()
};

// Line 1439 in popup.js - Signup form
const userAuth = {
  uid: userData.uid,
  email: userData.email,
  name: userData.name,
  token: userData.token,
  password: password, // Store password for token refresh
  is_premium: userData.is_premium || false,
  registrationDate: new Date().toISOString()
};

// Lines 8-26 in background.js - Password used for token refresh
async function refreshToken(userAuth) {
  if (!userAuth?.email || !userAuth?.password) return null;

  try {
    const response = await fetch(`${API_BASE_URL}/api/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userAuth.email, password: userAuth.password })
    });
    // ...
  }
}
```

**Impact**:
- User passwords are stored in **chrome.storage.sync**, which syncs across all Chrome instances
- Any malicious extension with `storage` permission can read these passwords
- If Chrome sync is compromised, passwords are exposed
- Passwords can be used to access user accounts on `king-prawn-app-2-zoebq.ondigitalocean.app`

**Verdict**: CONFIRMED VULNERABILITY - This is a critical security flaw that violates basic credential storage best practices.

---

### 2. BROAD CONTENT SCRIPT INJECTION (HIGH SEVERITY)

**Severity**: HIGH
**Files**: `manifest.json` (lines 17-24)
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**:
The extension injects content scripts on **ALL URLs** (`<all_urls>`), not just YouTube domains.

**Evidence**:
```json
"content_scripts": [
  {
    "matches": ["<all_urls>"],
    "js": ["/assets/index.js"],
    "css": ["styles.css"],
    "run_at": "document_end"
  }
]
```

**Impact**:
- Content script runs on every website the user visits
- Increases attack surface unnecessarily
- Potential for data leakage from non-YouTube sites
- Performance impact on all browsing

**Mitigation**: The extension appears to check for YouTube domains in the content script (lines 2823-2826 in assets/index.js), but this is insufficient. The permission should be restricted at the manifest level.

**Verdict**: CONFIRMED VULNERABILITY - Violates principle of least privilege.

---

### 3. EXTERNAL API DEPENDENCY & CREDENTIAL TRANSMISSION (MEDIUM SEVERITY)

**Severity**: MEDIUM
**Files**: `background.js` (line 1), `popup.js` (line 5)
**CWE**: CWE-319 (Cleartext Transmission of Sensitive Information - if not HTTPS)

**Description**:
The extension relies on an external API hosted at `king-prawn-app-2-zoebq.ondigitalocean.app` for authentication, premium status checks, and payment processing.

**Evidence**:
```javascript
// background.js line 1, popup.js line 5
const API_BASE_URL = 'https://king-prawn-app-2-zoebq.ondigitalocean.app';

// API endpoints called:
// - /api/auth/signin (POST) - email/password authentication
// - /api/auth/signup (POST) - user registration
// - /api/auth/premium-status (GET) - premium subscription check
// - /api/auth/profile (GET) - user profile fetch
// - /api/payments/create-checkout-session (POST) - Stripe checkout
// - /api/payments/customer-portal (POST) - Stripe customer portal
```

**Concerns**:
- Users must trust a third-party backend server
- Credentials (email/password) are transmitted to external server
- Backend server could be compromised or log credentials
- No transparency about backend data handling practices
- DigitalOcean app platform hosting may not have robust security guarantees

**Impact**:
- User credentials are sent to external server over network
- Premium status checks occur frequently (every 1-4 hours based on user tier)
- Dependency on external service availability
- User data subject to backend's security practices

**Verdict**: DESIGN CONCERN - While HTTPS is used, relying on external authentication with stored passwords creates inherent risks.

---

### 4. AGGRESSIVE PREMIUM STATUS POLLING (LOW SEVERITY)

**Severity**: LOW
**Files**: `background.js` (lines 3-6, 92-101, 104-126)
**CWE**: N/A (Privacy/Performance concern)

**Description**:
The extension frequently polls the external API to check premium status, especially for free users.

**Evidence**:
```javascript
// background.js lines 3-5
const FREE_USER_CHECK_INTERVAL_MS = 60000;        // 1 minute for free users
const PREMIUM_USER_CHECK_INTERVAL_MS = 4 * 60 * 60 * 1000; // 4 hours for premium

// Lines 92-101 - Check on tab activation
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url?.includes('youtube.com')) {
      checkAndUpdatePremiumStatus();
    }
  } catch (e) {
    console.error('[ShortsBlocker] onActivated error:', e);
  }
});

// Lines 115-118 - Check on YouTube navigation
if (tab?.url?.includes('youtube.com')) {
  checkAndUpdatePremiumStatus();
}
```

**Impact**:
- Free users: Premium status checked every 60 seconds when on YouTube
- Premium users: Checked every 4 hours
- Creates network traffic and potential tracking capability
- Backend can monitor user activity patterns based on check frequency

**Verdict**: MINOR CONCERN - Frequent polling may indicate user upgrade, but creates unnecessary network traffic and potential privacy issues.

---

### 5. POST-INSTALL REDIRECT TO DONATION PAGE (LOW SEVERITY)

**Severity**: LOW
**Files**: `background.js` (lines 127-132)
**CWE**: N/A (UX concern)

**Description**:
The extension automatically opens a donation page on installation.

**Evidence**:
```javascript
chrome.runtime.onInstalled.addListener(details => {
  if (details.reason == "install") {
    let externalUrl = "https://ravensmove.com/shortsblocker-donation/";
    chrome.tabs.create({ url: externalUrl });
  }
});
```

**Impact**:
- Unexpected behavior for users
- Opens external website without explicit consent
- Could be perceived as intrusive or misleading

**Verdict**: MINOR CONCERN - Common monetization practice, but not ideal UX.

---

### 6. TAB PERMISSION USAGE (LOW SEVERITY)

**Severity**: LOW
**Files**: `manifest.json` (line 8)
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**:
The extension requests the `tabs` permission, which grants access to sensitive tab information.

**Evidence**:
```json
"permissions": ["storage", "tabs"]
```

**Usage Analysis**:
- Used to query YouTube tabs for premium status checks (background.js lines 77, 94)
- Used to reload tabs when settings change (popup.js lines 8-14)
- Used to open checkout/portal URLs (popup.js lines 1908, 1972)

**Verdict**: LOW RISK - The `tabs` permission usage appears justified for the extension's functionality, though it could potentially be reduced with more targeted approaches.

---

## False Positive Analysis

| Pattern Detected | File | Verdict | Reason |
|------------------|------|---------|--------|
| `fetch()` calls | assets/index.js line 39 | FALSE POSITIVE | Module preload for performance, not data exfiltration |
| `chrome.runtime.sendMessage` | assets/index.js line 2688 | FALSE POSITIVE | Legitimate inter-component communication for opening popup |
| `chrome.storage.onChanged` | assets/index.js line 2860 | FALSE POSITIVE | Standard storage listener for settings synchronization |
| `MutationObserver` | assets/index.js lines 2769-2775, 2840-2845 | FALSE POSITIVE | Used to detect YouTube page changes for Shorts blocking |
| Svelte framework code | assets/index.js (majority) | FALSE POSITIVE | Legitimate UI framework code, heavily obfuscated by bundler |

---

## API Endpoints Summary

| Endpoint | Method | Purpose | Auth Required | Data Sent |
|----------|--------|---------|---------------|-----------|
| `/api/auth/signin` | POST | User authentication | No | email, password (plaintext) |
| `/api/auth/signup` | POST | User registration | No | email, password, name |
| `/api/auth/premium-status` | GET | Check premium subscription | Yes (Bearer token) | None |
| `/api/auth/profile` | GET | Fetch user profile | Yes (Bearer token) | None |
| `/api/payments/create-checkout-session` | POST | Create Stripe checkout | Yes (Bearer token) | plan_type, success_url, cancel_url |
| `/api/payments/customer-portal` | POST | Open Stripe customer portal | Yes (Bearer token) | return_url |

**Base URL**: `https://king-prawn-app-2-zoebq.ondigitalocean.app`

---

## Data Flow Summary

### User Credentials Flow
1. User enters email/password in popup
2. Credentials sent to `https://king-prawn-app-2-zoebq.ondigitalocean.app/api/auth/signin` via HTTPS POST
3. JWT token returned from server
4. **Password stored in chrome.storage.sync in plaintext** along with token
5. Password reused for token refresh operations

### Premium Status Flow
1. Background script checks premium status on:
   - YouTube tab activation
   - YouTube page navigation
   - Return from Stripe checkout
2. Token refreshed using **stored plaintext password**
3. Premium status fetched from `/api/auth/premium-status`
4. Settings updated in chrome.storage.sync

### Payment Flow
1. User clicks "Subscribe" in popup
2. Token refreshed (if needed)
3. Checkout session created via `/api/payments/create-checkout-session`
4. User redirected to Stripe checkout page
5. On return, premium status force-checked (2-second delay for webhook)

### Content Blocking Flow
1. Content script injected on ALL pages (despite only needing YouTube)
2. MutationObserver watches for YouTube Shorts elements
3. Shorts blocked based on:
   - Extension enabled state
   - Premium settings (daily limit, schedule, whitelist)
   - Channel whitelist status

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Rationale**:
- **CRITICAL** plaintext password storage issue
- **HIGH** unnecessary broad permissions (`<all_urls>`)
- **MEDIUM** external API dependency with credential transmission
- **LOW** aggressive polling and minor UX concerns
- **NO EVIDENCE** of malicious intent, data exfiltration, or backdoors

### Key Security Issues:
1. ✅ Passwords stored in plaintext in sync storage (CRITICAL)
2. ✅ Content scripts injected on all websites unnecessarily (HIGH)
3. ✅ External authentication server dependency (MEDIUM)
4. ✅ Frequent premium status polling for tracking/analytics (LOW)

### Mitigating Factors:
- No evidence of malicious code or hidden functionality
- HTTPS used for all network communications
- Legitimate business model (freemium with Stripe payments)
- Core functionality (blocking YouTube Shorts) is straightforward
- No attempts to access sensitive user data beyond authentication

### User Impact:
- **~100,000 users** potentially affected
- Users with accounts have passwords stored insecurely
- All users subject to broad permission scope
- Premium users have payment data processed through Stripe (external)

---

## Recommendations

### For Extension Developer:
1. **URGENT**: Replace plaintext password storage with:
   - OAuth 2.0 authentication flow
   - Refresh token mechanism (without password storage)
   - Or remove automatic token refresh entirely
2. **HIGH PRIORITY**: Restrict content script injection to YouTube domains only:
   ```json
   "matches": ["*://*.youtube.com/*"]
   ```
3. **MEDIUM PRIORITY**: Implement backend session management to reduce polling frequency
4. **LOW PRIORITY**: Make post-install redirect optional or request user consent

### For Users:
1. If you have created an account, consider changing your password on any other services where you use the same password
2. Review what other extensions have access to your storage
3. Monitor for unexpected behavior when browsing non-YouTube sites
4. Consider whether the premium features justify the security trade-offs

---

## Conclusion

ShortsBlocker is a **functional extension with legitimate purpose** but suffers from **critical security design flaws**, particularly around credential management. The plaintext password storage issue alone warrants a **MEDIUM overall risk rating** despite no evidence of malicious intent. The extension would benefit significantly from implementing proper authentication patterns (OAuth, refresh tokens) and restricting its permissions to only what's necessary (YouTube domains only).

The developer appears to be operating a legitimate freemium business, but the security implementation needs significant improvement to protect the ~100,000 users who have installed this extension.
