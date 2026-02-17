# Security Analysis: Clear Cache

**Extension ID:** cppjkneekbjaeellbfkmgnhonkkjfpdn
**Version:** 2.3.4.4
**Risk Level:** MEDIUM
**Users:** ~1,000,000

## Executive Summary

Clear Cache is a browser cache management extension that offers both free and premium features. The extension implements a freemium business model with AWS Cognito authentication, Paddle payment processing, and periodic license validation. While the extension appears to be legitimate software from a commercial vendor, it exhibits unexpected network behavior for a "cache cleaner" utility and raises privacy concerns due to authentication token storage and periodic API communication.

**Key Findings:**
- Communicates with external API at `api.clearcache.io` for authentication and license validation
- Implements AWS Cognito-based user authentication with persistent token storage
- Uses Paddle.com for payment processing via sandboxed iframe
- Stores and transmits authentication session data via chrome.storage APIs
- Contains sandbox with `unsafe-eval` CSP policy for Paddle integration
- No evidence of malicious data exfiltration, but privacy implications from auth system

## Detailed Analysis

### 1. Network Communication & Exfiltration Flows

The ext-analyzer identified 4 exfiltration flows, all related to the premium licensing system:

#### Primary API Endpoint Configuration
```javascript
// From Logger-D9IM42jA.js (deobfuscated)
const ae = {
    VITE_API_NAME: "prod-clear-cache-Api",
    VITE_API_URL: "https://api.clearcache.io",
    VITE_PADDLE_API_URL: "https://api.paddle.com",
    VITE_PADDLE_TOKEN: "live_46d5a27538475e9f3da4fb14051",
    VITE_USER_POOL_CLIENT_ID: "6h57vqvod34l886jtjr8krut9e",
    VITE_USER_POOL_ID: "us-east-1_7zoIi1cKO",
    VITE_IDENTITY_POOL_ID: "us-east-1:3eb0088c-5f55-4e61-bde5-650f67bec1bd"
}
```

**Risk Assessment:** MEDIUM
**Rationale:** The extension connects to a legitimate business API for licensing, but this is unexpected behavior for a cache cleaning utility. Users installing a "cache cleaner" would not anticipate cloud authentication or persistent session tracking.

#### Flow 1 & 2: Authentication Session Updates
**Location:** `assets/options-DBDgYuc9.js` and `assets/Scheduler-D_832SPt.js`

```javascript
// Periodic auth session update
C(this, "update", async u => {
    // Loads session from chrome.storage.local/sync
    const session = await chrome.storage.local.get(SessionStorageKey);

    // Fetches fresh tokens from AWS Cognito
    b(this, K).aws.user = await yl();
    b(this, K).aws.session = await xl({forceRefresh: u});
    b(this, K).aws.attributes = await vl();

    // Stores updated tokens back to chrome.storage
    await chrome.storage.local.set({[SessionStorageKey]: session});
});
```

**Data Flow:**
1. chrome.storage.local.get('session') → retrieves auth tokens
2. fetch(AWS Cognito endpoints) → validates/refreshes tokens
3. fetch(api.clearcache.io/private/billing/validate) → validates subscription
4. chrome.storage.local.set() → stores updated session

**Scheduled Execution:**
- Every 30 minutes (AlarmUpdateSession)
- Every 6 hours (AlarmValidateSubscription)
- On extension startup
- When tokens are expiring

**Risk Assessment:** MEDIUM
**Rationale:** The extension maintains persistent authentication state and periodically phones home. While this is standard for subscription software, it creates a persistent tracking mechanism.

#### Flow 3 & 4: License Activation/Deactivation
**Location:** `assets/Scheduler-D_832SPt.js`

```javascript
C(this, "activate", async (licenseKey, clientId) => {
    const headers = {
        "x-client-id": clientId
    };
    return await fetch(
        `${Ce.apiUrl}/public/licenses/activate/${licenseKey}`,
        {method: 'POST', headers}
    );
});

C(this, "deactivate", async (licenseKey, clientId) => {
    const headers = {
        "x-client-id": clientId
    };
    return await fetch(
        `${Ce.apiUrl}/public/licenses/deactivate/${licenseKey}`,
        {method: 'POST', headers}
    );
});
```

**Risk Assessment:** LOW
**Rationale:** Standard license management functionality. The client ID appears to be a device identifier, not sensitive user data.

### 2. Content Security Policy - Sandbox with unsafe-eval

**Location:** `manifest.json` line 50

```json
"content_security_policy": {
    "sandbox": "sandbox allow-scripts allow-forms allow-popups allow-modals;
                script-src 'self' 'unsafe-inline' 'unsafe-eval'
                https://cdn.paddle.com https://buy.paddle.com
                https://clearcache.io/checkout/index.html;"
}
```

**Purpose:** The sandbox is used to load Paddle.com's payment processing SDK, which requires `unsafe-eval` to function.

**Risk Assessment:** LOW
**Rationale:** While `unsafe-eval` is generally discouraged, it's isolated to a sandboxed context with restricted permissions. The sandbox cannot access chrome APIs or the main extension context. This is a common pattern for embedding third-party payment SDKs.

**Affected Files:**
- `pages/sandbox/index.html` - Main sandbox page
- `pages/offscreen/sandbox/index.html` - Offscreen sandbox variant
- `assets/sandbox-BrYD77S6.js` - Sandbox bridge code

### 3. AWS Cognito Integration

The extension implements full AWS Cognito authentication:

**Components:**
1. **User Pool:** `us-east-1_7zoIi1cKO`
2. **Identity Pool:** `us-east-1:3eb0088c-5f55-4e61-bde5-650f67bec1bd`
3. **Client ID:** `6h57vqvod34l886jtjr8krut9e`

**Authentication Flow:**
```javascript
// Email-based passwordless auth
C(this, "signUp", async (email, termsAcceptedAt) => {
    return await pl({
        username: email,
        password: this.generateRandomPassword(30),
        options: {
            userAttributes: {
                [Ce.aws.cognito.TERMS_ACCEPTED_AT_ATTR_NAME]: termsAcceptedAt
            }
        }
    });
});

C(this, "signIn", async email => {
    return bl({
        username: email,
        options: {
            authFlowType: "CUSTOM_WITHOUT_SRP"
        }
    });
});

C(this, "confirmSignIn", async code => {
    return await ml({challengeResponse: code});
});
```

**Stored Authentication Data:**
```javascript
// From chrome.storage.local
{
    session: {
        loggedIn: boolean,
        username: string (email),
        aws: {
            user: { userId, signInDetails },
            session: { tokens: { idToken, accessToken, refreshToken } },
            attributes: { email, "custom:customerId" }
        },
        paddle: {
            pwCustomer: { id, email }
        },
        license: {
            licenseKey, clientId
        }
    }
}
```

**Risk Assessment:** MEDIUM
**Rationale:**
- Authentication tokens grant persistent API access to clearcache.io
- Tokens are stored in chrome.storage.local (unencrypted browser storage)
- User email addresses are collected and stored
- Creates a tracking mechanism tied to user identity
- Unexpected for a cache cleaning utility

### 4. Premium Feature Gating

The extension restricts certain cache clearing features to paid users:

```javascript
// From Scheduler-D_832SPt.js - Data type definitions
C(z, "AppCache", new z("appcache", "App Cache", {
    supportsOrigins: true,
    requiresPlus: true  // Requires premium
}));
C(z, "Cache", new z("cache", "Cache", {
    supportsOrigins: true,
    requiresPlus: true  // Requires premium
}));
C(z, "CacheStorage", new z("cacheStorage", "Cache Storage", {
    supportsOrigins: true,
    requiresPlus: true  // Requires premium
}));
C(z, "Cookies", new z("cookies", "Cookies", {
    supportsOrigins: true,
    requiresPlus: false  // Free feature
}));
```

**Premium-gated features:**
- Advanced cache clearing (App Cache, Cache Storage)
- Origin-specific data removal
- IndexedDB clearing
- Local Storage clearing
- File Systems clearing
- Service Worker clearing
- WebSQL clearing

**Risk Assessment:** LOW (Transparency Issue)
**Rationale:** The free version appears to have limited cache clearing capabilities. This is legitimate software monetization, but the CWS listing should clearly indicate this is freemium software.

### 5. Payment Processing via Paddle

The extension uses Paddle.com as a payment processor, loaded in a sandboxed iframe:

**Integration Points:**
```javascript
// Manifest CSP allows Paddle domains
"script-src 'self' 'unsafe-inline' 'unsafe-eval'
    https://cdn.paddle.com
    https://buy.paddle.com
    https://clearcache.io/checkout/index.html"

// Optional permission for Paddle API
"optional_host_permissions": [
    "https://*.paddle.com/"
]
```

**Paddle Configuration:**
```javascript
paddle: {
    apiUrl: "https://api.paddle.com",
    token: "live_46d5a27538475e9f3da4fb14051",
    environment: "production"
}
```

**Risk Assessment:** LOW
**Rationale:** Paddle is a legitimate payment processor. The integration follows standard practices (sandboxed iframe, CSP restrictions). The exposed API token appears to be a public publishable key, not a secret.

### 6. Data Collection & Privacy Concerns

**Data Collected:**
1. **User email address** (via AWS Cognito)
2. **AWS Cognito user ID** (persistent identifier)
3. **Paddle customer ID** (stored in Cognito custom attributes)
4. **Device/Client ID** (for license activation)
5. **License key** (if premium user)
6. **Authentication tokens** (IdToken, AccessToken, RefreshToken)
7. **Terms acceptance timestamp**

**Data Storage:**
- chrome.storage.local (unencrypted)
- chrome.storage.sync (synced across devices, unencrypted)
- AWS Cognito backend

**Data Transmission:**
- Periodic auth token refresh (every 30 min)
- Subscription validation (every 6 hours)
- License activation/deactivation events

**Risk Assessment:** MEDIUM
**Rationale:**
- Collects more data than necessary for cache clearing functionality
- Creates persistent user tracking mechanism
- No evidence of privacy policy disclosure in extension code
- Users may not expect a cache cleaner to require email registration

## Vulnerability Summary

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 0 | None identified |
| HIGH | 0 | None identified |
| MEDIUM | 2 | Unexpected auth/tracking; unencrypted token storage |
| LOW | 1 | CSP unsafe-eval (justified, sandboxed) |

### MEDIUM-1: Unexpected Authentication & Tracking System

**Description:** The extension implements comprehensive user authentication and session management for a cache clearing utility. This creates a persistent tracking mechanism tied to user email addresses.

**Impact:**
- User behavior (cache clearing frequency, timing) could be tracked
- Email addresses are collected and stored
- Persistent device/user identification across sessions

**Recommendation:**
- Clearly disclose authentication requirement on Chrome Web Store listing
- Provide privacy policy explaining data collection and retention
- Consider anonymous license validation (no email required)
- Implement opt-out mechanism for free users

### MEDIUM-2: Unencrypted Authentication Token Storage

**Description:** AWS Cognito authentication tokens (IdToken, AccessToken, RefreshToken) are stored in chrome.storage.local without encryption.

**Impact:**
- Other extensions with storage permission could read tokens
- Malware on the system could extract tokens from browser profile
- Tokens grant full API access to user's clearcache.io account

**Recommendation:**
- Implement token encryption before storage
- Use shorter token lifetimes
- Implement token rotation on suspicious activity
- Consider session-only token storage (clear on browser close)

### LOW-1: Content Security Policy unsafe-eval

**Description:** The sandbox CSP includes `unsafe-eval`, which is generally discouraged.

**Impact:**
- Limited impact due to sandbox isolation
- Required for Paddle.com SDK functionality

**Recommendation:**
- No action required (justified use case)
- Continue monitoring Paddle SDK for security updates

## Positive Security Practices

1. **Manifest V3:** Extension uses modern Manifest V3 architecture
2. **Sandboxing:** Payment processing isolated in sandbox
3. **Optional Permissions:** Advanced features use optional permissions (scripting, tabs)
4. **CSP Restrictions:** Strict CSP for non-sandbox contexts
5. **Legitimate Business:** Appears to be commercial software from established vendor
6. **No Code Injection:** No evidence of remote code execution or dynamic script loading
7. **Transparent Monetization:** Premium features clearly gated (though could be more transparent)

## Recommendations

### For Users:
1. **Understand the model:** This is freemium software requiring email registration for premium features
2. **Privacy consideration:** Your email and cache clearing patterns may be tracked
3. **Alternatives:** Consider browser built-in cache clearing or extensions without authentication
4. **Free tier limitations:** Be aware that advanced cache clearing requires premium subscription

### For Developer:
1. **Transparency:** Update Chrome Web Store listing to clearly indicate freemium model
2. **Privacy Policy:** Link to privacy policy in manifest and options page
3. **Token Security:** Implement encryption for stored authentication tokens
4. **Minimal Data:** Consider reducing data collection to only what's necessary
5. **Anonymous Option:** Offer anonymous usage for basic cache clearing
6. **Disclosure:** Clearly state when authentication/network calls occur

### For Chrome Web Store Review:
1. **Verify listing accuracy:** Ensure freemium model is disclosed
2. **Privacy policy requirement:** Confirm privacy policy exists and is linked
3. **Permissions justification:** Validate that permissions match functionality
4. **User expectations:** Ensure listing manages user expectations about authentication

## Conclusion

Clear Cache appears to be **legitimate commercial software** from a vendor operating a freemium business model. The network communication and authentication flows are **intentional features** of the premium licensing system, not malicious data exfiltration.

**However**, the extension exhibits behavior that may be unexpected for users installing a "cache cleaner":
- Requires email registration for premium features
- Implements persistent user tracking via AWS Cognito
- Periodically communicates with vendor API
- Stores authentication tokens in browser storage

**Final Risk Assessment: MEDIUM**

The medium risk rating reflects:
- Privacy concerns from authentication/tracking system
- Unencrypted token storage
- Potential transparency issues in Chrome Web Store listing
- Unexpected behavior for stated purpose

This is **NOT malware**, but users should be aware they're installing freemium software with cloud authentication, not a simple local cache clearing utility.

## Technical Artifacts

### API Endpoints Contacted:
- `https://api.clearcache.io/public/licenses/activate/{key}` (POST)
- `https://api.clearcache.io/public/licenses/deactivate/{key}` (POST)
- `https://api.clearcache.io/private/billing/validate` (GET)
- AWS Cognito endpoints (via Amplify SDK)
- `https://api.paddle.com` (payment processing)

### Chrome Storage Keys:
- `session` - Authentication session data
- `auth` - AWS Cognito auth storage
- `auth_backup` - Auth storage backup
- `config` - Extension configuration
- `lastLaunchVersion` - Version tracking

### Alarm Schedules:
- `backgroundUpdateSession` - Every 30 minutes
- `backgroundValidateSubscription` - Every 6 hours

### AWS Resources:
- User Pool: `us-east-1_7zoIi1cKO`
- Identity Pool: `us-east-1:3eb0088c-5f55-4e61-bde5-650f67bec1bd`
- API Gateway: `prod-clear-cache-Api` at `api.clearcache.io`
