# Security Analysis: Roblox+ (jfbnmfgkohlfclfnplnlenbalpppohkm)

## Extension Metadata
- **Name**: Roblox+
- **Extension ID**: jfbnmfgkohlfclfnplnlenbalpppohkm
- **Version**: 3.27.0
- **Manifest Version**: 3
- **Estimated Users**: ~1,000,000
- **Developer**: WebGL3D
- **Homepage**: https://roblox.plus/settings
- **Analysis Date**: 2026-02-15

## Executive Summary
Roblox+ is a legitimate feature enhancement extension for Roblox.com with **LOW RISK** status. The extension provides quality-of-life improvements to the Roblox website, including enhanced UI features, premium membership tracking, trade notifications, friend presence monitoring, and catalog item notifications. Analysis revealed limited third-party API integration with the developer's backend (api.roblox.plus) for premium features and push notification services, but no malicious behavior or unauthorized data exfiltration. The extension uses appropriate permissions and follows secure coding practices for a Manifest V3 extension.

**Overall Risk Assessment: LOW**

## Vulnerability Assessment

### 1. Third-Party API Integration (Information Disclosure)
**Severity**: Low
**Files**:
- `/js/services/premium/getPremiumExpirationDate.ts` (lines 108-122)
- `/js/service-worker/notifiers/catalog/index.ts` (lines 26-51)

**Analysis**:
The extension integrates with the developer's API at `api.roblox.plus` for two purposes: premium membership validation and catalog item notification registration.

**Code Evidence** (`getPremiumExpirationDate.ts`, line 108):
```javascript
const response = await fetch(
  `https://api.roblox.plus/v1/rpluspremium/${userId}`
);

if (!response.ok) {
  throw new Error(`Failed to check premium membership for user (${userId})`);
}

const result = await response.json();
if (result.data) {
  return (definitelyPremium[userId] = result.data.expiration);
}
```

**Code Evidence** (`catalog/index.ts`, lines 29-36):
```javascript
fetch('https://api.roblox.plus/v2/itemnotifier/registertoken', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: `robloxUserId=${
    authenticatedUser?.id
  }&token=${encodeURIComponent(token)}`,
})
```

**Data Transmitted**:
1. **Premium Check**: User's Roblox ID (read from authenticated session)
2. **Notification Registration**: User's Roblox ID + Firebase Cloud Messaging (FCM) token

**Purpose**:
- Premium check validates if user has purchased Roblox+ Premium (via private server subscription)
- FCM token registration enables push notifications for new catalog items from followed creators

**Privacy Considerations**:
- User ID is semi-public information (visible in Roblox URLs)
- FCM token is ephemeral and only used for push notifications
- No browsing history, cookies, or sensitive credentials transmitted
- API domain matches extension developer's homepage (roblox.plus)

**Mitigating Factors**:
- Both features are user-facing and documented functionality
- Premium check also validates locally via Roblox API first (checkPrivateServerExpirations)
- Catalog notifications require user to enable "itemNotifier" setting (opt-in)
- Token refresh limited to 30-minute intervals

**Recommendation**: Users should be aware the extension communicates with third-party backend for premium/notification features.

**Verdict**: **LOW RISK** - Limited data sharing for legitimate documented features.

---

### 2. Authenticated User Data Access (Expected Behavior)
**Severity**: N/A (Not a Vulnerability)
**Files**:
- `/js/utils/authenticatedUser.ts` (lines 1-24)
- `/js/services/users/getAuthenticatedUser.ts` (lines 14-41)

**Analysis**:
The extension reads the authenticated user's data from the Roblox page to provide personalized features.

**Code Evidence** (`authenticatedUser.ts`, lines 4-15):
```javascript
const parseAuthenticatedUser = (): User | null => {
  const userData =
    globalThis.document && document.querySelector(`meta[name='user-data']`);

  return userData
    ? {
        id: Number(userData.getAttribute('data-userid')),
        name: userData.getAttribute('data-name') || '',
        displayName: userData.getAttribute('data-displayname') || '',
      }
    : null;
};
```

**Data Accessed**:
- User ID, username, and display name from DOM `<meta>` tag
- Additional validation via Roblox API: `users.roblox.com/v1/users/authenticated`

**Usage**:
- Personalizing UI elements (navigation bar, balance display)
- Filtering notifications (only show for followed creators)
- Premium feature validation
- Trade/friend presence notifications

**Safety Indicators**:
- Data read from page's own DOM elements (already visible to user)
- Roblox API calls use `credentials: 'include'` to leverage existing session
- No credential interception or cookie theft
- Data cached locally for 60 seconds only
- No transmission to third parties (except user ID to api.roblox.plus as noted above)

**Verdict**: **NOT MALICIOUS** - Standard practice for browser extensions enhancing authenticated websites.

---

### 3. CSRF Token Handling
**Severity**: N/A (Security Enhancement)
**Files**: `/js/utils/xsrfFetch.ts` (lines 1-46)

**Analysis**:
The extension implements CSRF token management for POST requests to Roblox APIs.

**Code Evidence** (`xsrfFetch.ts`, lines 21-37):
```javascript
if (xsrfToken) {
  requestDetails.headers.set(headerName, xsrfToken);
}

// ...retry logic...

const token = response.headers.get(headerName);
if (response.ok || !token) {
  return response;
}

xsrfToken = token;
```

**Mechanism**:
1. Captures `X-CSRF-Token` from Roblox API responses
2. Attaches token to subsequent POST/PUT/DELETE requests
3. Automatically retries failed requests with updated token

**Purpose**: Enables extension to make authenticated API calls (avatar changes, inventory actions, etc.) without breaking Roblox's CSRF protection.

**Safety Indicators**:
- Token only used for Roblox API endpoints (scoped to `*.roblox.com`)
- Token never transmitted to third parties
- Uses `credentials: 'include'` to maintain same-origin security model
- Standard CSRF token pattern used by web applications

**Verdict**: **NOT MALICIOUS** - Proper security token handling for API integration.

---

### 4. Firebase Cloud Messaging Integration
**Severity**: N/A (Expected Behavior)
**Files**: `/js/service-worker/notifiers/catalog/index.ts` (lines 6-220)

**Analysis**:
The extension uses Chrome's deprecated `chrome.instanceID` and `chrome.gcm` APIs for push notifications via Firebase Cloud Messaging.

**Code Evidence** (`catalog/index.ts`, lines 26-28):
```javascript
chrome.instanceID.getToken(
  { authorizedEntity: '303497097698', scope: 'FCM' },
  (token: string) => {
    // Register token with api.roblox.plus
  }
)
```

**FCM Project ID**: `303497097698` (Google Cloud project owned by extension developer)

**Notification Topics**:
- `/topics/catalog-notifier` (general catalog updates)
- `/topics/catalog-notifier-premium` (premium catalog notifications)

**Data Flow**:
1. Extension requests FCM token from Chrome
2. Token sent to `api.roblox.plus/v2/itemnotifier/registertoken` with user ID
3. Server subscribes token to FCM topics
4. Server sends FCM messages when new catalog items released
5. Extension displays Chrome notification if user follows item creator

**Notification Validation** (lines 173-185):
```javascript
chrome.notifications.onClicked.addListener((notificationId) => {
  const url = notificationId.substring(notificationIdPrefix.length);
  if (!url.startsWith('https://www.roblox.com/')) {
    console.warn('Skipped opening URL for notification because it was not for roblox.com');
    return;
  }
  chrome.tabs.create({ url, active: true });
});
```

**Safety Indicators**:
- URL validation prevents opening arbitrary websites
- Notifications only shown if user follows creator (via `isAuthenticatedUserFollowing()`)
- Feature requires opt-in via "itemNotifier" setting
- Token refresh throttled to 30-minute intervals
- No message content logging or storage

**Privacy Note**: Developer's backend receives FCM token and user ID, enabling them to send notifications. This is standard for push notification services but represents a trust relationship with the developer.

**Verdict**: **NOT MALICIOUS** - Standard push notification implementation for catalog updates.

---

### 5. External Message Handling
**Severity**: N/A (False Positive)
**Files**:
- `/libs/extension-messaging/dist/index.js` (lines 185-187)
- `/js/services/premium/getPremiumExpirationDate.ts` (line 136)

**Analysis**:
The static analyzer flagged "open message handlers" due to the `allowExternalConnections` parameter in message listeners.

**Code Evidence** (`getPremiumExpirationDate.ts`, lines 125-138):
```javascript
addListener(
  messageDestination,
  (message: BackgroundMessage) => {
    return cache.getOrAdd(`${message.userId}`, () =>
      loadPremiumMembership(message.userId)
    );
  },
  {
    levelOfParallelism: 1,
    allowExternalConnections: true,
  }
);
```

**Investigation**:
The `allowExternalConnections` flag is defined in the extension's internal messaging library but **does not** expose the extension to arbitrary external websites. Review of `extension-messaging/dist/index.js` shows:

1. External messages require sender to have `extensionId` set via injected script
2. No `externally_connectable` directive in manifest.json
3. No web-accessible message bridge scripts
4. Only internal content scripts can communicate with background

**Conclusion**: The `allowExternalConnections` parameter is a misnomer in the library's API. It enables messaging between content scripts and background, not external webpage-to-extension communication.

**Verdict**: **FALSE POSITIVE** - Internal messaging only, no external attack surface.

---

### 6. Obfuscation Detection (False Positive)
**Severity**: N/A
**Static Analyzer Report**: `"hasObfuscation": true`

**Analysis**:
The static analyzer flagged obfuscation likely due to webpack bundling artifacts in the compiled JavaScript.

**Evidence**:
- Source code shows clear TypeScript/JavaScript with readable variable names
- Webpack bootstrap code (`/******/ (() => { // webpackBootstrap`) may trigger heuristics
- All functions and variables have semantic names (`getAuthenticatedUser`, `loadPremiumMembership`, etc.)
- No string encoding, control flow flattening, or variable name mangling

**Code Quality**: The extension appears to be professionally developed TypeScript compiled via webpack, not intentionally obfuscated.

**Verdict**: **FALSE POSITIVE** - Webpack bundling, not malicious obfuscation.

---

## Network Analysis

### Roblox API Endpoints (Legitimate)
The extension makes authenticated requests to official Roblox API domains:

| Domain | Purpose | Sensitive Data |
|--------|---------|----------------|
| `users.roblox.com` | Get authenticated user info, user lookups | User ID, username |
| `economy.roblox.com` | Robux balance, asset details, transactions | Currency balance |
| `games.roblox.com` | Private server details, game info | VIP server subscriptions |
| `avatar.roblox.com` | Avatar data, outfit changes | Avatar asset IDs |
| `inventory.roblox.com` | User inventory, collectibles | Asset ownership |
| `friends.roblox.com` | Friend list, friend requests | Social graph |
| `presence.roblox.com` | Friend online status | User activity |
| `trades.roblox.com` | Trade notifications | Trade offers |
| `badges.roblox.com` | Badge ownership | Achievement data |
| `groups.roblox.com` | Group memberships | Group affiliations |
| `thumbnails.roblox.com` | Asset thumbnails | Public image URLs |
| `privatemessages.roblox.com` | Unread message count | Message metadata |
| `assetdelivery.roblox.com` | Asset file downloads | Asset content |
| `locale.roblox.com` | User locale settings | Language preference |
| `translations.roblox.com` | UI translations | N/A |
| `develop.roblox.com` | Creator groups | Development permissions |

**Security Posture**: All Roblox API calls use existing session cookies (`credentials: 'include'`) and CSRF tokens. No credentials are stored or intercepted.

### Third-Party Endpoints
| Domain | Purpose | Data Sent | Risk |
|--------|---------|-----------|------|
| `api.roblox.plus` | Premium validation, FCM registration | User ID, FCM token | Low |

**Risk Assessment**: The third-party API is operated by the extension developer (roblox.plus domain matches homepage). Data sent is minimal and directly related to documented features.

---

## Permission Analysis

### Declared Permissions
| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `alarms` | Schedule periodic tasks (token refresh, notifier checks) | Low |
| `gcm` | Firebase Cloud Messaging for push notifications | Low |
| `notifications` | Display catalog/trade/friend notifications | Low |
| `storage` | Cache user preferences and API responses | Low |

### Host Permissions
| Host Pattern | Justification | Risk Level |
|--------------|---------------|------------|
| `https://*.roblox.com/*` | Access Roblox website and APIs | Low |
| `https://*.roblox.plus/*` | Access developer's premium/notification backend | Low |
| `https://*.rbxcdn.com/*` | Access Roblox CDN for asset thumbnails | Low |

**Assessment**: Permissions are appropriate for stated functionality. No overprivileged patterns detected.

---

## Data Flow Analysis

### Static Analyzer Report Summary
```
Exfiltration Flows: 1 (FALSE POSITIVE)
Code Execution Flows: 0
Risk Score: 25 (Low)
```

### Flow Investigation: pageContent → fetch
**Analyzer Report**:
```
SOURCE: document.getElementById('nav-robux-balance') [line 35967]
TRANSFORM: devexBalance = value * devexRate [line 35998]
SINK: fetch(`https://games.roblox.com/v1/vip-servers/${id}`) [line 37278]
```

**Analysis**:
The static analyzer traced data from `document.getElementById()` to a `fetch()` call, flagging potential exfiltration. Manual inspection reveals this is a **false positive**:

1. **Source Context** (line 35967): Reading Robux balance from navigation bar DOM element
2. **Transform Context** (line 35998): Converting Robux to USD equivalent for DevEx display (UI feature)
3. **Sink Context** (line 37278): Fetching VIP server details from Roblox API

**Reality**: These are three separate code paths in the same file (`all.js`). The `id` parameter in the fetch call comes from a different function (`getPrivateServerExpiration`), not from the Robux balance DOM element. The analyzer incorrectly connected unrelated variable flows.

**Actual Flow**:
```
checkPrivateServerExpirations(userId)
  → response.data[i].vipServerId
  → getPrivateServerExpiration(privateServer.vipServerId)
  → fetch(`https://games.roblox.com/v1/vip-servers/${id}`)
```

The VIP server ID comes from Roblox's own API response, not user input or DOM content.

**Verdict**: **FALSE POSITIVE** - No actual data exfiltration path exists.

---

## Code Quality Assessment

### Positive Indicators
- **Modern Architecture**: TypeScript codebase compiled to JavaScript via webpack
- **Manifest V3**: Uses service worker instead of persistent background page
- **Type Safety**: TypeScript types imported from `roblox` package
- **Error Handling**: Comprehensive try/catch blocks with console logging
- **Security Practices**:
  - CSRF token management
  - URL validation before opening tabs
  - Credential scoping (`credentials: 'include'`)
  - No use of `eval()` or `Function()` constructor
  - No dynamic script injection

### Negative Indicators
- **Deprecated APIs**: Uses `chrome.instanceID` (deprecated in favor of FCM SDK)
- **Third-Party Dependency**: Reliance on developer's backend for notifications

---

## Final Risk Assessment

### Risk Level: **LOW**

### Rationale
Roblox+ is a well-engineered extension providing legitimate enhancements to the Roblox platform. The extension:

1. **No Malicious Behavior**: No credential theft, unauthorized tracking, or data exfiltration
2. **Minimal Third-Party Integration**: Limited to documented premium/notification features
3. **Appropriate Permissions**: No overprivileged access patterns
4. **Secure Coding**: Follows web extension security best practices
5. **Transparent Functionality**: All features align with stated purpose

### Low-Risk Finding
- Limited user data (ID only) shared with developer's backend for premium validation and notifications

### Recommendations for Users
1. **Trust Assessment**: Consider developer reputation (1M+ users, 4.1 rating, established domain)
2. **Privacy**: Understand that enabling catalog notifications shares your Roblox user ID with api.roblox.plus
3. **Permissions**: Extension requests minimal permissions appropriate for functionality

### Recommendations for Developers
1. **Modernize**: Migrate from deprecated `chrome.instanceID`/`gcm` to Firebase Cloud Messaging SDK
2. **Transparency**: Add privacy policy disclosure about api.roblox.plus data sharing
3. **Documentation**: Clarify premium/notification feature data flows in extension description

---

## Conclusion

Roblox+ is a **legitimate enhancement extension** with **LOW RISK** for users. The extension enhances the Roblox experience with quality-of-life features while maintaining user security and privacy. The limited third-party API integration serves documented functionality and does not expose sensitive user data. Static analysis flags are false positives from webpack bundling and overzealous data flow tracing.

**Final Verdict: LOW RISK - Safe for installation with awareness of notification/premium features.**
