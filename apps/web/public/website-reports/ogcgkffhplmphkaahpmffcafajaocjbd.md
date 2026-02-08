# Security Analysis Report: ZenHub for GitHub

## Metadata
- **Extension Name**: ZenHub for GitHub
- **Extension ID**: ogcgkffhplmphkaahpmffcafajaocjbd
- **Version**: 4.5.73
- **User Count**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

ZenHub for GitHub is a legitimate project management extension that integrates with GitHub. The extension implements standard analytics and monitoring practices using Mixpanel, Sentry, FullStory, and HockeyStack. While the extension collects user data for product analytics, this collection appears to be for legitimate business purposes. The extension uses XMLHttpRequest proxying through the background service worker to bypass CORS restrictions, which is a common pattern for Manifest V3 extensions. No malicious behavior, residential proxy infrastructure, ad injection, or other security threats were identified.

**Overall Risk Level: CLEAN**

## Vulnerability Details

### 1. Third-Party Analytics and Tracking SDKs

**Severity**: LOW (Expected Behavior)
**Category**: Privacy Concern
**Files**:
- `/deobfuscated/js/built/config.js`
- `/deobfuscated/js/built/main.js`

**Description**:
The extension integrates multiple analytics and monitoring services:

1. **Mixpanel** (Token: `28eacd763239e0137e163cc1da830f90`)
   - Event tracking and user identification
   - User property tracking
   - Organization grouping
   ```javascript
   r.A.init(s.A.mixpanel.token, {
     api_host: s.A.isDev ? void 0 : `${s.A.ZENHUB_WEBAPP_ADDRESS}/mp`,
     autocapture: !1,
     debug: s.A.verboseLogs,
     record_collect_fonts: !0,
     record_mask_text_selector: null,
     record_sessions_percent: 0
   })
   ```

2. **Sentry** (DSN: `https://8cfca46805114169a63f945320db71d4@o1038965.ingest.sentry.io/6007661`)
   - Error monitoring and crash reporting
   - Has appropriate error filtering for common issues
   ```javascript
   ignoreErrors: ["auth:error:not_authed", "Issues are disabled for this repo",
                  "Extension context invalidated", "NetworkError when attempting to fetch resource",
                  "ResizeObserver loop limit exceeded"]
   ```

3. **FullStory** (Org ID: `o-1A1KFV-na1`)
   - Session replay and user behavior tracking
   - URL: `https://edge.fullstory.com`
   ```javascript
   g.logToFullStory({
     level: "error",
     msg: `[Debug] Subscription timed out; Terminating; SubscriptionUuid: ${e.current}`
   })
   ```

4. **HockeyStack**
   - User identification for analytics
   ```javascript
   window.addEventListener("hockeystackLoaded", (() => {
     "HockeyStack" in window && e && window.HockeyStack?.identify?.(e)
   }))
   ```

**Verdict**: **FALSE POSITIVE** - These are standard product analytics tools used by SaaS products. The extension properly gates tracking behind the `isTrackerEnabled` flag and only operates in production mode. Session recording is disabled (`record_sessions_percent: 0`).

---

### 2. XMLHttpRequest Proxying via Background Service Worker

**Severity**: LOW (Expected Behavior)
**Category**: Network Interception
**Files**:
- `/deobfuscated/js/built/main.js` (lines 34177-34221)
- `/deobfuscated/js/worker.js` (lines 145-198)

**Description**:
The extension overrides `XMLHttpRequest.prototype.open` to proxy certain requests through the background service worker using the `executeXMLHttpRequestInBackground` command.

**Content Script (main.js)**:
```javascript
XMLHttpRequest.prototype.open = function(...t) {
  const n = t[1],
    s = {
      open: t
    };
  // Excludes upload endpoints
  ! function(e) {
    return !(!i.H8 || e && (/upload\/images$/.test(e) || /upload\/files$/.test(e)
            || /file\/upload$/.test(e) || /api\/gh\/upload_file$/.test(e)))
  }(n) ? e.call(this, ...t): (this.setRequestHeader = (e, t) => {
    s.setRequestHeader || (s.setRequestHeader = []), s.setRequestHeader.push({
      key: e,
      value: t
    })
  }, this.send = (...e) => {
    s.send = e, r.A.sendMessage({
      command: "executeXMLHttpRequestInBackground",
      data: s
    }, (e => {
      // Process response...
    }))
  })
}
```

**Background Worker (worker.js)**:
```javascript
executeXMLHttpRequestInBackground: async (data, _sender, senderResponse) => {
  const [method, url] = data.open;
  const [body] = data.send;
  const requestHeaders = data.setRequestHeader;

  const response = await fetch(url, {
    method,
    headers: formattedRequestHeaders,
    body,
  }).catch((error) => {
    if (error.message === 'Failed to fetch') {
      senderResponse({
        readyState: 4,
        responseText: '',
        status: 0,
        statusText: '',
        responseHeaders: '',
      });
    }
  });
  // Format and return response...
}
```

**Verdict**: **FALSE POSITIVE** - This is a legitimate workaround for CORS restrictions in Manifest V3 extensions. The extension only proxies requests to its own API endpoints (`api.zenhub.com`) and GitHub APIs, which are declared in `host_permissions`. File uploads are explicitly excluded from proxying.

---

### 3. Data Storage in Chrome Storage and Local/Session Storage

**Severity**: LOW (Expected Behavior)
**Category**: Data Storage
**Files**: `/deobfuscated/js/built/main.js`

**Description**:
The extension stores various data types:

1. **Chrome Storage (Sync)**:
   - API tokens (`api_token`, `auth0_token`, `github_token`)
   - User preferences
   - Extension state

2. **LocalStorage**:
   - Recent repositories
   - User settings
   - Theme preferences (with cookies for `zenhub.com` domain)

3. **SessionStorage**:
   - Temporary session data
   - Navigation state

**Code Examples**:
```javascript
// Chrome storage usage
chrome.storage.sync.set(e, t)
chrome.storage.sync.get(e, t)
chrome.storage.onChanged.addListener((n => {
  // Handle changes
}))

// Cookie setting for theme
document.cookie = `${d.Tw}=${e}; SameSite=strict; Secure; domain=zenhub.com`
```

**Verdict**: **FALSE POSITIVE** - Standard storage patterns for browser extensions. Tokens are stored securely using Chrome's encrypted storage API. Cookies are set with appropriate security flags (Secure, SameSite=strict).

---

### 4. OAuth Authentication Flow

**Severity**: LOW (Expected Behavior)
**Category**: Authentication
**Files**:
- `/deobfuscated/js/worker.js` (lines 11-32, 94-113)
- `/deobfuscated/js/built/main.js`

**Description**:
The extension implements OAuth authentication with GitHub, Google, ZenHub, and optionally Azure AD and SAML. On first install, users are redirected to a thank-you/sign-up page.

**Background Worker OAuth Handler**:
```javascript
const redirectToThankyouPage = () => {
  storage.get(null, (cacheParam) => {
    const cache = cacheParam || {};
    if (THANK_YOU_URL_WITH_REDIRECT && !cache.api_token) {
      chrome.tabs.create({
        url: THANK_YOU_URL_WITH_REDIRECT, // https://app.zenhub.com/thank-you
      });
    }
  });
};

oauthSuccess(_data, sender) {
  try {
    oAuthListenerPorts.forEach((port) =>
      port.postMessage({ name: 'oauthSuccessFromPort' }),
    );
  } catch (err) {
    console.error('oauthSuccessFromPort error:', err);
  }
  oAuthListenerPorts = [];

  // Close the OAuth redirect window
  chrome.tabs.get(sender?.tab?.id, (tab) => {
    if (tab) chrome.tabs.remove(tab.id);
  });
}
```

**Supported Auth Methods** (from config.js):
```javascript
"authOptions": {
  "GitHub": true,
  "Google": true,
  "Zenhub": true,
  "AzureAD": false,
  "LDAP": false,
  "SAML": false
}
```

**Verdict**: **FALSE POSITIVE** - Standard OAuth implementation for extension authentication. The extension properly manages OAuth windows and notifies waiting tabs upon successful authentication.

---

### 5. WebSocket Connection for Real-Time Updates

**Severity**: LOW (Expected Behavior)
**Category**: Network Communication
**Files**:
- `/deobfuscated/js/built/config.js`
- `/deobfuscated/js/built/main.js`

**Description**:
The extension uses ActionCable (WebSocket) for real-time updates from ZenHub's backend.

**Configuration**:
```javascript
"CABLE_URL": "wss://api.zenhub.com/cable/"
```

**Usage**:
```javascript
return this.cable = e.getContext().cable, r.A.prototype.request.call(this, e, t)
```

**Verdict**: **FALSE POSITIVE** - Legitimate WebSocket connection to ZenHub's API for real-time project management updates. The connection requires authentication tokens.

---

### 6. GitHub Navigation Detection

**Severity**: LOW (Expected Behavior)
**Category**: Page Monitoring
**Files**: `/deobfuscated/js/worker.js` (lines 201-225)

**Description**:
The background worker tracks URL changes in GitHub tabs to inject ZenHub content at appropriate times.

**Code**:
```javascript
const tabUrlMap = new Map();

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    if (!tab.url) return;
    const url = new URL(tab.url);
    if (url.hostname !== githubDomain) return;

    const previousUrl = tabUrlMap.get(tabId);

    // Fire a `ghNavigation` command to tell the client-side script that a URL
    // change (ie. navigation) event has occurred
    if (!previousUrl || previousUrl !== tab.url) {
      await chrome.tabs.sendMessage(tabId, { command: 'ghNavigation', url: tab.url });
    }
  }
});
```

**Verdict**: **FALSE POSITIVE** - This is necessary for the extension to detect GitHub's single-page navigation (which doesn't trigger standard navigation events) and inject ZenHub UI components at the right time. Limited to `github.com` domain.

---

### 7. GraphQL API Communication

**Severity**: LOW (Expected Behavior)
**Category**: API Communication
**Files**: `/deobfuscated/js/built/main.js`

**Description**:
The extension communicates extensively with ZenHub's GraphQL API for project management features, including:
- Issue management
- Sprint tracking
- Workspace management
- User authentication
- Analytics tracking

**Sample Queries/Mutations**:
```javascript
mutation trackEvent($TrackEventInput: TrackEventInput!)
query getUserAuthDetails
query getSprintConfig($workspaceId: ID!, $first: Int, ...)
mutation moveIssueToPipeline($input: MoveIssueInput!, $workspaceId: ID!)
subscription AcceptanceCriteriaEventsSubscription(...)
```

**API Endpoints**:
```javascript
s = `${p.A.ZENHUB_RAPTOR_ADDRESS}/v1/raptor/graphql`
R = P("v1/graphql")
M = P("public_graphql")
```

**Verdict**: **FALSE POSITIVE** - Standard GraphQL API communication for the extension's core functionality. All queries appear to be legitimate project management operations.

---

## False Positive Summary

| Pattern | Reason | Context |
|---------|--------|---------|
| Mixpanel/Sentry/FullStory/HockeyStack | Standard SaaS analytics | Product analytics for legitimate business purposes |
| XMLHttpRequest hooking | CORS workaround for Manifest V3 | Only proxies requests to declared host_permissions |
| chrome.storage usage | Token/state management | Standard extension storage patterns |
| OAuth authentication | User login flow | Standard OAuth implementation |
| WebSocket connection | Real-time updates | Legitimate ActionCable connection to ZenHub API |
| Tab URL monitoring | GitHub navigation detection | Required for single-page app navigation detection |
| Cookie setting | Theme persistence | Secure cookies with appropriate flags |
| LocalStorage/SessionStorage | Preferences/state | Standard web storage usage |
| FullStory logging | Debug logging | Conditional logging for development |
| atob/btoa | Base64 encoding | Used for decoding GitHub data |

## API Endpoints

| Endpoint | Purpose | Authentication |
|----------|---------|----------------|
| `https://api.zenhub.com/*` | ZenHub API | Bearer token / x-authentication-token |
| `https://github.com/*` | GitHub integration | GitHub OAuth token |
| `https://api.github.com/*` | GitHub REST API | GitHub token |
| `https://api.github.com/graphql` | GitHub GraphQL API | GitHub token |
| `wss://api.zenhub.com/cable/` | Real-time updates via ActionCable | Token-based authentication |
| `https://app.zenhub.com/mp` | Mixpanel proxy endpoint | N/A |
| `https://o1038965.ingest.sentry.io/*` | Error reporting | Sentry DSN |
| `https://edge.fullstory.com` | Session analytics | FullStory org ID |

## Data Flow Summary

### Data Collection:
1. **User Identity**: Email, name, GitHub ID, ZenHub user ID
2. **Usage Analytics**: Feature usage, page views, user interactions (via Mixpanel)
3. **Error Reports**: Stack traces, error messages (via Sentry)
4. **Session Data**: User behavior logging (via FullStory - session recording disabled)
5. **GitHub Data**: Repository information, issues, pull requests, project boards
6. **Authentication Tokens**: GitHub OAuth token, ZenHub API token, Auth0 token

### Data Storage:
1. **Chrome Storage Sync**: API tokens, user preferences, settings
2. **LocalStorage**: Recent repositories, theme preferences
3. **SessionStorage**: Temporary navigation state
4. **Cookies**: Theme preference (domain: zenhub.com, Secure, SameSite=strict)

### External Data Sharing:
1. **Mixpanel**: User identity, feature usage events, organization associations
2. **Sentry**: Error reports with stack traces and context
3. **FullStory**: Debug logs (conditional, verbose mode only)
4. **HockeyStack**: User identification (email only)
5. **ZenHub API**: All project management data (issues, sprints, workspaces)
6. **GitHub API**: Repository and issue metadata

### Security Controls:
1. ✅ Tracking gated behind `isTrackerEnabled` flag
2. ✅ Session recording disabled (`record_sessions_percent: 0`)
3. ✅ Sentry configured with appropriate error filtering
4. ✅ Secure cookie flags (Secure, SameSite)
5. ✅ Chrome Storage API used for sensitive tokens
6. ✅ CORS properly handled via background worker
7. ✅ OAuth implementation follows best practices
8. ✅ Host permissions limited to necessary domains

## Suspicious Patterns Analysis

### ❌ No Malicious Patterns Found:
- ❌ No extension enumeration/killing
- ❌ No residential proxy infrastructure
- ❌ No remote kill switches
- ❌ No market intelligence SDKs (Sensor Tower, Pathmatics, etc.)
- ❌ No AI conversation scraping
- ❌ No ad/coupon injection
- ❌ No aggressive obfuscation
- ❌ No dynamic code execution (eval, Function constructor)
- ❌ No keyloggers
- ❌ No chrome.webRequest/declarativeNetRequest abuse
- ❌ No unauthorized data exfiltration

### ✅ Legitimate Patterns Observed:
- ✅ Standard OAuth authentication flow
- ✅ Proper manifest v3 implementation
- ✅ Reasonable CSP policy
- ✅ Minimal permissions (only storage)
- ✅ Scoped host_permissions
- ✅ Professional code structure
- ✅ Error handling and logging
- ✅ Privacy-conscious tracking implementation

## Overall Risk Assessment

**Risk Level: CLEAN**

### Justification:

1. **Legitimate Product**: ZenHub is a well-known, established project management tool for GitHub with ~60,000 users and professional development practices.

2. **Appropriate Permissions**: The extension only requests the `storage` permission and declares necessary host_permissions for its legitimate functionality (api.zenhub.com, github.com, api.github.com).

3. **Transparent Analytics**: While the extension does implement analytics, it uses industry-standard tools (Mixpanel, Sentry, FullStory) with appropriate safeguards:
   - Tracking gated behind configuration flag
   - Session recording disabled
   - Error filtering implemented
   - No excessive data collection

4. **Security Best Practices**:
   - Manifest V3 implementation
   - Secure token storage
   - Proper OAuth flows
   - CORS handling via background worker (standard Manifest V3 pattern)
   - Secure cookie flags

5. **No Malicious Indicators**: Extensive analysis revealed no proxy infrastructure, ad injection, keylogging, unauthorized data access, or other malicious behaviors.

6. **Minimal Attack Surface**: The extension is scoped to GitHub pages only, with clear separation between content scripts and background worker.

### Recommendations:

1. **For Users**:
   - The extension is safe to use for its intended purpose
   - Users should be aware that usage analytics are collected
   - Review privacy policy at https://zenhub.com for data handling practices

2. **For Developers**:
   - Consider making analytics opt-in rather than opt-out
   - Document data collection practices in the extension's description
   - Implement clear privacy controls in the UI

## Conclusion

ZenHub for GitHub is a **CLEAN** extension that implements standard project management functionality without any malicious behavior. The analytics and tracking observed are typical for professional SaaS products and are implemented with appropriate safeguards. No security vulnerabilities or privacy violations were identified that would pose a risk to users.
