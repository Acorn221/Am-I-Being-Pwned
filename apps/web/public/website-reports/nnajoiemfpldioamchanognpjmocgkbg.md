# Security Analysis: Draftback

**Extension ID:** nnajoiemfpldioamchanognpjmocgkbg
**Version:** 0.0.27
**Users:** 500,000
**Overall Risk:** MEDIUM

## Summary

Draftback is a legitimate Google Docs extension that allows users to play back document edit history. While the extension serves its intended purpose, it exhibits several security concerns related to data handling and message validation. The extension extracts OAuth tokens and user email addresses from Google Docs pages, transmits them to a third-party server (accounts.draftback.com) for subscription validation, and uses message handlers without proper origin validation.

## Vulnerabilities

### HIGH: Unvalidated Message Handlers (postMessage without origin check)

**Location:** `background.min.js:1`

**Description:**
The background script registers a `window.addEventListener("message")` handler without validating the origin of incoming messages. This allows any webpage or extension component to send arbitrary messages to the background script, potentially triggering unintended actions.

**Code Evidence:**
```javascript
self.addEventListener('message',(e=>{
  e.data&&'terminate'===e.data.type&&self.registration.unregister()
}))
```

**Impact:**
Malicious web pages or other extensions could potentially send crafted messages to trigger service worker termination or exploit other message-based functionality. The ext-analyzer detected that message data flows directly to `fetch(accounts.draftback.com)` endpoints without origin validation.

**Recommendation:**
Implement strict origin validation on all message event listeners:
```javascript
if (e.origin !== 'https://docs.google.com') return;
```

---

### MEDIUM: OAuth Token and Email Extraction from Page Context

**Location:** `injected.js:3-6`, `background.min.js` (sign-in handler)

**Description:**
The extension injects a script (`injected.js`) into Google Docs pages that extracts sensitive authentication data from the page's global context:

**Code Evidence:**
```javascript
// injected.js
const token = _docs_flag_initialData.info_params.token;
const email = _docs_flag_initialData['docs-hue'];
window.dispatchEvent(new CustomEvent('tokenExtracted', { detail: { token: token, email: email } }));
```

The background script also uses `chrome.identity.getAuthToken()` to obtain OAuth tokens:
```javascript
chrome.identity.getAuthToken({interactive:!0},(function(e){
  e?fetch('https://www.googleapis.com/oauth2/v3/userinfo',{
    headers:{Authorization:`Bearer ${e}`}
  })
```

**Impact:**
The extension collects:
1. Google Docs internal tokens from page context
2. User email addresses from both page context and OAuth
3. OAuth access tokens with userinfo.email scope
4. A generated `userChromeUUID` stored in local storage

All of this data is transmitted to `accounts.draftback.com` for subscription verification.

**Privacy Concern:**
While this appears to be for legitimate subscription enforcement, the collection and transmission of Google authentication tokens and email addresses to a third-party server represents a privacy risk. Users may not expect their Google credentials to be shared with external services.

---

### MEDIUM: Data Transmission to Third-Party Server

**Location:** `background.min.js` (check-entitlement function)

**Description:**
The extension transmits user identification data to `accounts.draftback.com` for subscription validation:

**Code Evidence:**
```javascript
fetch('https://accounts.draftback.com/check-entitlement',{
  method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({
    userEmail:e.email,
    userChromeUUID:e.userChromeUUID,
    codepath:e.codepath
  })
})
```

**Data Flows (from ext-analyzer):**
1. `chrome.tabs.query` → `fetch(accounts.draftback.com)`
2. `chrome.storage.local.get` → `fetch(accounts.draftback.com)` (2 flows)

**Impact:**
User email addresses, unique device identifiers, and authentication state are sent to a third-party subscription service. While this is for paywall enforcement (the extension now requires a paid subscription after a free trial), users should be clearly informed about this data transmission.

**Transparency Issue:**
The extension description does not clearly disclose that user identification data is transmitted to external servers for subscription validation.

---

## Flagged Categories

1. **oauth_token_extraction** - Extracts OAuth tokens and Google Docs internal tokens from page context
2. **user_email_collection** - Collects user email via chrome.identity API and page context
3. **postmessage_no_origin_check** - Message event listeners lack origin validation
4. **subscription_paywall** - Implements subscription paywall with third-party server communication

## Network Endpoints

- `https://accounts.draftback.com/check-entitlement` - Subscription validation (POST)
- `https://www.googleapis.com/oauth2/v3/userinfo` - OAuth email retrieval

## Permissions Analysis

**Declared Permissions:**
- `identity` - Used for OAuth authentication
- `identity.email` - Retrieves user email address
- `storage` - Stores user email and UUID locally

**Host Permissions:**
- `*://docs.google.com/*` - Full access to all Google Docs domains
- `https://accounts.draftback.com/*` - Communication with subscription backend

**OAuth Scopes:**
- `https://www.googleapis.com/auth/userinfo.email` - Email address access

All permissions align with the extension's stated functionality, though the extent of data transmission to third-party servers may not be fully transparent to users.

## Legitimate Functionality

The core functionality appears legitimate:
- Fetches Google Docs revision history using internal Google APIs
- Processes document changelog to reconstruct edit timeline
- Stores processed revisions in IndexedDB locally
- Provides playback visualization and writing session analytics
- Detects potential paste events based on large insertions (>100 chars)

The extension genuinely implements document history playback functionality and is not malware. The security concerns relate primarily to data handling practices and message validation.

## Recommendations

1. **Add origin validation** to all `window.addEventListener("message")` handlers
2. **Enhance transparency** in the extension description about data transmission to draftback.com
3. **Minimize data collection** - consider using anonymous subscription keys instead of email addresses
4. **Implement Content Security Policy** headers in extension pages
5. **Use chrome.runtime.onMessage** for internal extension messaging instead of window.postMessage where possible

## Conclusion

Draftback is a legitimate productivity tool with a genuine use case (document history playback). The MEDIUM risk rating reflects privacy and security hygiene concerns rather than malicious intent. The extension would benefit from improved message validation and more transparent disclosure of third-party data transmission. Users concerned about privacy should be aware that their email address and device identifier are transmitted to accounts.draftback.com for subscription verification.
