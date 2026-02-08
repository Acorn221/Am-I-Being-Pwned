# Security Analysis Report: Email Finder by Snov.io

## Extension Metadata
- **Extension ID**: einnffiilpmgldkapbikhkeicohlaapj
- **Name**: Email Finder by Snov.io
- **Version**: 2.3.24
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Email Finder by Snov.io is a legitimate B2B sales intelligence tool that scrapes contact information from web pages. The extension exhibits **MEDIUM risk** due to extensive DOM access, full HTML extraction, third-party cookie manipulation, and hardcoded Twitter API bearer token. While the extension operates as intended for its stated purpose (finding email addresses and company information), it has broad permissions that enable significant data collection. The primary concerns are:

1. **Full HTML extraction on all websites** via content script messaging
2. **Twitter API bearer token hardcoded** for unauthorized profile scraping
3. **Cookie manipulation** (creating/reading authentication cookies)
4. **Broad host permissions** (`http://*/`, `https://*/`)
5. **No evidence of malicious behavior** but extensive legitimate data extraction capabilities

The extension does not contain market intelligence SDKs (e.g., Sensor Tower), residential proxy infrastructure, extension enumeration/killing mechanisms, or remote kill switches. It appears to function as advertised for B2B lead generation.

---

## Vulnerability Findings

### 1. Full HTML Extraction on All Websites
**Severity**: MEDIUM
**Files**:
- `/deobfuscated/js/content.js` (line 1)
- `/deobfuscated/js/popup.js` (line 40)
- `/deobfuscated/js/googleSearch/googleSearch.js` (line 32)
- `/deobfuscated/js/twitter/twitterSearch.js` (line 19)
- `/deobfuscated/js/yelp/yelpCompany.js` (line 12)

**Code Evidence**:
```javascript
// content.js
chrome.runtime.onMessage.addListener((e,n,t)=>{
    "getInnerHTML"===e.method&&t({
        data:document.all[0].innerHTML,
        method:"getInnerHTML"
    })
});

// popup.js (line 40)
chrome.tabs.sendMessage(s.id, {
    method: "getInnerHTML"
}, async e => {
    let t = [];
    e && (t = searchEmailsO(e.data, currentHost))
    // ... processes extracted HTML
});
```

**Analysis**: The content script responds to `getInnerHTML` messages by returning `document.all[0].innerHTML` (entire page HTML) to the extension popup/background. This HTML is then parsed for email addresses using regex patterns. While legitimate for email extraction, this grants the extension access to all page content on every website.

**Verdict**: LEGITIMATE but privacy-invasive. The extension's stated purpose is email finding, and HTML extraction is necessary for this functionality. However, users should be aware that all page content can be accessed.

---

### 2. Hardcoded Twitter API Bearer Token
**Severity**: MEDIUM-HIGH
**Files**: `/deobfuscated/js/twitter/twitterParserApi.js` (line 2)

**Code Evidence**:
```javascript
let REG_TWITTER_ACCOUNTS = /(^|\W)(@.+?)\b/gi,
    TWITTER_AUTH_HEADER = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";

async function setTwitterUserInfo(e, t) {
    let n = getTwitterInfo(await getTwitterData(e, t)),
    // ...
}

async function getTwitterData(e, t, n = 0) {
    let r = {};
    return await $.get({
        url: "https://api.twitter.com/graphql/P8ph10GzBbdMqWZxulqCfA/UserByScreenName?variables=%7B%22screen_name%22%3A%22" + e + "%22%2C%22withHighlightedLabel%22%3Afalse%7D",
        beforeSend: e => {
            e.setRequestHeader("authorization", TWITTER_AUTH_HEADER),
            e.setRequestHeader("x-csrf-token", t)
        }
    })
    // ...
}
```

**Analysis**: The extension includes a hardcoded Twitter API bearer token to access Twitter's GraphQL API for scraping user profiles. It also uses the user's CSRF token (obtained from `ct0` cookie) to authenticate requests. This enables the extension to extract profile information (name, description, location, profile image, screen name, URLs) from Twitter accounts without proper API authorization.

**Verdict**: CONCERNING. Using a hardcoded bearer token to access Twitter's API without user consent violates Twitter's Terms of Service. The extension accesses Twitter cookies (`ct0`) and uses them to scrape profile data. While not directly malicious to the user, this is unauthorized third-party API usage.

---

### 3. Cookie Manipulation (Authentication Token Management)
**Severity**: MEDIUM
**Files**: `/deobfuscated/js/CheckAuth.js` (lines 7-58)

**Code Evidence**:
```javascript
function parseCheckLogin(e, t) {
    function o(e) {
        chrome.cookies.set({
            name: "token",
            url: mainHost,
            value: e,
            expirationDate: new Date / 1e3 + 1209600,
            httpOnly: !0,
            secure: !0,
            sameSite: "no_restriction"
        }, function(e) {
            bStartedCheckAuth = !1
        })
    }
    var n = JSON.parse(e);
    n && n.result ? (n.name && (n.name, localStorage.userName = n.name),
        n.token ? chrome.cookies.set({
            name: "token",
            url: mainHost,
            value: n.token,
            expirationDate: new Date / 1e3 + 1209600,
            httpOnly: !0,
            secure: !0,
            sameSite: "no_restriction"
        }, // ...
    // Also sets "fingerprint" cookie
    n.fingerprint && chrome.cookies.set({
        name: "fingerprint",
        url: mainHost,
        value: n.fingerprint,
        expirationDate: new Date / 1e3 + 1209600,
        httpOnly: !0,
        secure: !0
    })
```

**Analysis**: The extension creates and manages authentication cookies (`token`, `selector`, `fingerprint`) for `app.snov.io` domain. It also reads Twitter cookies (`ct0` for CSRF token). Cookie manipulation is used for legitimate authentication with Snov.io backend services and for Twitter integration.

**Verdict**: LEGITIMATE. Cookie management is necessary for authentication with the Snov.io platform. The extension sets cookies for its own domain (`app.snov.io`) and reads Twitter cookies for feature functionality. No cross-site cookie theft detected.

---

### 4. Google Analytics Tracking
**Severity**: LOW
**Files**: `/deobfuscated/js/background/googleAnalyticsEvents.js` (lines 1-44)

**Code Evidence**:
```javascript
class GoogleAnalyticsEvents {
    constructor() {
        this.trackingID = "UA-94112226-8",
        this.analyticsPath = "https://www.google-analytics.com/collect",
        this.gaCIDStorageKey = "gaCID",
        this.chromeStoreID = "einnffiilpmgldkapbikhkeicohlaapj",
        this.initClientID()
    }
    send(e) {
        var t = new URLSearchParams;
        t.append("v", 1),
        t.append("tid", this.trackingID),
        t.append("cid", this.gaCID),
        t.append("t", "event"),
        t.append("ec", "SnovioExt"),
        t.append("ea", e),
        this.postData(this.analyticsPath, t)
    }
}
```

**Analysis**: Standard Google Analytics implementation for tracking extension usage events (install, update, feature usage). Events include: `install`, `update_from_X_to_Y`, `domainSearchShow`, `bulkDomainSearchShow`. No PII is sent; only event names and auto-generated client ID.

**Verdict**: ACCEPTABLE. Standard analytics for product telemetry. No sensitive data collection detected.

---

### 5. Broad Host Permissions
**Severity**: MEDIUM
**Files**: `/deobfuscated/manifest.json` (lines 51-53)

**Code Evidence**:
```json
"host_permissions": [
    "http://*/",
    "https://*/"
]
```

**Analysis**: Extension requests access to all HTTP/HTTPS URLs. This is necessary for its core functionality (email finding on any website) but represents broad access. Content script runs on `<all_urls>` to enable HTML extraction.

**Verdict**: LEGITIMATE but broad. Required for email finding functionality across all websites. Users should be aware of the extensive access scope.

---

### 6. Promotional Behavior (Black Friday Auto-Open)
**Severity**: LOW
**Files**: `/deobfuscated/js/background/blackFridayPromotion.js` (lines 19-28)

**Code Evidence**:
```javascript
async checkConditions() {
    this.nowIsPromotionDate() &&
    !(await chrome.storage.local.get(this.promotionCompletedKey))[this.promotionCompletedKey] &&
    (await this.isAlreadyOpenedBF() ||
        (chrome.storage.local.set({
            [this.promotionCompletedKey]: !0
        }),
        this.openTabWithPromoUrl()
    ),
    // ...
}

openTabWithPromoUrl() {
    chrome.tabs.create({
        url: this.promoUrl
    })
}
```

**Analysis**: Extension automatically opens a Black Friday promotional page during a date range (Nov 24 - Dec 3) once per year if not previously opened. The promo tab opens on extension install/startup. Localized URLs for different languages.

**Verdict**: MINOR ANNOYANCE. Not malicious but potentially unwanted promotional behavior. Only triggers once per year per install.

---

## False Positives

| Pattern Detected | File(s) | Explanation |
|------------------|---------|-------------|
| `setTimeout`/`setInterval` usage | Multiple files | Standard JavaScript timing functions for UI updates, polling, and delayed execution. Not dynamic code execution. |
| `innerHTML` usage | `js/twitter/twitter.js`, `js/content.js` | Used for rendering templated UI elements and extracting page HTML for email parsing. Not XSS vectors. |
| jQuery library | `js/libs/jquery.min.js` | Standard library dependency. Not obfuscated malware. |
| Bootstrap library | `js/libs/bootstrap.min.js` | Standard UI framework. Not malicious. |
| `execCommand('copy')` | `js/twitter/twitter.js` (line 110) | Clipboard copy functionality for email addresses. User-initiated action. |
| `fetch()` calls | Multiple files | Legitimate API calls to `app.snov.io` backend for extension functionality. |

---

## API Endpoints & Data Exfiltration

| Endpoint | Purpose | Data Sent | Method |
|----------|---------|-----------|--------|
| `https://app.snov.io/extension/api/contacts/get-by-domain` | Get emails by domain | `link` (current URL) | GET |
| `https://app.snov.io/extension/api/peoples/create` | Save prospect | `people` array (name, source, logo, contacts, etc.), `listId`/`listName` | POST |
| `https://app.snov.io/extension/api/companies/create` | Save company | `companies` array (name, URL, address, phone, etc.), `listId`/`listName` | POST |
| `https://app.snov.io/extension/api/user/balance` | Check user credits | None (authenticated via cookie) | GET |
| `https://app.snov.io/extension/api/news/get-last` | Get news notifications | `data: "finder"` (extension name) | GET |
| `https://app.snov.io/api/checkAuth` | Authenticate user | `selector`, `token` | POST |
| `https://www.google-analytics.com/collect` | Usage analytics | Event name, client ID, tracking ID | POST |
| `https://snov.io/knowledgebase/ext/extension.json` | Check for updates | None | GET |
| `https://api.twitter.com/graphql/P8ph10GzBbdMqWZxulqCfA/UserByScreenName` | Scrape Twitter profiles | `screen_name` (username) | GET (with hardcoded bearer token) |
| `https://app.snov.io/api/email-finder/find-contacts` | Bulk company search | `domains` array | POST |

**Data Flow Summary**:
1. **Page HTML** → Extracted via content script → Parsed for emails using regex
2. **Emails found** → Sent to `app.snov.io` API → Saved to user's Snov.io account lists
3. **Twitter profiles** → Scraped via Twitter GraphQL API → Processed for company/contact info → Sent to Snov.io
4. **User actions** → Tracked via Google Analytics → Aggregate usage metrics
5. **Authentication** → Cookies managed for `app.snov.io` domain → Session tokens stored

All data exfiltration appears to be for the extension's stated purpose (B2B lead generation). No evidence of unauthorized data collection beyond stated functionality.

---

## Security Concerns Summary

### CONFIRMED RISKS:
1. **Hardcoded Twitter Bearer Token**: Unauthorized Twitter API access violating TOS
2. **Full HTML Extraction**: Extension can read entire page content on all websites
3. **Broad Permissions**: `<all_urls>` access for content scripts and host permissions
4. **Cookie Access**: Reads Twitter cookies and manages Snov.io authentication cookies

### NO EVIDENCE OF:
- ✅ Market intelligence SDKs (Sensor Tower, Pathmatics, etc.)
- ✅ AI conversation scraping (ChatGPT, Claude, etc.)
- ✅ Extension enumeration/killing mechanisms
- ✅ Residential proxy infrastructure
- ✅ Remote kill switches or server-controlled behavior changes
- ✅ XHR/fetch hooking or monkey-patching
- ✅ Keylogging or form interception
- ✅ Ad injection or search manipulation
- ✅ Obfuscation or encrypted payloads
- ✅ WebRequest API manipulation
- ✅ Dynamic code execution (eval/Function)

---

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
Email Finder by Snov.io is a **legitimate B2B sales intelligence tool** operating within its stated purpose. The extension enables users to find and save contact information (emails, company details, social profiles) from websites for sales/marketing purposes. However, it has several privacy and security concerns:

**MEDIUM Risk Factors**:
- Hardcoded Twitter API bearer token for unauthorized profile scraping
- Full HTML extraction capability on all websites
- Broad permissions (`<all_urls>`, `http://*/`, `https://*/`)
- Cookie manipulation for authentication and Twitter integration
- Auto-opening promotional tabs (Black Friday)

**Mitigating Factors**:
- No evidence of malicious data exfiltration beyond stated purpose
- No market intelligence SDKs or hidden tracking
- No extension killing or proxy infrastructure
- Transparent functionality matching Chrome Web Store description
- Legitimate backend API endpoints (app.snov.io)
- Proper authentication and user account management

**Recommendation**:
The extension is **SAFE FOR INTENDED USE** but users should be aware of:
1. **Privacy implications**: All page content can be accessed on visited websites
2. **Twitter TOS violation**: Unauthorized API usage may affect Twitter accounts
3. **Broad permissions**: Extension has extensive access to browsing activity
4. **Data collection**: Contact information is sent to Snov.io servers

This extension is suitable for B2B sales professionals who understand and consent to its data collection practices. It is **NOT recommended** for users concerned about privacy or those who do not actively use Snov.io services.

---

## Technical Details

**Manifest Permissions**:
- `tabs` - Access to tab information for current page URL
- `cookies` - Cookie management for authentication and Twitter integration
- `notifications` - Version update notifications
- `storage` - Local/sync storage for user preferences and analytics ID
- `host_permissions: ["http://*/", "https://*/"]` - Access to all websites

**Content Security Policy**: None specified (default MV3 CSP applies)

**Background Service Worker**: `/js/sw.js` - Handles messaging, version checks, news updates, Black Friday promotions

**Content Scripts**:
1. `js/content.js` on `<all_urls>` - Listens for HTML extraction requests
2. `js/snovio/snovioEvents.js` on `https://app.snov.io/*` - Syncs user lists
3. `js/snovio/presence.js` on `https://app.snov.io/*` - Adds extension presence indicator

**Key Libraries**:
- jQuery 3.x (standard library)
- Bootstrap 4.x (UI framework)
- tld.js (domain parsing)

**No evidence of**:
- Webpack/Parcel bundling obfuscation
- Third-party analytics SDKs beyond Google Analytics
- Content script injection into sensitive domains (banking, email providers)
- Sensitive data collection (passwords, credit cards, PII beyond public business contacts)

---

## Conclusion

Email Finder by Snov.io operates as advertised: a B2B lead generation tool for finding and managing business contact information. The **MEDIUM risk** rating reflects legitimate but privacy-invasive functionality, particularly the hardcoded Twitter bearer token and broad permissions. Users should only install this extension if they actively use Snov.io services and consent to extensive data collection for business purposes.

**No critical vulnerabilities requiring immediate action were identified.**
