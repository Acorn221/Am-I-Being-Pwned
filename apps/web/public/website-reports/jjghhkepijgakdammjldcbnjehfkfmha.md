# Salesforce Chrome Extension Security Analysis

## Extension Metadata
- **Extension ID**: jjghhkepijgakdammjldcbnjehfkfmha
- **Name**: Salesforce
- **Version**: 2.256.7
- **User Count**: ~400,000 users
- **Publisher**: Salesforce.com, Inc.
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

The Salesforce Chrome extension is a **LEGITIMATE PRODUCTIVITY TOOL** designed to integrate Salesforce CRM capabilities directly into Gmail and Google Calendar. After comprehensive analysis of the extension's manifest, background scripts, content scripts, and network behavior, this extension is rated as **CLEAN** with appropriate security practices for its intended functionality.

**Key Findings:**
- OAuth2-based authentication with proper token refresh mechanisms
- Legitimate use of `chrome.management` API to detect conflicting email extensions
- Scoped permissions appropriate for Gmail/Calendar integration
- No third-party tracking SDKs or market intelligence code
- LinkedIn context extraction is legitimate for CRM enrichment
- Session management follows OAuth2 hybrid refresh flow standard
- All network calls are exclusively to Salesforce-owned domains

**Overall Risk Assessment**: **CLEAN**

---

## Vulnerability Analysis

### 1. Extension Enumeration via chrome.management
**Severity**: LOW (FALSE POSITIVE)
**Files**:
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/background.bundle.js` (lines 2471-2507)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/gmail/js/bootstrap.bundle.js` (lines 70-74)

**Code Evidence**:
```javascript
// background.bundle.js line 2471-2484
const incompatibleExtIds = [
    "cnkgdfnjmgamkcpjdljdncfjcegpgcdg", // Salesforce Inbox
    "hibhcpjgdocamgallhmphmmjeahifgof", // Fond
    "jpbnpbfpgjkblmejlgkfkekajajhjcid", // Bananatag Email Tracking
    "fmdomiplhgolgpibfdjjhgbcbkdcfkmk", // Cirrus Insight Legacy
    "mflnemhkomgploogccdmcloekbloobgb", // Right Inbox for Gmail
    "ndddjdifcfcddfdgedlcmfjamionaago", // Assistant.to Scheduling Assistant
    "chmpifjjfpeodjljjadlobceoiflhdid", // Outreach Everywhere
    "ejidjjhkpiempkbhmpbfngldlkglhimk", // Gmail Offline
    "dlppikdhbkdinhpfbneekdbjhgphknad", // Email Tracking, Salesforce & Mail Merge
    "ocpljaamllnldhepankaeljmeeeghnid", // Mixmax: Email Tracking, Templates, Mail
    "gkjnkapjmjfpipfcccnjbjcbgdnahpjp", // Yesware
    "khndhdhbebhaddchcgnalcjlaekbbeof", // Bitdefender Anti-tracker
];

function getIncompatibleExtensions() {
    return getExtensions().then(extensions => {
        if (!extensions || !extensions.length) {
            return null;
        }
        return extensions
            .filter(ext => ext.enabled && "extension" === ext.type && incompatibleExtIds.indexOf(ext.id) >= 0)
            .map(ext => {
                return { id: ext.id, name: ext.name };
            });
    });
}
```

**Analysis**: This is a **compatibility checker**, not malicious enumeration. The extension:
- Only checks for a hardcoded whitelist of known conflicting email extensions
- Does NOT enumerate all extensions
- Does NOT disable or interfere with other extensions
- Simply warns users about potential conflicts with competing CRM/email tools

**Verdict**: LEGITIMATE - Standard practice for detecting conflicting productivity tools

---

### 2. Session Management & Cookie Access
**Severity**: LOW (EXPECTED BEHAVIOR)
**Files**:
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/background.bundle.js` (lines 333-522)

**Code Evidence**:
```javascript
// Hybrid OAuth2 refresh flow
async function doHybridRefreshRequest(resource, refreshToken) {
    try {
        const result = await fetch(resource, {
            method: 'POST',
            cache: 'no-cache',
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
                'grant_type': 'hybrid_refresh',
                'client_id': "SfdcEverywhere",
                'refresh_token': refreshToken
            })
        });
        return await result.json();
    } catch (error) {
        throw "Unable to refresh session";
    }
}

// Creates session cookies across Salesforce domains
async function createSessionCookies(url, sessionCookies) {
    if (!await ChromePermissionsManager.containsOptional([], [`${url}/`])) {
        throw 'Missing required host permissions';
    }

    const sessionCookieProps = {
        path: '/',
        sameSite: 'no_restriction', // === none
        secure: true,
        url
    };

    // Creates: sid_Client, clientSrc, lightning_sid, access_token, etc.
    const promises = cookieCreateOptions.map((cookieCreateOption) => {
        return Chrome.cookies.set(cookieCreateOption);
    });
    return Promise.all(promises);
}
```

**Analysis**: The extension implements **standard OAuth2 hybrid refresh flow** for Salesforce authentication:
- Uses refresh tokens to obtain new session tokens
- Creates session cookies on Salesforce domains only (*.salesforce.com, *.force.com, *.cloudforce.com)
- Requires explicit user permission via `chrome.permissions` API
- All cookies are marked `secure: true` and `sameSite: no_restriction` (required for cross-origin integration)

**Verdict**: LEGITIMATE - Proper OAuth2 implementation for authenticated CRM integration

---

### 3. DOM Scraping on Gmail/Calendar
**Severity**: LOW (EXPECTED BEHAVIOR)
**Files**:
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/gmail/js/bootstrap.bundle.js`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/gcal/js/bootstrap.bundle.js`

**Manifest Evidence**:
```json
"content_scripts": [
    {
        "matches": [
            "https://mail.google.com/*"
        ],
        "js": [
            "gmail/js/bootstrap.bundle.js"
        ]
    },
    {
        "matches": [
            "https://calendar.google.com/*"
        ],
        "js": [
            "gcal/js/bootstrap.bundle.js"
        ]
    }
]
```

**Analysis**: Content scripts run **only on Gmail and Google Calendar** to:
- Extract email context (sender, recipient, subject) for CRM logging
- Extract calendar event details for Salesforce event integration
- Inject side panel UI for displaying Salesforce records related to emails/events
- Use `ContentScriptProxy` for secure postMessage communication between content scripts and embedded frames

**Verdict**: LEGITIMATE - Core functionality for email/calendar CRM integration

---

### 4. LinkedIn Context Extraction
**Severity**: LOW (LEGITIMATE CRM FEATURE)
**Files**:
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/injectable/js/linkedin-profile-context-builder.bundle.js`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/injectable/js/linkedin-company-context-builder.bundle.js`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/injectable/js/linkedin-search-context-builder.bundle.js`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/injectable/js/linkedin-messaging-context-builder.bundle.js`

**Code Evidence**:
```javascript
// linkedin-profile-context-builder.bundle.js
function getOpenGraphData(settings = {}) {
    const results = {};
    const elements = document.querySelectorAll('meta[property*=og\\:], meta[property*=profile\\:], meta[name*=twitter\\:], meta[name*=og\\:], meta[name=description]');
    for (const element of elements) {
        const key = element.getAttribute('property') || element.getAttribute('name');
        const value = element.getAttribute('content');
        if (key && value) {
            results[key] = value;
        }
    }
    // Also extracts sf:emails and sf:phones from mailto:/tel: anchors
    if (settings.shouldGetAnchors) {
        const { emails, phones } = getAnchorData();
        results['sf:emails'] = emails;
        results['sf:phones'] = phones;
    }
    return results;
}
```

**Analysis**: LinkedIn scrapers are **dynamically injected** (not persistent content scripts) to:
- Extract Open Graph metadata (profile:first_name, profile:last_name, og:title, etc.)
- Collect email addresses and phone numbers from visible `mailto:` and `tel:` links
- Parse LinkedIn search results, company pages, messaging threads, and Sales Navigator
- **IMPORTANT**: These are injectable scripts loaded on-demand via `chrome.scripting.executeScript`, not persistent background monitoring

**Verdict**: LEGITIMATE - Standard CRM contact enrichment from publicly visible LinkedIn data

---

### 5. Declarative Net Request (Redirect Rules)
**Severity**: LOW (TRACKING PIXEL WORKAROUND)
**Files**:
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/redirect_rules.json`

**Code Evidence**:
```json
[
    {
        "id": 1,
        "priority": 1,
        "action": {
            "type": "redirect",
            "redirect": {
                "regexSubstitution": "\\1"
            }
        },
        "condition": {
            "regexFilter": "^https://.*.googleusercontent.com/.*#(.*.salesforceiq.com/t.png.*)",
            "resourceTypes": ["image"]
        }
    },
    {
        "id": 2,
        "priority": 1,
        "action": {
            "type": "redirect",
            "redirect": {
                "regexSubstitution": "\\1"
            }
        },
        "condition": {
            "regexFilter": "^https://.*.googleusercontent.com/.*#(.*apiq-apiv1-.*.svc.sfdcfc.net/t.png.*)",
            "resourceTypes": ["image"]
        }
    }
]
```

**Analysis**: These rules **rewrite tracking pixel URLs** in Gmail:
- Gmail proxies external images through `googleusercontent.com` for privacy
- Salesforce embeds tracking pixels (t.png) in emails to track opens
- Extension redirects proxied pixel URLs back to direct Salesforce domains
- This is necessary for email open tracking to work in Gmail's proxy environment

**Verdict**: LEGITIMATE - Standard workaround for email tracking in Gmail

---

### 6. Optional Broad Host Permissions
**Severity**: MEDIUM (REQUIRES USER CONSENT)
**Manifest Evidence**:
```json
"optional_host_permissions": [
    "https://*/*"
]
```

**Analysis**: The extension declares **optional** (not automatic) permissions for all HTTPS sites. This is used for:
- **LinkedIn integration** (context extraction on linkedin.com)
- **Everywhere panel** feature (CRM overlay on any webpage where user is browsing)
- **Dynamic content script injection** on sites beyond Gmail/Calendar

**Mitigating Factors**:
- Requires explicit user approval via permissions prompt
- Checked at runtime: `ChromePermissionsManager.containsOptional([], ['https://*/*'])`
- Background.bundle.js line 1327-1360 shows proper permission request handling

**Verdict**: ACCEPTABLE - Properly gated behind user consent for enhanced CRM features

---

## False Positives Summary

| Pattern | Files | Explanation |
|---------|-------|-------------|
| **chrome.management.getAll()** | background.bundle.js, all bootstrap bundles | Compatibility checker for conflicting email extensions (whitelist-based, read-only) |
| **chrome.cookies access** | background.bundle.js | OAuth2 session cookie management for Salesforce authentication (scoped to *.salesforce.com domains) |
| **querySelectorAll on LinkedIn** | injectable/js/linkedin-*.bundle.js | CRM enrichment from public LinkedIn profile metadata (on-demand injection, not persistent monitoring) |
| **XMLHttpRequest/fetch usage** | background.bundle.js, everywhere.bundle.js | Legitimate API calls to Salesforce OAuth2 endpoints and CRM APIs (no third-party tracking) |
| **innerHTML usage** | everywhere.bundle.js, embedded.bundle.js | LWC (Lightning Web Components) framework rendering for Salesforce UI components |
| **postMessage communication** | bootstrap.bundle.js, content-script-proxy.js | Secure iframe/content script communication for side panel integration |

---

## API Endpoints & Data Flow

### Primary Backend Domains
All network traffic goes **exclusively to Salesforce-owned infrastructure**:

| Domain Pattern | Purpose |
|---------------|---------|
| `https://*.salesforce.com/` | Production Salesforce CRM instances |
| `https://*.force.com/` | Lightning/Visualforce domains |
| `https://*.cloudforce.com/` | Alternative Salesforce domain |
| `https://*.my-salesforce.com/` | Customer-specific org domains |
| `https://*.crmforce.com/` | CRM Force subdomains |
| `https://*.salesforceiq.com/` | SalesforceIQ (acquired product) |

### Key API Flows

#### 1. OAuth2 Hybrid Refresh Flow
```
Extension → https://[server]/services/oauth2/token
  POST grant_type=hybrid_refresh
       client_id=SfdcEverywhere
       refresh_token=[token]

Response → {
  csrf_token, access_token, refresh_token,
  lightning_domain, visualforce_domain, instance_url,
  sidCookieName, cookie-sid_Client, cookie-clientSrc,
  lightning_sid, visualforce_sid, content_sid
}
```

#### 2. CSRF Token Exchange
```
Extension → https://[server]/clients/mailapp/everywhere/exchange
  POST { csrf: [token] }

Response → { refresh-token: [new_token] }
```

#### 3. Context Data Flow
```
Gmail/Calendar Content Script
  ↓ (extract email/event context)
ContentScriptProxy (postMessage)
  ↓
Background Service Worker
  ↓ (build context + apply data mappings)
Side Panel / Everywhere Window
  ↓ (display Salesforce records)
Salesforce CRM API
```

---

## Data Collection & Privacy

### Data Collected
The extension collects the following data **only for authenticated Salesforce users**:

1. **Email Context** (Gmail):
   - Email sender, recipients, subject, message ID
   - Thread ID, conversation participants
   - Sent timestamp

2. **Calendar Context** (Google Calendar):
   - Event title, attendees, organizer
   - Event start/end time, location
   - Meeting description

3. **LinkedIn Context** (when user explicitly uses feature):
   - Profile name, job title, company
   - Email addresses and phone numbers from visible contact info
   - Company search results

4. **Session Data**:
   - Salesforce org ID, user ID
   - OAuth2 refresh tokens (stored in chrome.storage)
   - CSRF tokens for API requests

### Data Storage
- **chrome.storage.local**: OAuth2 tokens, user preferences, context subscriptions
- **Cookies**: Session cookies on Salesforce domains (sid_Client, clientSrc, access tokens)
- **No external transmission**: All data sent exclusively to user's Salesforce org

### Privacy Assessment
- **No third-party tracking SDKs detected**
- **No market intelligence collection** (unlike Sensor Tower extensions)
- **No browsing history upload**
- **No AI conversation scraping**
- **User data stays within Salesforce ecosystem**

---

## Permissions Analysis

### Required Permissions
```json
"permissions": [
    "management",        // Check for incompatible extensions
    "storage",          // Store OAuth tokens and preferences
    "declarativeNetRequest", // Redirect tracking pixels
    "cookies",          // Manage Salesforce session cookies
    "sidePanel",        // Display CRM panel in browser
    "idle"              // Detect user activity for session management
]
```

### Optional Permissions (User Consent Required)
```json
"optional_permissions": [
    "activeTab",        // Access current tab for context
    "notifications",    // Show CRM alerts
    "system.display",   // Optimize UI for screen size
    "scripting"         // Inject LinkedIn context extractors
]
```

**Assessment**: Permissions are **appropriately scoped** for a CRM integration tool. No excessive or suspicious permissions requested.

---

## Security Posture

### Positive Security Indicators
✅ **Official Salesforce extension** (Copyright © 2016 salesforce.com, Inc.)
✅ **OAuth2-compliant authentication** with secure token refresh
✅ **No obfuscation or code packing** (readable webpack bundles)
✅ **Manifest V3 compliance** (modern security model)
✅ **Scoped host permissions** (only Gmail, Calendar, Salesforce domains by default)
✅ **No external CDN dependencies** (all resources bundled)
✅ **Proper CSP handling** for embedded iframes
✅ **UUID-based context correlation** (no user tracking IDs)

### Potential Concerns
⚠️ **Broad optional permissions** (https://\*/\*) - Mitigated by user consent requirement
⚠️ **LinkedIn scraping** - Mitigated by on-demand injection and public data only
⚠️ **Chrome.management API** - Mitigated by read-only, whitelist-based usage

---

## Overall Risk Assessment: **CLEAN**

The Salesforce Chrome extension is a **legitimate productivity tool** with no malicious behavior detected. All functionality aligns with its stated purpose of integrating Salesforce CRM capabilities into Gmail, Google Calendar, and (optionally) LinkedIn.

### Risk Breakdown
- **Extension Enumeration**: LOW (compatibility checker, not malicious)
- **Session Management**: LOW (proper OAuth2 implementation)
- **DOM Scraping**: LOW (limited to Gmail/Calendar/LinkedIn for CRM context)
- **Network Traffic**: CLEAN (Salesforce domains only)
- **Privacy Concerns**: CLEAN (no third-party data sharing)
- **Permissions**: MEDIUM (broad optional permissions, but properly gated)

### Recommendation
**SAFE FOR USE** - This extension can be safely used by Salesforce customers who need Gmail/Calendar integration with their CRM. Users should be aware that:
1. Email/calendar data is sent to their Salesforce org (expected for CRM logging)
2. LinkedIn context extraction requires separate permission grant
3. Extension can detect other installed email tools (for compatibility warnings)

---

## Technical Architecture

### Framework Stack
- **Build System**: Webpack 5 with multiple entry points
- **UI Framework**: Lightning Web Components (LWC 2.41.4)
- **OAuth Client**: Custom implementation of Salesforce hybrid refresh flow
- **Content Script Communication**: Custom ContentScriptProxy using window.postMessage

### Key Components
1. **Background Service Worker** (background.bundle.js) - OAuth2 flow, context management, message routing
2. **Gmail Bootstrap** (gmail/js/bootstrap.bundle.js) - Email context extraction, side panel injection
3. **Calendar Bootstrap** (gcal/js/bootstrap.bundle.js) - Calendar event context extraction
4. **Everywhere Panel** (everywhere/js/everywhere.bundle.js) - Floating CRM UI overlay
5. **LinkedIn Injectors** (injectable/js/linkedin-*.bundle.js) - On-demand profile scraping

---

## Comparison to Known Malicious Patterns

Unlike malicious extensions analyzed in this project (StayFree, StayFocusd, Urban VPN, etc.), Salesforce extension does **NOT** exhibit:
- ❌ Sensor Tower / Pathmatics SDK injection
- ❌ XHR/fetch global hooking for ad scraping
- ❌ AI conversation scraping (ChatGPT, Claude, etc.)
- ❌ Browsing history upload to third parties
- ❌ Extension disabling/killing mechanisms
- ❌ Remote config for silent behavior changes
- ❌ Hardcoded tracking endpoints outside declared domains
- ❌ Residential proxy infrastructure
- ❌ Ad injection or coupon manipulation

---

## File Reference

### Critical Files Analyzed
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/manifest.json`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/background.bundle.js` (4597 lines)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/redirect_rules.json`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/gmail/js/bootstrap.bundle.js`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/gmail/js/embedded.bundle.js`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/gcal/js/bootstrap.bundle.js`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/everywhere/js/everywhere.bundle.js` (39628 lines)
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/injectable/js/linkedin-profile-context-builder.bundle.js`
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/jjghhkepijgakdammjldcbnjehfkfmha/deobfuscated/injectable/js/linkedin-company-context-builder.bundle.js`

---

**Analysis Completed**: 2026-02-06
**Analyst**: Claude Opus 4.6
**Methodology**: Static code analysis, manifest inspection, network flow analysis, permission audit
