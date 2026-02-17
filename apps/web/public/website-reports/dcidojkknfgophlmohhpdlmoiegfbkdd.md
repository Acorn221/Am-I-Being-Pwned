# Vulnerability Assessment Report
## WA Contacts Extractor (dcidojkknfgophlmohhpdlmoiegfbkdd)

**Extension ID:** dcidojkknfgophlmohhpdlmoiegfbkdd
**Extension Name:** WA Contacts Extractor
**User Count:** ~50,000
**Analysis Date:** 2026-02-07
**Overall Risk Level:** HIGH

---

## Executive Summary

WA Contacts Extractor is a Chrome extension designed to extract contact information from WhatsApp Web. The extension harvests extensive personal data including phone numbers, contact names, business status, labels, message history, and geographic information. While the extension appears to function as advertised without obvious malicious behavior, it collects highly sensitive personally identifiable information (PII) with minimal user transparency and creates significant privacy risks.

**Key Concerns:**
- Extensive contact data harvesting from WhatsApp Web
- Collection of phone numbers, names, last message content/dates, and location data
- OAuth integration with Google Identity for user tracking
- Injection of scripts into WhatsApp Web to access internal APIs
- Limited transparency about data collection scope
- Built using Plasmo framework with Firebase authentication

---

## Vulnerability Details

### 1. PRIVACY: Extensive Contact Data Harvesting
**Severity:** HIGH
**Files:**
- `/deobfuscated/assets/i.js` (lines 389-451)
- `/deobfuscated/assets/w.js`
- `/deobfuscated/plasmo-overlay.db6b23e9.js`

**Description:**
The extension systematically harvests extensive contact information from WhatsApp Web, including:
- Phone numbers with country codes
- Contact names (saved, public, verified, notify names)
- Business account status
- Contact labels/tags
- Last message text content
- Last message timestamps
- Message read/unread status
- Contact blocking status
- Geographic location inference from phone numbers

**Evidence:**
```javascript
// From assets/i.js - Contact data extraction
async function paresAndPostUserData(C, m, i = 'idle') {
    const dataArr = [];
    for (const f of m) {
        let data = {
            'country_code': countryCode ? '+' + countryCode : '',
            'country_name': countryCode ? COUNTRY_INFO[countryCode] || '' : '',
            'phone_number': '+' + user,
            'formatted_phone': formattedPhone ? formattedPhone : '+' + user,
            'is_my_contact': f['isMyContact'],
            'saved_name': E || '',
            'public_name': K || '',
            'is_business': f['isBusiness'],
            'is_blocked': f['isContactBlocked'],
            'labels': await paresLabelsStr(f['labels'] || [])
        };
        await addLastMsg(user, data), dataArr['push'](data);
    }
}

// Last message extraction
const addLastMsg = async (C, m) => {
    const e = f['msgs']['last']();
    e && e['body'] && (m['last_msg_text'] = e['body'],
                        m['last_msg_date'] = new Date(0x3e8 * e['t'])['toString'](),
                        m['last_msg_type'] = e['id']['fromMe'] ? 'Outgoing' : 'Incoming',
                        m['last_msg_status'] = f['msgs']['unreadCount'] && f['msgs']['unreadCount'] > 0x0 ? 'YES' : 'NO');
};
```

**Risk:**
- Collection of highly sensitive PII from user contacts
- Potential for data misuse, resale, or unauthorized disclosure
- Privacy violation of both extension user and their contacts
- GDPR/privacy regulation concerns

**Verdict:** CONFIRMED VULNERABILITY - High privacy risk due to extensive PII collection

---

### 2. DATA EXFILTRATION: Phone Number Validation Service
**Severity:** MEDIUM
**Files:**
- `/deobfuscated/assets/i.js` (lines 352-383)
- `/deobfuscated/plasmo-overlay.db6b23e9.js`

**Description:**
The extension provides a phone number validation feature that checks if numbers exist on WhatsApp. This could be used for mass phone number validation/enumeration attacks.

**Evidence:**
```javascript
// Phone number checking functionality
case '_wa_contacts_24uvb_____WA_CHECK_NUMBER____':
    let Q = event['data']['n'];
    const U = Q['split']('+')[0x1];
    let O = await X['contact']['queryExists'](U + '@c.us');
    window['postMessage']({
        'k': '_wa_contacts_24uvb___WA_CHECK_NUMBER_RESP__',
        'req': {
            'n': Q,
            'i': event['data']['i']
        },
        'ret': O
    });
```

**Risk:**
- Enables phone number enumeration attacks
- Could be abused for spam/marketing campaigns
- Privacy violation through mass contact validation

**Verdict:** CONFIRMED VULNERABILITY - Medium risk for abuse

---

### 3. CODE INJECTION: WhatsApp Web Script Injection
**Severity:** HIGH
**Files:**
- `/deobfuscated/plasmo-overlay.db6b23e9.js` (lines 51-77)
- `/deobfuscated/assets/w.js`
- `/deobfuscated/assets/i.js`

**Description:**
The extension injects custom JavaScript files (`w.js` and `i.js`) directly into WhatsApp Web to access internal APIs and extract data. This creates a significant attack surface.

**Evidence:**
```javascript
// Script injection from content script
const N = new MutationObserver((ne, ke) => {
    for (let te = 0; te < C.length; te++) {
        const Ie = document.querySelector(C[te]);
        if (Ie) {
            (0, Z.injectJsInsertWA)(chrome.runtime.getURL("assets/w.js")),
            (0, Z.injectJsInsertWA)(chrome.runtime.getURL("assets/i.js")),
            (0, H.sendToBackground)("LOGS", {
                title: "INJECT JS SUCCESS"
            }),
            ke.disconnect();
            break
        }
    }
});
```

**Risk:**
- Direct manipulation of WhatsApp Web's internal state
- Bypasses WhatsApp's intended API boundaries
- Potential for data interception or manipulation
- If extension is compromised, injected code could be weaponized

**Verdict:** CONFIRMED VULNERABILITY - High risk due to deep integration with target site

---

### 4. AUTHENTICATION: Google OAuth Integration
**Severity:** MEDIUM
**Files:**
- `/deobfuscated/manifest.json`
- `/deobfuscated/background.5fadff2f.js`
- `/deobfuscated/plasmo-overlay.db6b23e9.js`

**Description:**
The extension uses Chrome Identity API with Google OAuth for user authentication and tracking.

**Evidence:**
```json
// From manifest.json
"oauth2": {
    "client_id": "212318457565-pip8h2pjtoo3lg04esfkv2kr6b5cd6ke.apps.googleusercontent.com",
    "scopes": [
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ]
}
```

```javascript
// OAuth token acquisition
chrome.identity.getAuthToken({
    interactive: true
}, function(token) {
    if (chrome.runtime.lastError || !token) {
        reject(chrome.runtime.lastError);
        return;
    }
    resolve(token);
});
```

**Risk:**
- User identification and tracking across sessions
- Correlation of extracted contact data with user identity
- Potential for cross-service tracking

**Verdict:** CONFIRMED - Medium privacy concern

---

### 5. PERMISSIONS: Broad Access Scope
**Severity:** MEDIUM
**Files:**
- `/deobfuscated/manifest.json`

**Description:**
The extension requests several powerful permissions that enable extensive data collection.

**Evidence:**
```json
{
    "permissions": ["storage", "identity", "unlimitedStorage"],
    "host_permissions": ["*://*.whatsapp.com/*"],
    "content_scripts": [{
        "matches": ["https://web.whatsapp.com/*"],
        "js": ["plasmo-overlay.db6b23e9.js"],
        "run_at": "document_end"
    }]
}
```

**Permissions Analysis:**
- `storage` + `unlimitedStorage`: Can store unlimited extracted contact data locally
- `identity`: OAuth access for user tracking
- `host_permissions`: Full access to WhatsApp Web domain
- Content script injection on WhatsApp Web

**Risk:**
- Broad permission scope enables extensive data collection
- Unlimited storage could accumulate large datasets
- No CSP restrictions in manifest

**Verdict:** CONFIRMED - Standard concern for this type of extension

---

## False Positives

| Pattern | Location | Reason for FP |
|---------|----------|---------------|
| Firebase SDK code | background.5fadff2f.js | Legitimate Firebase Auth library (Apache 2.0 licensed) |
| `chrome.downloads.download` | background.5fadff2f.js, plasmo-overlay.db6b23e9.js | Legitimate download functionality for exporting contacts |
| `chrome.runtime.setUninstallURL` | background.5fadff2f.js | Standard extension lifecycle management |
| Console hooking in i.js | assets/i.js (lines 14-24) | Development/anti-debugging wrapper, not malicious |
| Regenerator runtime | background.5fadff2f.js | Standard Babel polyfill for async/await |

---

## API Endpoints & External Connections

| Endpoint/Domain | Purpose | Files |
|----------------|---------|-------|
| `googleapis.com/auth/*` | Google OAuth authentication | Inferred from oauth2 config |
| `chromewebstore.google.com` | Review page redirect | background.5fadff2f.js, plasmo-overlay.db6b23e9.js |
| Chrome Identity API | OAuth token management | Multiple files |
| Chrome Storage API | Local data persistence | Multiple files |
| Chrome Downloads API | Contact export functionality | background.5fadff2f.js, plasmo-overlay.db6b23e9.js |

**Note:** No hardcoded remote endpoints found for data exfiltration in deobfuscated code, but Firebase integration suggests potential cloud backend (Firebase project details not visible in code).

---

## Data Flow Summary

1. **Injection Phase:**
   - Content script (`plasmo-overlay.db6b23e9.js`) monitors WhatsApp Web DOM
   - When target elements detected, injects `w.js` and `i.js` into page context

2. **Authentication Phase:**
   - Uses Chrome Identity API to authenticate user via Google OAuth
   - Obtains user email/profile for tracking purposes

3. **Data Collection Phase:**
   - Injected scripts (`i.js`) access WhatsApp Web's internal webpack modules
   - Extracts contact lists, group info, labels from WhatsApp's internal state
   - Validates phone numbers via WhatsApp's contact query API
   - Retrieves last message content and metadata for each contact

4. **Data Processing Phase:**
   - Parses contact information including names, phone numbers, countries
   - Infers geographic location from phone number country codes
   - Enriches data with message history and contact labels

5. **Data Export Phase:**
   - Sends extracted data via `postMessage` to content script
   - Content script forwards to background page
   - Background page triggers Chrome downloads API for file export
   - Data stored in local storage with unlimited quota

**Critical Flow:**
```
WhatsApp Web Internal APIs
    ↓ (accessed via injected w.js)
WPP Wrapper Functions
    ↓ (i.js processes)
Contact Extraction Pipeline
    ↓ (postMessage)
Content Script
    ↓ (chrome.runtime.sendMessage)
Background Page
    ↓ (chrome.downloads.download)
User's Download Folder
```

---

## Overall Risk Assessment

**RISK LEVEL: HIGH**

### Justification:
1. **Extensive PII Collection (HIGH):** The extension systematically harvests highly sensitive personal data including phone numbers, names, message content, and geographic location for potentially thousands of contacts per user.

2. **Minimal User Transparency (HIGH):** While the extension's name indicates contact extraction, the full scope of data collection (last messages, location inference, business status, etc.) is not clearly disclosed.

3. **Privacy Violations (HIGH):** Collects data about third parties (user's contacts) who have not consented to data collection by this extension.

4. **Code Injection Risk (MEDIUM-HIGH):** Deep integration with WhatsApp Web through script injection creates potential for misuse if extension is compromised or updated maliciously.

5. **OAuth Tracking (MEDIUM):** User identification enables correlation of extracted contact databases with user identities.

6. **Enumeration Capability (MEDIUM):** Phone number validation feature could be abused for large-scale contact discovery.

### Positive Factors:
- No evidence of remote data exfiltration to third-party servers in deobfuscated code
- Uses standard download API for local export
- Built on legitimate Plasmo framework
- No obvious obfuscated malware

### Negative Factors:
- Collects far more data than necessary (last message content is particularly invasive)
- No visible privacy policy or data handling disclosures in manifest
- OAuth integration enables user tracking
- Unlimited storage permission suggests long-term data retention
- 50,000+ users means significant data exposure at scale

---

## Recommendations

**For Users:**
1. Only use this extension if absolutely necessary for legitimate business purposes
2. Review and delete exported contact data immediately after use
3. Be aware that your contacts' phone numbers and message snippets are being collected
4. Consider GDPR/privacy implications if operating in regulated jurisdictions

**For Review:**
1. Request transparency about data retention and deletion policies
2. Verify Firebase backend configuration and data handling practices
3. Question necessity of last message content collection
4. Recommend removal of phone number validation feature (enumeration risk)
5. Request privacy policy disclosure in Chrome Web Store listing

---

## Conclusion

WA Contacts Extractor functions as a privacy-invasive data harvesting tool that extracts extensive contact information from WhatsApp Web. While not overtly malicious, it represents a **HIGH privacy risk** due to the volume and sensitivity of collected data, particularly the inclusion of last message content and third-party contact information. The extension should be considered high-risk for deployment in privacy-sensitive environments.

**Classification: HIGH RISK - Privacy-invasive contact harvesting tool**
