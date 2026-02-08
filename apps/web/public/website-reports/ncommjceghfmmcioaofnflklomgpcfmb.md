# Security Analysis Report: FinalScout - Find Anyone's Email

## Metadata
- **Extension ID**: ncommjceghfmmcioaofnflklomgpcfmb
- **Extension Name**: FinalScout - Find Anyone's Email
- **Version**: 1.3.1
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

FinalScout is a legitimate LinkedIn email finder tool that scrapes user data from LinkedIn profiles and sends it to the vendor's backend (finalscout.com) for email lookup services. The extension demonstrates **standard but privacy-concerning practices** typical of lead generation tools, including harvesting LinkedIn cookies, extracting profile data, and exfiltrating HTML content to remote servers.

**Overall Risk Assessment**: **MEDIUM**

The extension operates within its stated purpose but raises significant privacy concerns due to extensive data collection from LinkedIn profiles. No evidence of malicious code, obfuscation techniques, or backdoors was found. However, users should be aware of the comprehensive data harvesting that occurs when using this tool.

## Vulnerability Details

### 1. LinkedIn Cookie Harvesting (MEDIUM Severity)

**Finding**: The extension harvests LinkedIn authentication cookies (`li_at`, `li_a`, `JSESSIONID`) and transmits them base64-encoded to the vendor's backend.

**Files Affected**:
- `src/background.js` (lines 767-856)

**Code Evidence**:
```javascript
function with_credentials(e, t) {
  let n = Config.cookie || {},
    i = [new Promise(function(e, t) {
      chrome.cookies.get({
        url: "https://www.linkedin.com",
        name: n.li_at || "li_at"
      }, function(t) {
        e({
          name: "li_at",
          cookie: t
        })
      })
    }), new Promise(function(e, t) {
      chrome.cookies.get({
        url: "https://www.linkedin.com",
        name: n.li_a || "li_a"
      }, function(t) {
        e({
          name: "li_a",
          cookie: t
        })
      })
    })];
  // ... cookies are Base64 encoded and transmitted
  for (const e of t) n[e.name] = Base64.encode((e.cookie || {}).value || "");
}
```

**Analysis**:
- The extension collects LinkedIn session cookies to authenticate API requests to finalscout.com
- Cookies are encoded (not encrypted) and sent to `https://finalscout.com`
- This allows the vendor to make authenticated requests to LinkedIn on the user's behalf
- Legitimate use case for the extension's stated functionality but creates privacy/security dependency

**Verdict**: **Privacy concern, not malicious** - Standard practice for LinkedIn scraping tools, but users should be aware their LinkedIn session credentials are shared with the vendor.

---

### 2. Comprehensive Profile Data Exfiltration (MEDIUM Severity)

**Finding**: The extension extracts complete LinkedIn profile HTML (including experience, education, skills, languages) and sends it to remote servers.

**Files Affected**:
- `src/inject.js` (lines 1589-1739)

**Code Evidence**:
```javascript
function do_find_email_by_single(e, t) {
  let l = $(`${o.selector}`).prop("outerHTML");
  const {
    extra_html_selectors: r
  } = o || {};
  Array.isArray(r) && r.forEach(e => {
    const t = $(e);
    0 !== t.length && (l += t.prop("outerHTML"))
  })
  // ...
  const v = {
    trigger_position: i,
    inject_setting_version: o.ver || "v1",
    html: `<div>${l}</div>`,
    source: I
  };
  // Sent to finalscout.com via background.js
  request_background(Config.request_bg_types.single_find, {
    data: v
  }, function(n) { /* ... */ })
}
```

**Profile sections scraped** (from inject_setting, lines 476):
```javascript
extra_html_selectors: [
  "section:has(> #about)",
  "section:has(> #experience)",
  "section:has(> #education)",
  "section:has(> #skills)",
  "section:has(> #languages)"
]
```

**Analysis**:
- Full profile HTML is extracted and transmitted to `https://finalscout.com/api/plugin/find/email`
- Includes personal information, employment history, education, skills
- Data is used for email lookup services (legitimate use case)
- No evidence of unauthorized data retention or misuse

**Verdict**: **Privacy concern, expected behavior** - The extension functions as described, but users should understand the scope of data collection.

---

### 3. External Communication to Vendor Backend (LOW Severity)

**Finding**: All user interactions and profile data are sent to finalscout.com servers via HTTPS.

**Files Affected**:
- `src/background.js` (lines 878-940)

**API Endpoints Identified**:
```javascript
APIs: {
  url_finder: "/plugin/r/find/linkedin",
  batch_finder: "/plugin/r/scrape/linkedin",
  prospect_search: "/plugin/r/prospect",
  scrape_content_authors: "/plugin/r/scrape/content_authors",
  scrape_post_reactors: "/plugin/r/scrape/post_reactors",
  single_finder: "/api/plugin/find/email",
  single_finder_poll_result: "/api/plugin/find/email/status",
  tags: "/api/plugin/tags",
  setting_contact_tags: "/api/plugin/contact/tags",
  event_finder: "/plugin/r/scrape/event",
  plugin_config: "/api/plugin/config",
  verify_account: "/api/account/verify",
  report: "/api/plugin/report",
  notifications: "/api/plugin/notifications",
  plugin_logs: "/api/plugin/logs",
  user_profile: "/api/plugin/account/profile"
}
```

**Network Request Function** (background.js lines 878-940):
```javascript
function request_server(e, t, n, i, s, r) {
  let o = `${Config.server_base_path}${e}`;
  fetch(o, {
    method: s,
    headers: {
      "Content-Type": "application/json"
    },
    body: "POST" === s ? JSON.stringify(t) : void 0,
    withCredentials: !0,
    mode: "cors"
  }).then(e => e.json().then(t => ({
    rsp: t,
    status: e.status
  })))
}
```

**Analysis**:
- All communications use HTTPS (encrypted in transit)
- Uses `withCredentials: true` for authenticated requests
- Server base path is hardcoded to `https://finalscout.com`
- No evidence of communication with unauthorized third parties

**Verdict**: **Expected behavior** - Standard client-server architecture for SaaS extension.

---

### 4. Notification Polling (LOW Severity)

**Finding**: Extension polls for notifications every 30 minutes from finalscout.com servers.

**Files Affected**:
- `src/background.js` (lines 982-1011)

**Code Evidence**:
```javascript
poll_notifications_interval: 1800,  // 30 minutes in seconds

function poll_notifications() {
  const e = () => {
    request_server(Config.APIs.notifications, {
      plugin_type: Config.plugin_type
    }, t => {
      // Process notifications
      setTimeout(function() {
        e()
      }, 1e3 * Config.poll_notifications_interval)
    }, !1, "GET")
  };
  e()
}
```

**Analysis**:
- Background polling every 30 minutes to `/api/plugin/notifications`
- Used for in-app notifications (quota warnings, feature updates)
- No evidence of excessive data collection during polling

**Verdict**: **Benign** - Standard notification mechanism.

---

### 5. Chrome Storage Usage (LOW Severity)

**Finding**: Extension stores user settings and notification state in chrome.storage.local.

**Files Affected**:
- `src/background.js` (lines 755-763, 1142-1152)

**Code Evidence**:
```javascript
// Get closed notification IDs
chrome.storage.local.get(["closed_notification_ids"]).then(t => {
  let { closed_notification_ids: n } = t || {};
  Array.isArray(n) || (n = []), e(n)
})

// Save user settings
chrome.storage.local.set({
  user_settings: user_settings
})
```

**Analysis**:
- Stores user preferences (UI settings, dismissed notifications)
- No sensitive data stored locally
- Settings include: `opener_button_top` (UI position preference)

**Verdict**: **Benign** - Standard local storage usage.

---

### 6. Dynamic Configuration Updates (LOW Severity)

**Finding**: Extension fetches remote configuration from finalscout.com servers.

**Files Affected**:
- `src/background.js` (lines 942-964, 1050-1077)

**Code Evidence**:
```javascript
function init() {
  request_server(Config.APIs.plugin_config, {}, e => {
    update_config(e), poll_notifications()
  }, !1, "GET")
}

function update_config(e) {
  const { config: t, css: n } = e || {};
  if (t) {
    for (const e of ["request_bg_types", "plugin_type", "is_prd"])
      t.hasOwnProperty(e) && delete t[e];
    updateConfig(t)
  }
}
```

**Analysis**:
- Fetches configuration from `/api/plugin/config` endpoint
- Updates injection selectors, CSS, feature flags
- Filters out sensitive config keys (`request_bg_types`, `plugin_type`, `is_prd`)
- Uses 120-second cache to reduce polling frequency

**Verdict**: **Standard practice** - Allows vendor to update LinkedIn DOM selectors without requiring extension updates. No evidence of malicious use.

---

### 7. External Communication Channel (LOW Severity)

**Finding**: Extension is externally connectable from finalscout.com web pages.

**Files Affected**:
- `manifest.json` (lines 35-38)
- `src/background.js` (lines 1155-1161)

**Manifest Configuration**:
```json
"externally_connectable": {
  "matches": [
    "https://finalscout.com/*"
  ]
}
```

**Message Handler** (background.js):
```javascript
chrome.runtime.onMessageExternal.addListener(function(e, t, n) {
  if ("finalscout:version" === e.type) {
    n({ version: get_version() })
  } else if ("finalscout:li:cookies" === e.type) {
    with_credentials(e => { n(e) })
  }
})
```

**Analysis**:
- Allows finalscout.com web pages to request extension version and LinkedIn cookies
- Restricted to finalscout.com domain only
- Used for web-extension integration (legitimate use case)

**Verdict**: **Standard integration pattern** - No security risk as it's properly restricted to vendor's domain.

---

### 8. PostMessage Communication (LOW Severity)

**Finding**: Content script communicates with embedded iframe via postMessage.

**Files Affected**:
- `src/inject.js` (lines 2125-2150, 2220-2227)

**Code Evidence**:
```javascript
function send_command_to_plugin_app({ type: e, data: t, callback_id: n }) {
  const s = init_plugin_app_iframe();
  if (s) {
    try {
      s.get(0).contentWindow.postMessage({
        type: e,
        callback_id: n,
        source: "finalscout:plugin",
        data: t,
        context: plugin_context
      }, "*")  // TARGET ORIGIN: "*"
    } catch (e) {
      console.error("[FinalScout]: failed to send msg to plugin app", e)
    }
  }
}

window.addEventListener("message", function(e) {
  const { data: t } = e, { source: n } = t || {};
  n && ["finalscout:plugin:app"].includes(n) && handle_plugin_app_message(t)
}, !1)
```

**Analysis**:
- Uses wildcard targetOrigin `"*"` in postMessage (minor security concern)
- Validates incoming messages by checking source identifier
- Iframe is loaded from `https://finalscout.com/plugin_app`
- Context includes current URL and profile identifiers

**Verdict**: **Minor weakness** - Should specify targetOrigin explicitly, but risk is minimal since iframe is from vendor's domain and messages are validated.

---

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| Base64 encoding | background.js:554-741 | Standard Base64 library (not obfuscation) |
| Cookie access | background.js:767-856 | Legitimate LinkedIn authentication for stated functionality |
| innerHTML usage | inject.js:566-568 | CSS injection via data URI (legitimate styling) |
| Dynamic config | background.js:942-964 | Feature flag/selector updates (not code injection) |
| jQuery library | src/jquery.js | Minified library (not malicious obfuscation) |
| SweetAlert2 library | src/sweetalert2.all.min.js | Minified UI library |
| Toastify library | src/toastify-js.js | Notification library |

## API Endpoints Summary

| Endpoint | Method | Purpose | Data Transmitted |
|----------|--------|---------|------------------|
| /plugin/r/find/linkedin | POST | Batch email finder | LinkedIn search URL, cookies |
| /plugin/r/scrape/linkedin | POST | Batch profile scraper | Search URLs, trigger position, tags |
| /api/plugin/find/email | POST | Single email lookup | Profile HTML, URL, cookies |
| /api/plugin/find/email/status | GET | Poll email lookup status | Contact ID |
| /api/plugin/config | GET | Fetch dynamic config | Version number |
| /api/plugin/notifications | GET | Fetch notifications | Plugin type |
| /api/plugin/tags | GET | Fetch contact tags | None |
| /api/plugin/contact/tags | POST | Update contact tags | Contact ID, tag list |
| /api/account/verify | POST | Resend email verification | None |
| /api/plugin/report | POST | Error reporting | Error details, URL |
| /api/plugin/account/profile | GET | User profile/credits | None |
| /plugin/r/scrape/content_authors | POST | Scrape post authors | Post URL |
| /plugin/r/scrape/post_reactors | POST | Scrape post reactors | Post data |
| /plugin/r/scrape/event | POST | Scrape event attendees | Event URL |

## Data Flow Summary

1. **User browses LinkedIn**: Content script (inject.js) monitors page for profiles/search results
2. **Profile detection**: Extension identifies LinkedIn profile/search pages using URL patterns
3. **Cookie harvesting**: Background script retrieves `li_at`, `li_a`, `JSESSIONID` cookies
4. **HTML extraction**: Content script extracts profile HTML including experience, education, skills
5. **Data transmission**: Profile data + cookies sent to finalscout.com via HTTPS POST
6. **Email lookup**: Backend processes data and returns found email addresses
7. **Result display**: Content script injects email results into LinkedIn page UI
8. **Contact management**: Tags and contacts stored on finalscout.com servers

## Permissions Analysis

| Permission | Usage | Justification |
|------------|-------|---------------|
| `cookies` | Read LinkedIn cookies | Required for authenticated API requests |
| `storage` | Local settings storage | User preferences, dismissed notifications |
| `host_permissions: linkedin.com/*` | DOM manipulation, data extraction | Core functionality - inject UI, scrape profiles |
| `host_permissions: finalscout.com/*` | Backend communication | API requests, authentication |

All permissions are necessary for stated functionality.

## Content Security Policy Analysis

**Manifest CSP**: Not explicitly defined (uses default MV3 CSP)

**Default MV3 CSP**:
- No inline scripts allowed
- No eval() or Function() constructor
- External scripts must be declared in web_accessible_resources

**Findings**: Extension adheres to MV3 security model. No CSP bypasses detected.

## Obfuscation Assessment

**Minified Libraries**: Standard libraries (jQuery, SweetAlert2, Toastify, Tooltipster, Base64)
**Core Code**: Deobfuscated code is readable with meaningful variable names
**Obfuscation Level**: None (beyond standard library minification)

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Rationale**:
- **No malicious behavior detected**: Extension operates as advertised
- **Privacy-invasive by design**: Extensive LinkedIn data harvesting is core functionality
- **Data exfiltration**: Profile data and cookies sent to vendor (expected for SaaS model)
- **No backdoors or hidden functionality**: All network requests go to declared vendor domain
- **No code injection**: Dynamic config updates are data-only (selectors/CSS)
- **Secure communication**: HTTPS used for all external requests
- **Legitimate business model**: Email lookup service for B2B sales/recruiting

### Concerns:
1. Users' LinkedIn session cookies are shared with third-party vendor
2. Complete profile HTML (including private sections) transmitted to remote servers
3. Vendor has ability to update injection selectors via remote config
4. PostMessage uses wildcard origin (minor issue)

### Strengths:
1. No malware, trojans, or backdoors detected
2. Transparent data flow (matches stated purpose)
3. Uses HTTPS for all communications
4. Adheres to Manifest V3 security requirements
5. No dynamic code execution (eval, Function constructor)

## Recommendations

**For Users**:
- Understand that your LinkedIn cookies and profile data are shared with FinalScout servers
- Review FinalScout's privacy policy before use
- Consider using a separate browser profile for this extension
- Be aware that the vendor can track which LinkedIn profiles you view

**For Vendor**:
1. Specify explicit targetOrigin in postMessage calls (replace `"*"`)
2. Document data retention policies clearly
3. Consider encrypting cookie values before transmission (not just base64)
4. Implement cookie rotation to minimize session token exposure
5. Add CSP to manifest for defense-in-depth

**For Security Researchers**:
- Monitor finalscout.com backend for data handling practices
- Review privacy policy for compliance with stated behavior
- Check for third-party data sharing agreements

## Conclusion

FinalScout is a **legitimate lead generation tool** with **privacy-invasive but disclosed functionality**. The extension harvests LinkedIn session cookies and profile data to provide email lookup services. While this raises significant privacy concerns, the behavior aligns with the extension's stated purpose and business model.

**No evidence of malicious code, obfuscation, or unauthorized data exfiltration was found.** The extension operates transparently within its scope, making it suitable for users who understand and accept the trade-off between privacy and convenience.

Users should be aware that using this extension grants FinalScout comprehensive access to their LinkedIn activity and profile data viewed during usage.

---

**Overall Verdict**: **MEDIUM RISK** - Privacy-invasive by design but not malicious. Operates as described with no hidden functionality.
