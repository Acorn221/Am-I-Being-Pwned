# Boomerang for Gmail (mdanidgdpmkimeiiojknlnekblgmpdll) -- Vulnerability Report

**Extension Version:** 1.9.1 (Manifest V3)
**Analyzed Date:** 2026-02-06
**Analyst:** Automated Static Analysis + Manual Deep Dive
**Triage Flags:** 27 T1, 1 T2, 22 V1, 9 V2 across 16 categories

---

## Executive Summary

Boomerang for Gmail is a legitimate, well-known email scheduling and productivity tool (by Baydin Inc.) with millions of users. The triage flagged it as SUSPECT due to 27 T1 flags across categories including social_scraping, ext_enumeration, management_permission, cookie_access, script_injection, and jquery_html_dynamic. After thorough manual analysis, **the vast majority of these flags are FALSE POSITIVES** resulting from:

1. Social media share buttons for viral marketing (not scraping)
2. Extension conflict detection for troubleshooting (not enumeration for disabling)
3. Gmail CSRF token extraction required for Inbox Pause functionality (not cookie harvesting)
4. Legitimate UI injection into Gmail's DOM for send-later/boomerang buttons (not malicious script injection)
5. jQuery `.html()` calls for building extension UI dialogs (not XSS injection)

However, the analysis did identify **two real privacy/security concerns** of LOW-to-MEDIUM severity:

- **Email content sent to Baydin servers** (premium Respondable feature, with explicit user consent)
- **Hardcoded Google Analytics Measurement Protocol API secret** exposed in background.js
- **Server-controlled behavior** via remote JSON config from S3

**Overall Risk Assessment: LOW**

This is a legitimate commercial extension with standard patterns for a Gmail productivity tool. No evidence of malicious intent, data harvesting, affiliate injection, ad injection, or covert exfiltration was found.

---

## Architecture Overview

| Component | File | Purpose |
|-----------|------|---------|
| Service Worker | `background.js` (251 lines) | Message routing, GA tracking, Respondable computation, extension list relay |
| Content Script | `b4g.js` (327 lines) | Version check, inject bookmarklet, message bridge, troubleshoot mode |
| Content Script | `b4g_message_ui.js` (179 lines) | Server-push banner/dialog rendering |
| Main Application | `b4g_bookmarklet_1.9.1.js` (~27,500 lines) | Core Gmail UI manipulation, scheduling, Inbox Pause, Respondable, BCal |
| Popup | `popup.js` / `popup.html` | "Boomerang the Web" -- opens Gmail compose with current page URL |
| Login Dialog | `login_dialog.js` / `login_dialog.html` | Partitioned cookie auth iframe to b4g.baydin.com |
| Inbox Pause | `inbox_pause_dialog.html` | Iframe to b4g.baydin.com/inboxpause/dialog |

**Permissions:** `management`, `activeTab`
**Content Script Scope:** `https://mail.google.com/*` only
**Server Endpoints:** `b4g.baydin.com`, `s3.amazonaws.com/BoomerangForGmail/`

---

## True Positive Findings

### FINDING-1: Email Body Content Sent to Server (Premium Respondable)

**Severity:** LOW (consent-gated)
**CVSS 3.1:** 3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)
**File:** `b4g_bookmarklet_1.9.1.js:13264-13266`
**Category:** Data exfiltration (consent-gated)

**Evidence:**
```javascript
// b4g_bookmarklet_1.9.1.js:13264-13266
$.ajax({
    url: "https://b4g.baydin.com/mailcruncher/respondablescore",
    data: {"text": composeBodyText, "subject": get_transformed_respondable_subject($composeContainer)},
    type: "POST",
    xhr: xhr_with_credentials,
    ...
});
```

**Analysis:** When the premium "Respondable" feature is enabled, the full compose body text and subject line are sent to `b4g.baydin.com/mailcruncher/respondablescore` for ML-based analysis. This is gated behind THREE requirements (line 13122-13123):
1. User must be on a premium plan (`is_on_premium_respondable_plan()`)
2. User must have enabled the feature (`premium_respondable_is_enabled()`)
3. User must have explicitly consented via checkbox dialog (`has_consented_to_advanced_respondable()`)

The consent dialog (line 13004-13017) clearly states: "If you enable these features, Boomerang will securely send data about your messages to our servers for analysis."

**Verdict:** This is a legitimate, consent-gated feature. However, the email body is sent in plaintext over HTTPS without additional encryption, and the "data is discarded after analysis" claim is not verifiable client-side.

**PoC Scenario:** A premium user enables Respondable and types sensitive/confidential email content. The body text transits to Baydin servers. If Baydin is compromised, or the "discard" policy is not enforced, email content could be exposed.

---

### FINDING-2: Hardcoded Google Analytics Measurement Protocol API Secret

**Severity:** LOW
**CVSS 3.1:** 2.0 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)
**File:** `background.js:207-208`
**Category:** Information disclosure

**Evidence:**
```javascript
// background.js:207-208
const measurement_id = 'G-48B3G8LRPQ';
const api_secret = 'uIAXRk5NR3m2Mef57TbpxQ';
```

**Analysis:** The GA4 Measurement Protocol API secret is hardcoded in the extension source. This is a common practice in browser extensions (since the code is inherently client-side), but it allows anyone to send fake analytics events to Boomerang's GA4 property. This is a data integrity issue rather than a privacy issue.

**PoC Scenario:** An attacker extracts the API secret and floods Boomerang's analytics with fake events, corrupting their product metrics.

---

### FINDING-3: Server-Controlled Code Path via Remote JSON Config

**Severity:** LOW-MEDIUM (design concern)
**CVSS 3.1:** 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L)
**File:** `b4g.js:3, 77-174`
**Category:** Remote code execution surface

**Evidence:**
```javascript
// b4g.js:3
var configURL = "https://s3.amazonaws.com/BoomerangForGmail/bookmarklet/b4gconfig.json";

// b4g.js:77-155
fetch(configURL).then(r => r.text()).then(result => {
    var response = JSON.parse(result);
    var blockBoomerang = response["blockLoadingOfBoomerang"];
    // ... controls which version of bookmarklet is loaded
    // ... can show arbitrary server-controlled messages
    // ... can roll out different code to different user buckets
});
```

**Analysis:** The extension fetches a JSON config from S3 at every load that controls:
- Whether Boomerang loads at all (`blockLoadingOfBoomerang`)
- Which version of the bookmarklet JS is injected (`minVersion`, `maxVersion`)
- Gradual rollout by user email first letter (`rollout.buckets`)
- Server-controlled banner/dialog messages with arbitrary text and button URLs
- UI experiment flags (`meetMenuExperiment`)
- Domain-specific behavior overrides (`inboxPauseSpecialCaseDomains`)

This is a standard A/B testing and version control mechanism, but it means that if the S3 bucket is compromised, an attacker could:
- Block Boomerang for all users (DoS)
- Show phishing dialogs with arbitrary text/URLs
- Force rollback to older, potentially vulnerable versions

The config CANNOT inject arbitrary code -- it can only select between pre-bundled bookmarklet versions (1.8.6 through 1.9.1) that are already in the extension package. The `boomerang_version_exists()` check (b4g.js:35-41) validates the version string against `web_accessible_resources`.

---

### FINDING-4: GMAIL_AT CSRF Token Read from document.cookie

**Severity:** LOW (legitimate use)
**CVSS 3.1:** 2.0 (AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N)
**Files:** `b4g_bookmarklet_1.9.1.js:17673-17676, 26718-26721`
**Category:** Cookie access

**Evidence:**
```javascript
// b4g_bookmarklet_1.9.1.js:17672-17676
function get_gmail_at_variable() {
    var atStartIndex = document.cookie.indexOf("GMAIL_AT=") + 9;
    var atEndIndex = document.cookie.indexOf(";",document.cookie.indexOf("GMAIL_AT"));
    var at = document.cookie.substring(atStartIndex, atEndIndex);
    return at;
}
```

**Analysis:** The extension reads the `GMAIL_AT` cookie, which is Gmail's CSRF token. This token is used in two legitimate contexts:
1. **Inbox Pause** (line 17695-17699): Used to make authenticated requests to Gmail's internal API to manage mail filters for the pause feature
2. **Search URL construction** (line 26678): Used in Gmail API requests when navigating search results

The token is used exclusively for Gmail API calls on `mail.google.com` -- it is NOT exfiltrated to Baydin servers. This is the standard way Gmail extensions interact with Gmail's internal API.

---

### FINDING-5: Email Metadata Sent to Baydin Servers

**Severity:** LOW (expected for core functionality)
**CVSS 3.1:** 2.0 (AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N)
**Files:** `b4g_bookmarklet_1.9.1.js:6089-6120, 6787-6877`
**Category:** Data transmission

**Evidence:**
```javascript
// b4g_bookmarklet_1.9.1.js:6089-6120 (Boomerang a thread)
var url = "https://b4g.baydin.com/mailcruncher/schedulereturn";
url += "?subject=" + encodeURIComponent(subject);
url += "&senders=" + encodeURIComponent(JSON.stringify(senders));
url += "&guser=" + encodeURIComponent(gmailUser);
url += "&threadId=" + encodeURIComponent(get_boomerang_thread_id());
url += "&offset=" + encodeURIComponent(offset.valueOf());

// b4g_bookmarklet_1.9.1.js:6787-6877 (Send later)
params.subject = subject;
params.guser = gmailUser;
params.to = to;
params.cc = cc;
params.bcc = bcc;
params.threadId = threadId;
params.notes = notes;
```

**Analysis:** When using core Boomerang features (schedule return, send later), the following metadata is sent to Baydin:
- **Email subject line**
- **Gmail user email address**
- **Thread ID**
- **To/CC/BCC recipients** (for send-later)
- **Scheduling parameters** (return date, conditions)
- **User notes** (user-authored, not email body)

This is necessary for the scheduling service to function (the server needs to know WHICH email to return and WHEN). The email body content is NOT sent for standard scheduling -- only metadata. This is a reasonable data collection for the service provided.

---

## False Positive Analysis Table

| Triage Category | Flag Count | Files | Pattern Flagged | Verdict | Explanation |
|----------------|------------|-------|----------------|---------|-------------|
| **social_scraping** | 6 | b4g_bookmarklet_*.js | `facebook`, `twitter`, `linkedin`, `social` | **FALSE POSITIVE** | Social media share buttons for viral marketing ("Share Boomerang" with friends). Also, Gmail category tab detection (`category/social`). No scraping of social media data occurs. |
| **ext_enumeration** | 1+ | background.js:186, b4g.js:307 | `chrome.management.getAll()` | **FALSE POSITIVE** | Only called when user manually triggers troubleshoot mode (`?b4g_troubleshoot=1`). Lists enabled extensions to identify known conflicts (MixMax, Streak, Yesware, etc.). Extension list is stored temporarily in localStorage, displayed to user, then deleted (line 792). Never sent to server. |
| **management_permission** | 1 | manifest.json:11 | `"management"` permission | **FALSE POSITIVE** | Used exclusively for the troubleshooting conflict-detection feature described above. No extensions are disabled or modified. |
| **cookie_access** | 6 | b4g_bookmarklet_*.js | `document.cookie` (GMAIL_AT) | **FALSE POSITIVE** | Reads Gmail's CSRF token for authenticated internal API calls (Inbox Pause filter management, search). Token is never exfiltrated. Standard pattern for Gmail extensions. |
| **script_injection** | 7 | b4g.js:8-15 | `createElement("script")`, `appendChild(script)` | **FALSE POSITIVE** | Injects the bundled bookmarklet JS (`b4g_bookmarklet_X.Y.Z.js`) into the Gmail page. Source is always `chrome.runtime.getURL()` -- a local extension resource, not remote code. Required because content scripts cannot directly access Gmail's page-level JS context. |
| **jquery_html_dynamic** | 6 | b4g_bookmarklet_*.js, b4g_message_ui.js | `.html()`, `innerHTML` | **FALSE POSITIVE** | jQuery `.html()` used to build extension UI (dialogs, menus, settings panels, viral share hooks). `innerHTML` in `b4g_message_ui.js` is a static SVG close button icon (line 103-106). All content is extension-generated strings, not user-controlled input. No XSS risk. |
| **cookie_access** (partitioned) | 2 | login_dialog.js, b4g_bookmarklet_*.js | `getpartitionedcookie` | **FALSE POSITIVE** | Chrome's Storage Access API / partitioned cookie mechanism for maintaining Boomerang login state inside Gmail's iframe context. This is Chrome's recommended approach for third-party cookie deprecation. |
| **new Function()** | 2 | b4g_bookmarklet_1.9.1.js:26729,26875 | `new Function(get_data)` | **MINOR CONCERN** | Parses Gmail's internal API response (which returns JS array literals, not JSON). Input is Gmail's own internal data from `mail.google.com`. No external/attacker-controlled input reaches this code path. Equivalent to `eval()` on trusted same-origin data. |

---

## Data Flow Summary

### Data Sent to Baydin Servers (b4g.baydin.com)

| Endpoint | Data | Trigger | Consent |
|----------|------|---------|---------|
| `/mailcruncher/schedulereturn` | Subject, senders, guser, threadId, offset | User clicks "Boomerang" button | Implicit (core feature) |
| `/mailcruncher/schedulereturndelay` | Subject, guser, to/cc/bcc, threadId, offset, condition | User clicks "Send Later" | Implicit (core feature) |
| `/gmailmigration/boomerangfromdraft` | Same as above (POST) | Send Later (new Gmail UI) | Implicit (core feature) |
| `/mailcruncher/respondablescore` | **Full email body + subject** | Typing in compose (premium) | **Explicit consent dialog** |
| `/mailcruncher/checklogin2` | guser | Page load (if overlay enabled) | Implicit |
| `/mailcruncher/checkIfHasSeenAnnouncementsAndFTUEs` | guser | BCal feature check | Implicit |
| `/mailcruncher/tweet` | (none meaningful) | User clicks tweet button | Explicit (user clicks) |
| `/subscriptions`, `/insights/insightsfromgmail` | guser (in URL) | User clicks menu links | Explicit (user clicks) |

### Data Sent to Google Analytics
| Endpoint | Data | Trigger |
|----------|------|---------|
| `google-analytics.com/mp/collect` | Event name, action, label, client_id | Various UI interactions |

### Data Stored Locally (localStorage)
- User preferences (respondable settings, menu customizations, sticky options)
- Funnel/marketing attribution data (acquisition channel, ad source)
- Feature state (inbox pause, bookable calendar)
- Extension conflict list (temporary, deleted after display)

---

## What the Extension Does NOT Do

Based on thorough static analysis:

- **Does NOT read email body content** except for Respondable (consent-gated premium feature) and local readability metrics (computed in background.js web worker, never sent to server for basic plan)
- **Does NOT enumerate extensions covertly** -- only on explicit troubleshoot mode, never sends list to server
- **Does NOT disable other extensions** -- only identifies known conflicts for user display
- **Does NOT harvest cookies** -- reads only GMAIL_AT for legitimate Gmail API interaction
- **Does NOT inject ads** or modify email content for monetization
- **Does NOT perform affiliate injection**
- **Does NOT scrape social media** -- only has share buttons for "tell a friend" viral marketing
- **Does NOT exfiltrate contacts or address book data**
- **Does NOT have any obfuscated or encrypted payloads**
- **Does NOT fetch remote code** -- only fetches a JSON config that selects between pre-bundled local JS versions

---

## Overall Risk Assessment

**Rating: LOW**

Boomerang for Gmail is a legitimate, well-engineered productivity extension. All triage flags are either false positives or low-severity design patterns common to Gmail extensions. The only real data concern is the premium Respondable feature which sends email body text to Baydin servers, but this is:
1. Behind a paid plan gate
2. Behind an explicit user consent checkbox
3. Clearly disclosed in the consent dialog

The extension's codebase is clean, well-commented, and follows standard patterns for Gmail productivity tools. The `management` permission usage is conservative (read-only, user-triggered, data never leaves the client). The remote config mechanism is constrained to selecting between pre-bundled code versions and cannot inject arbitrary code.

**Recommendation:** Reclassify from SUSPECT to CLEAN. No further investigation warranted.
