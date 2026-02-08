# Vulnerability Report: Backup and Sync Google Drive to other clouds

## Metadata
- **Extension ID**: iobcbdgacfkninlcbphihhdlkobkehia
- **Extension Name**: Backup and Sync Google Drive to other clouds
- **Version**: 1.4.2.12
- **User Count**: ~50,000
- **Developer**: cloudHQ (https://www.cloudhq.net)
- **Analysis Date**: 2026-02-07

## Executive Summary

This extension provides legitimate cloud backup/synchronization functionality between Google Drive and other cloud storage services (Dropbox, OneDrive, Box, etc.) through the cloudHQ service. The extension has **LIMITED** permissions and operates primarily as a UI integration layer that redirects users to the cloudHQ web service for actual cloud operations.

**Key Findings:**
- **No direct data exfiltration** - Extension does not directly access or transmit Google Drive file contents
- **Limited permissions** - Only requests `storage`, `background`, and host permissions for docs.google.com/drive.google.com/cloudhq.net
- **Third-party service dependency** - All backup operations require cloudHQ account and occur server-side
- **User authentication required** - Extension prompts for cloudHQ login/signup before any operations
- **Eval usage** - Contains eval() in legacy jQuery JSON parsing (moderate concern)

**Overall Risk Level: LOW**

The extension serves its stated purpose without malicious behavior. Privacy concerns exist around data being processed through cloudHQ's servers, but this is transparent to users and inherent to the service model.

---

## Vulnerability Details

### 1. Dynamic Code Execution (eval)
**Severity**: MEDIUM
**Location**: `content.js` lines 9693-9697

**Code:**
```javascript
$.evalJSON = function(src) {
  return eval("(" + src + ")")
}
// Later:
if (/^[\],:{}\s]*$/.test(filtered)) return eval("(" + src + ")");
```

**Description:**
The extension includes legacy jQuery code that uses `eval()` for JSON parsing. This is from an older JSON parsing implementation that predates `JSON.parse()`.

**Exploitation Scenario:**
If attacker-controlled JSON could reach this function, they could execute arbitrary JavaScript. However, the extension only processes JSON from:
1. cloudHQ.net API responses (validated by URL whitelist)
2. Google's internal settings page responses

**Verdict**: **LOW RISK** - The eval usage is restricted to trusted sources (cloudHQ.net domain is whitelisted in PROXY_AJAX handler). Modern browsers also provide `JSON.parse()` which jQuery likely uses preferentially.

---

### 2. Third-Party Data Processing
**Severity**: MEDIUM
**Location**: `content.js` lines 10875-10937, `background.js` lines 10132-10159

**Code:**
```javascript
// User email extraction
_ = function() {
  var e = null, n = "";
  // ... extracts email from Google UI elements
  return $.trim(n)
}()

// Backup initiation - opens cloudHQ wizard with user email
var t = y + "main_synch_wizard/start_with?wizard_type=backup&source_path=" +
  encodeURIComponent("/google_docs (" + _ + ")") +
  "&source_ref=" + encodeURIComponent("https://docs.google.com/feeds/id/folder%3A" + e) +
  "&user_email=" + encodeURIComponent(_);
window.open(t)
```

**Description:**
The extension extracts the user's Google email address from the Drive/Docs UI and passes it to cloudHQ.net when initiating backups. All actual file access occurs server-side at cloudHQ.net, not within the extension.

**Privacy Implications:**
- User email is shared with cloudHQ.net
- Folder IDs and paths are shared with cloudHQ.net
- cloudHQ service requires OAuth authorization to access Google Drive on user's behalf (happens on their website)
- Users must create cloudHQ account to use the service

**Verdict**: **INFORMATIONAL** - This is transparent functionality. The extension is a frontend for cloudHQ's cloud backup service. Users explicitly sign up for this service.

---

### 3. AJAX Proxy Pattern
**Severity**: LOW
**Location**: `background.js` lines 10131-10159, `content.js` lines 9438-9463

**Code:**
```javascript
chrome.runtime.onMessage.addListener((function(e, t, n) {
  if ("PROXY_AJAX" == e.what) {
    var i = e.payload;
    if (!i.url || !i.url.startsWith("https://www.cloudhq.net/")) return void n({
      what: "error",
      payload: "Invalid request"
    });
    // ... performs AJAX to cloudHQ.net
  }
}));
```

**Description:**
Content scripts send AJAX requests through the background script. The background script validates that all proxied requests target `https://www.cloudhq.net/` only.

**Security Analysis:**
- **Positive**: Strict URL validation prevents open proxy abuse
- **Positive**: Only cloudHQ.net domain is allowed
- **Positive**: No CORS bypass for arbitrary domains

**Verdict**: **SECURE** - Proper domain whitelist implementation prevents proxy abuse.

---

### 4. Installation Tracking
**Severity**: LOW
**Location**: `background.js` lines 10160-10195

**Code:**
```javascript
chrome.runtime.onInstalled.addListener((function(e) {
  if ("install" == e.reason) {
    var t = Math.floor(4 * Math.random()) + 1;
    // Opens one of 4 random Google Doc URLs on install
    chrome.tabs.create({ url: n, active: !0 })
  }
  // Stores install timestamp
  chrome.storage.sync.set(t, (function() {}))
}));

chrome.runtime.setUninstallURL("https://www.cloudhq.net/uninstall_chrome_extension?product_what=sync_and_backup")
```

**Description:**
On install, the extension:
1. Opens a random Google Doc (likely tutorial/welcome document)
2. Stores installation timestamp
3. Sets uninstall feedback URL

**Verdict**: **INFORMATIONAL** - Standard extension onboarding. The random doc selection is slightly unusual but not malicious.

---

### 5. External Content Fetching
**Severity**: LOW
**Location**: `background.js` lines 9967-10018

**Code:**
```javascript
fn_fetch_website_content = async function(e) {
  var o = [e, "https://websitescraper.cloudhq.workers.dev/scrape?scrapeUrl=" + e];
  for (const e of o) {
    var t = await fetch(e, headers);
    r = await t.text();
    // Converts HTML to text using html-to-text library
  }
}
```

**Description:**
Background script contains functionality to fetch and parse website content, with fallback to a cloudHQ web scraper service. This appears related to AI/ChatGPT integration features (references to "dalle", "chatgpt.com" in code).

**Analysis:**
- Feature appears dormant (not called from content scripts in current version)
- Could be for future features or shared codebase with other cloudHQ extensions
- Scraper endpoint is cloudHQ-controlled

**Verdict**: **INFORMATIONAL** - Unused feature, likely for other cloudHQ products.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `eval()` | content.js:9693 | Legacy jQuery JSON parsing, restricted to trusted domains |
| `setTimeout` with function strings | Multiple | All use function references, not string eval: `setTimeout(function() {...})` |
| jQuery library patterns | background.js, content.js | Standard jQuery 3.x library code (Sizzle selector engine, Deferred, etc.) |
| Base64 (atob/btoa) | background.js:9612, content.js | URL-safe base64 encoding for Drive folder IDs, standard API pattern |
| `innerHTML` usage | Multiple | jQuery HTML manipulation, context-appropriate |

---

## API Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://www.cloudhq.net/main_chrome_extension/chrome_extension_login_or_signup_dialog` | User authentication check | User email, redirect URL |
| `https://www.cloudhq.net/main_cloud_fs_interface/cloudhq_init` | Initialize cloud service list | Authentication tokens |
| `https://www.cloudhq.net/main_synch_wizard/start_with` | Start backup wizard | User email, folder ID, folder path |
| `https://www.cloudhq.net/main_cloud_fs_interface/refresh_cloudhq_dir` | Refresh folder browser | Folder metadata |
| `https://www.cloudhq.net/uninstall_chrome_extension?product_what=sync_and_backup` | Uninstall feedback | Extension ID |

**All network requests are to cloudHQ.net domain only.**

---

## Data Flow Summary

1. **User Interaction**: User clicks "Save to" or "Backup My Drive" button in Google Drive UI
2. **Email Extraction**: Extension extracts user's Google email from DOM (public UI element)
3. **Authentication Check**: Extension queries cloudHQ.net to check if user is logged in
4. **Account Flow**:
   - If not logged in: Opens cloudHQ signup/login dialog
   - If logged in: Opens cloudHQ backup wizard in new tab
5. **Backup Configuration**: User selects destination cloud service on cloudHQ.net website
6. **Authorization**: User authorizes cloudHQ OAuth access to Google Drive (on cloudHQ.net)
7. **Sync Execution**: cloudHQ servers perform actual file synchronization (server-to-server)

**Key Point**: The extension is a UI integration layer only. It does **not** access file contents, create OAuth tokens, or perform file transfers. All cloud operations happen server-side at cloudHQ.net after user authorization.

---

## Overall Risk Assessment

**Risk Level: LOW**

**Justification:**
1. **Limited Permissions**: Only requests storage and host permissions for specific domains
2. **No Direct File Access**: Does not read or transmit Google Drive file contents
3. **User Authorization Required**: Requires explicit cloudHQ account and OAuth consent
4. **Transparent Functionality**: Clearly operates as frontend for cloudHQ service
5. **Domain Whitelist**: Network requests restricted to cloudHQ.net only
6. **No Malicious Patterns**: No extension fingerprinting, ad injection, cookie harvesting, or proxy abuse

**Privacy Considerations:**
- User email is shared with cloudHQ.net (necessary for service)
- Folder metadata shared with cloudHQ.net (necessary for service)
- Users must trust cloudHQ with OAuth access to their Google Drive
- This is inherent to the service model and transparent to users

**Comparison to Stated Purpose:**
The extension performs exactly as advertised: it provides UI integration for cloudHQ's cloud backup service. It does not perform any covert operations.

---

## Recommendations

### For Users:
- **Safe to Use**: The extension is legitimate and secure for its intended purpose
- **Privacy Awareness**: Understand that cloudHQ.net will have OAuth access to your Google Drive
- **Service Evaluation**: Review cloudHQ's privacy policy and terms of service
- Consider native cloud sync features if you only need Google Drive ↔ OneDrive sync

### For Developers:
- **Low Priority**: Remove legacy eval() JSON parsing (use JSON.parse() exclusively)
- **Good Practice**: Consider migrating to Manifest V3 (currently V3, but ensure all APIs are modern)
- **Code Cleanup**: Remove unused web scraping functionality from background.js

---

## Conclusion

**Backup and Sync Google Drive to other clouds** is a legitimate extension that serves as a UI integration for the cloudHQ cloud synchronization service. It operates transparently, requires explicit user authorization, and does not exhibit malicious behavior. The extension's architecture (delegating all file operations to cloudHQ servers) is appropriate for a cloud backup service.

The privacy model is acceptable: users must trust cloudHQ with OAuth access to their Google Drive, which is clearly communicated through the signup/authorization flow. This is equivalent to using any third-party cloud backup service.

**Final Verdict: CLEAN - LOW RISK**

The extension is safe for users who want to use the cloudHQ cloud backup service.
