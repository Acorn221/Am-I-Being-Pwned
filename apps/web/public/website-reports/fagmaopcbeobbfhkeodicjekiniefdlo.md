# Security Analysis Report: Copy Text Easily

## Extension Metadata
- **Extension ID**: fagmaopcbeobbfhkeodicjekiniefdlo
- **Name**: Copy Text Easily
- **Version**: 2.7.1
- **Manifest Version**: 3
- **Users**: ~30,000
- **Developer**: devapt.com
- **Last Updated**: 2026-02-09

## Executive Summary

**RISK LEVEL: MEDIUM**

Copy Text Easily is a legitimate clipboard history manager that allows users to view, manage, and reuse previously copied text. The extension uses React for its UI and implements a freemium model with pro features unlocked via DodoPayments license validation.

**Key Findings:**
- **Privacy Concern - System-wide clipboard monitoring**: Pro feature polls system clipboard every 700ms, capturing ALL clipboard activity including passwords, authentication tokens, credit cards, API keys, and other sensitive data copied from any application.
- **Unlimited local storage**: Uses `unlimitedStorage` permission to store clipboard history indefinitely, creating a persistent local database of potentially sensitive information without encryption.
- **Broad access**: Content script runs on `<all_urls>`, accessing all web pages to provide copy functionality.
- **No data exfiltration**: Clipboard data stays local - no transmission to external servers (verified).
- **Legitimate license system**: Uses DodoPayments for pro feature activation. Only license keys sent externally.

**Vulnerabilities Identified:**
1. **[MEDIUM] Unencrypted sensitive data storage** - Clipboard history stored in plaintext in local storage
2. **[MEDIUM] Continuous clipboard surveillance** - 700ms polling interval captures all clipboard activity when Pro enabled
3. **[LOW] Lack of data retention controls** - No automatic deletion or user control over history retention period

The static analyzer flagged 8 "exfiltration flows" (risk_score=70), but these are **false positives**. The "obfuscation" is standard React production minification, and the "exfiltration" flows are benign (license validation, uninstall URL, React error URLs). However, the privacy implications of system-wide clipboard monitoring justify a MEDIUM risk rating.

---

## Vulnerability Details

### 1. Unencrypted Sensitive Data Storage
**Severity**: MEDIUM
**CWE**: CWE-312 (Cleartext Storage of Sensitive Information)
**File**: background.js (lines 417-434), offscreen.js (lines 109-116)

**Evidence**:
```javascript
// background.js - Saves clipboard text to local storage unencrypted
chrome.storage.local.get(["history", "lastBrowserCopyText", "lastBrowserCopyTs"], e => {
  let n = Array.isArray(e.history) ? e.history : [];
  n.unshift({
    id: s,
    text: t,  // Plaintext clipboard content
    timestamp: o,
    site: "",
    isFavorite: !1,
    source: "system"
  });
  n.length > 100 && (n = n.slice(0, 100));
  chrome.storage.local.set({ history: n })  // No encryption
})
```

**Impact**:
Users copying sensitive information (passwords, API keys, credit cards, authentication tokens, private messages) will have this data stored in plaintext in the extension's local storage. If the user's device is compromised or accessed by another party, this sensitive data is immediately readable.

**Recommendation**:
- Implement encryption for clipboard history using Web Crypto API
- Provide opt-out for sensitive content (e.g., detect password fields and skip those copies)
- Add auto-clear functionality for history older than X days/hours
- Warn users prominently about what data is being stored

---

### 2. System-Wide Clipboard Surveillance
**Severity**: MEDIUM
**CWE**: CWE-359 (Exposure of Private Information)
**File**: offscreen.js (lines 76-120)

**Evidence**:
```javascript
// Polls clipboard every 700ms when Pro feature enabled
function v() {
  const e = () => {
    const e = yield navigator.clipboard.readText();  // Read system clipboard
    if (e && e !== s) {
      s = e;
      chrome.runtime.sendMessage({
        action: "saveHistory",
        text: e  // Send ALL clipboard content to background
      })
    }
  };
  yield e();
  a = setInterval(e, 700)  // Every 700 milliseconds
}
```

**Impact**:
When "Pro" features are enabled with system-wide clipboard monitoring, the extension captures:
- Passwords copied from password managers (1Password, LastPass, Bitwarden)
- Two-factor authentication codes copied from authenticator apps
- API keys and secrets copied from development environments
- Credit card numbers copied from banking sites
- Private messages copied from messaging apps
- Any other sensitive data copied from ANY application on the system

The 700ms polling interval ensures virtually all clipboard activity is captured before the user can paste, creating a comprehensive surveillance log.

**Recommendation**:
- Make clipboard monitoring opt-in with explicit warning about privacy implications
- Increase polling interval to reduce surveillance granularity (e.g., 3-5 seconds)
- Add exclude patterns for sensitive data (regex for credit cards, passwords, API keys)
- Provide clear UI indicator when monitoring is active (system tray icon/badge)
- Allow users to pause monitoring with keyboard shortcut

---

### 3. Indefinite Data Retention
**Severity**: LOW
**CWE**: CWE-404 (Improper Resource Shutdown or Release)
**File**: background.js (line 430)

**Evidence**:
```javascript
// Only limits to 100 entries, but never auto-deletes old entries
n.length > 100 && (n = n.slice(0, 100));
chrome.storage.local.set({ history: n })
```

**Impact**:
Clipboard history persists indefinitely (only limited to 100 entries). Sensitive data copied weeks or months ago remains in local storage. Combined with `unlimitedStorage` permission, large text entries could accumulate significant sensitive data over time.

**Recommendation**:
- Auto-delete entries older than 7/30/90 days (user configurable)
- Provide "Clear History" button prominently in UI
- Add "Clear on Browser Close" option for privacy-conscious users

---

### FALSE POSITIVE ANALYSIS

The following findings from the static analyzer are false positives:

#### 4. "Exfiltration Flow: chrome.storage.sync.get → fetch(forms.gle)"
**Severity**: FALSE POSITIVE
**File**: background.js (line 437)
**CWE**: N/A

**Evidence**:
```javascript
chrome.runtime.onInstalled.addListener(e => {
  e.reason === chrome.runtime.OnInstalledReason.INSTALL &&
    (chrome.runtime.setUninstallURL("https://forms.gle/8WHtD7NvsxBcX7b4A"),
     chrome.tabs.create({
       url: "https://devapt.com/copy-text-easily/how-to-use?extension=true&utm_source=background&utm_medium=extension&utm_content=how-to-use"
     }))
})
```

**Analysis**:
The `forms.gle` URL is only set as the uninstall URL via `chrome.runtime.setUninstallURL()`. This is a standard Chrome API that sets a feedback form URL opened when the user uninstalls the extension. No data is sent to forms.gle by the extension itself - Chrome handles this when the user uninstalls. This is a **benign** practice used for collecting uninstall feedback.

**Verdict**: NOT A VULNERABILITY

---

#### 5. "Exfiltration Flow: chrome.tabs.query → *.src(reactjs.org)"
**Severity**: FALSE POSITIVE
**File**: popup.js, panel.js, contentScript.js, background.js
**CWE**: N/A

**Evidence**:
```javascript
function l(e) {
  for (var t = "https://reactjs.org/docs/error-decoder.html?invariant=" + e,
       n = 1; n < arguments.length; n++)
    t += "&args[]=" + encodeURIComponent(arguments[n]);
  return "Minified React error #" + e + "; visit " + t + " for the full message..."
}
```

**Analysis**:
The `reactjs.org` URLs are **never actually loaded or fetched**. They are part of React's production error handling system - when a React error occurs in production (minified code), React generates an error message that includes a URL to the React documentation explaining the error. The URL is constructed but never sent anywhere. This is standard in all production React builds.

**Verdict**: NOT A VULNERABILITY

---

#### 6. "Exfiltration Flow: chrome.storage.sync/local.get → fetch(forms.gle)"
**Severity**: FALSE POSITIVE
**File**: background.js, panel.js, contentScript.js
**CWE**: N/A

**Analysis**:
There is **no fetch to forms.gle anywhere in the codebase**. The static analyzer incorrectly traced data flow from storage APIs to the uninstall URL (which is not a fetch call). Searching the entire codebase confirms:
- `forms.gle` appears only once: in `setUninstallURL()` call
- No `fetch("forms.gle")` or similar network call exists
- All clipboard history data stays in `chrome.storage.local`

**Verdict**: NOT A VULNERABILITY

---

#### 7. "innerHTML Flows"
**Severity**: FALSE POSITIVE
**File**: contentScript.js, panel.js
**CWE**: N/A

**Evidence**:
```javascript
// React property definition (not actual usage)
"children dangerouslySetInnerHTML defaultValue defaultChecked innerHTML suppressContentEditableWarning..."

// SVG icon injection (static)
f.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 17v5M5 17h14l-1-7H6l-1 7zM9 9V4a3 3 0 0 1 3-3h0a3 3 0 0 1 3 3v5"/></svg>'
```

**Analysis**:
- The `innerHTML` string in the first example is part of React's internal property mapping (defining which DOM properties React supports). This is not actual DOM manipulation.
- The SVG innerHTML assignments are **hardcoded static strings** for icon rendering (pin icon). No user input or message data is involved.
- The static analyzer's claim "message data → *.innerHTML" is incorrect - there is no dynamic innerHTML assignment from message data.

**Verdict**: NOT A VULNERABILITY

---

## False Positives Analysis

The ext-analyzer static analysis tool produced significant false positives:

**8 "exfiltration flows"**:
- 3x Chrome storage → fetch(forms.gle): **Incorrect data flow tracing**. No such fetch exists.
- 3x Chrome tabs/storage → reactjs.org src: **React error URLs, never loaded**.
- 2x Legitimate license validation flows to DodoPayments (expected behavior for pro features).

**"Obfuscated" flag**: The code uses standard React production minification. The variables are minified (e, t, n, r, etc.) but this is normal for all React production builds, not intentional obfuscation to hide malicious code.

**Risk score of 70**: Inflated due to:
- Manifest permissions (30 points) - legitimate for clipboard history features
- False positive exfil flows (8 × 15 = 120 points, capped at 40)
- Misidentified obfuscation (+10 points)

The actual risk is **LOW**.

---

## API Endpoints Analysis

### 1. live.dodopayments.com
**Purpose**: License management for pro features
**Data Sent**:
- License key (user-provided)
- License instance ID
- Instance name

**Endpoints**:
- `/licenses/validate` - Check if license is valid
- `/licenses/activate` - Activate license on this device
- `/licenses/deactivate` - Deactivate license

**Frequency**:
- On pro activation/deactivation
- Every 24 hours (86400000ms) for validation

**Privacy Impact**: LOW - Only license keys are sent, no user data or clipboard content.

**Code Reference** (background.js, lines 442-609):
```javascript
// Validate license every 24 hours
function t() {
  chrome.storage.sync.get(["licenseKey", "iKey"], t => {
    const e = (t.licenseKey || "").trim(),
          o = (t.iKey || "").trim();
    if (e && o) {
      const t = yield fetch("https://live.dodopayments.com/licenses/validate", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          license_key: e,
          license_key_instance_id: o
        })
      });
      // Store validation result in storage.a
      chrome.storage.sync.set({ a: n })
    }
  })
}
setInterval(t, 864e5) // 24 hours
```

The business ID check (`bus_5rONydDEeFFDSPhpEhXq9`) ensures licenses are for this specific product.

---

### 2. forms.gle/8WHtD7NvsxBcX7b4A
**Purpose**: Uninstall feedback (Google Form)
**Data Sent**: None by extension (Chrome handles navigation on uninstall)
**Frequency**: Once per uninstall
**Privacy Impact**: MINIMAL - Standard practice for collecting uninstall feedback

---

### 3. devapt.com
**Purpose**: Developer website
**Data Sent**: None (just URL parameters for tracking: utm_source, utm_medium, utm_content)
**Frequency**: Once on first install (opens help page)
**Privacy Impact**: MINIMAL - Standard onboarding

---

## Data Flow Summary

### Clipboard Data Flow
1. **Content Script** detects text selection on webpage
2. User clicks "Copy" button or uses keyboard shortcut
3. Text is copied to system clipboard using `navigator.clipboard.writeText()`
4. Message sent to **Background Script** to save to history
5. **Background Script** saves to `chrome.storage.local.history` (max 100 entries)
6. **No external transmission** - all data stays local

### System Clipboard Monitoring (Pro Feature)
1. **Offscreen Document** (offscreen.js) monitors system clipboard every 700ms
2. Reads clipboard using `navigator.clipboard.readText()` or `execCommand("paste")`
3. If new text detected, sends to Background Script via `saveHistory` message
4. Background Script saves to local storage
5. **No external transmission**

Code evidence (offscreen.js, lines 109-116):
```javascript
const e = yield navigator.clipboard.readText();
if (e && e !== s) {
  s = e;
  chrome.runtime.sendMessage({
    action: "saveHistory",
    text: e
  })
}
```

Code evidence (background.js, lines 413-434):
```javascript
e && "saveHistory" === e.action && "string" == typeof e.text && function(e) {
  const t = e.trim();
  const o = Date.now();
  chrome.storage.local.get(["history", "lastBrowserCopyText", "lastBrowserCopyTs"], e => {
    let n = Array.isArray(e.history) ? e.history : [];
    // Deduplication logic
    n.unshift({
      id: s,
      text: t,
      timestamp: o,
      site: "",
      isFavorite: !1,
      source: "system"
    });
    n.length > 100 && (n = n.slice(0, 100));
    chrome.storage.local.set({ history: n })
  })
}
```

### License Data Flow
1. User enters license key in settings
2. UI sends `activateLicense` message to Background Script
3. Background Script sends key to DodoPayments for validation/activation
4. Response stored in `chrome.storage.sync.a` (boolean pro status)
5. Validation repeats every 24 hours

**No user content or clipboard data is included in license requests.**

---

## Manifest Analysis

### Permissions Justification

| Permission | Justification | Risk |
|------------|---------------|------|
| `storage` | Store clipboard history and settings | LOW - Standard for extensions |
| `tabs` | Query active tab to show hostname in history entries | LOW - Read-only tab access |
| `unlimitedStorage` | Store large clipboard history (up to 100 entries, potentially long text) | LOW - Prevents quota errors |
| `offscreen` | Monitor system clipboard in background (pro feature) | MEDIUM - Requires clipboard access |
| `clipboardRead` | Read system clipboard for history monitoring | MEDIUM - Sensitive but justified for features |
| `commands` | Keyboard shortcuts (Ctrl+Shift+H, Ctrl+Shift+S) | LOW - User convenience |
| `contextMenus` | Right-click menu to enable/disable extension | LOW - Standard feature |
| `<all_urls>` | Inject content script on all pages for copy button | MEDIUM - Required for core feature |

### Host Permissions Analysis
**`<all_urls>`** is required because:
1. Extension adds a floating "Copy" button to selected text on any webpage
2. Users expect clipboard functionality to work on all sites
3. Content script (contentScript.js) must inject on all pages to detect text selection

**Alternative**: Could request `activeTab` only, but this would require user to click extension icon on each page, severely degrading UX.

**Data Access**: While content script runs on all pages, it does NOT:
- Access sensitive page data
- Scrape form inputs or passwords
- Exfiltrate browsing history
- Inject ads or modify page content (except for the copy UI)

---

## Overall Risk Assessment

### Risk Level: MEDIUM

**Justification**:
1. **No malicious intent**: Extension functions as advertised - clipboard history management. No data exfiltration, backdoors, or malware detected.
2. **Privacy concerns outweigh malware risk**: While not malicious, the extension's design creates significant privacy risks:
   - System-wide clipboard surveillance every 700ms captures sensitive data
   - Plaintext storage of clipboard history including passwords, tokens, keys
   - Broad `<all_urls>` access combined with clipboard monitoring
3. **Legitimate but invasive**: The Pro feature's clipboard monitoring is a legitimate business feature, but the implementation (700ms polling, no encryption, no exclude patterns) is privacy-invasive.
4. **User awareness gap**: Many users may not understand that enabling Pro features means the extension captures ALL clipboard activity from ALL applications (not just browser).

### Comparison to Static Analysis
The ext-analyzer reported **risk_score=70 (HIGH)** with 8 exfiltration flows. Analysis shows:
- **False positives**: forms.gle (uninstall URL), reactjs.org (error decoder URLs) - no actual data transmission
- **True positive on privacy risk**: The extension DOES access sensitive sources (clipboard, tabs, storage), though it doesn't exfiltrate them
- **Legitimate license validation**: DodoPayments flows are expected behavior

**Corrected assessment: MEDIUM RISK** - The extension is not malware, but its privacy implications for Pro users warrant elevated risk due to potential for sensitive data exposure if device is compromised or if future versions add data collection.

---

## Recommendations

### For Users
- **Use with caution**: This extension is legitimate but has significant privacy implications.
- **FREE version recommended**: The free version (extension-only clipboard monitoring) is safer than Pro.
- **WARNING - Pro features**: System-wide clipboard monitoring captures ALL clipboard activity from ALL applications:
  - Passwords from password managers (1Password, LastPass, etc.)
  - 2FA codes from authenticator apps
  - API keys copied from development tools
  - Credit card numbers from banking sites/apps
  - Private messages from messaging applications
  - This data is stored UNENCRYPTED in local storage
- **Consider alternatives**: If you need system-wide clipboard history, use OS-native tools (Windows Clipboard History, macOS clipboard managers) which may have better security controls.
- **If you must use Pro**: Regularly clear clipboard history, avoid copying highly sensitive data while monitoring is active, or pause monitoring when working with sensitive information.

### For Developer
1. **Add Privacy Policy link** in manifest and CWS listing to explain clipboard data handling
2. **Consider activeTab permission** as alternative for users who want less intrusive mode
3. **Encrypt clipboard history** in storage for users copying sensitive data
4. **Add clear UI indicators** when system clipboard monitoring is active (pro feature)
5. **Source maps**: Consider publishing source maps or unminified React code to improve transparency

---

## Conclusion

Copy Text Easily is a **legitimate extension** that provides clipboard history management as advertised, but with **significant privacy concerns** for Pro users. The high static analysis risk score (70) was partially driven by false positives, but the underlying privacy implications justify a MEDIUM risk rating.

**Vulnerabilities Identified:**
1. **[MEDIUM]** Unencrypted storage of sensitive clipboard data
2. **[MEDIUM]** System-wide clipboard surveillance every 700ms (Pro feature)
3. **[LOW]** Indefinite data retention without auto-deletion

**No malicious behavior or data exfiltration detected.**

The extension's use of powerful permissions (`clipboardRead`, `<all_urls>`, `unlimitedStorage`) is justified by its core functionality, but the implementation lacks basic privacy safeguards (encryption, retention limits, sensitive data filtering).

**Final Verdict**: MEDIUM RISK - Safe for basic use (free version), but Pro users should be aware of privacy implications. The extension is legitimate but could expose sensitive data if device is compromised or if future versions add telemetry/analytics.

**Recommendation**: FREE version acceptable; PRO version use with extreme caution.
