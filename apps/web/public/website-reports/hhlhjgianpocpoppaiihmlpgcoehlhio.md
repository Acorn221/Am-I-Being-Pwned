# Security Analysis Report: Super Simple Highlighter

## Extension Metadata
- **Extension ID**: hhlhjgianpocpoppaiihmlpgcoehlhio
- **Extension Name**: Super Simple Highlighter
- **Estimated Users**: ~200,000
- **Version Analyzed**: 28 (2025.10.28)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

**OVERALL RISK LEVEL: CLEAN**

Super Simple Highlighter is a legitimate text highlighting extension with no evidence of malicious behavior, data exfiltration, or privacy violations. The extension provides local-only functionality for creating, managing, and persisting text highlights on web pages using a client-side PouchDB database. All data remains local to the user's browser with no external network communication.

The extension demonstrates good security practices including:
- Restrictive Content Security Policy
- Optional permissions model (user must grant site access)
- Local-only data storage (PouchDB/IndexedDB)
- No network communication or telemetry
- No third-party SDKs or analytics
- No code obfuscation beyond standard minification of libraries

## Manifest Analysis

### Permissions Declared
```json
{
  "permissions": ["tts", "contextMenus", "storage", "activeTab"],
  "optional_permissions": ["scripting", "webNavigation"],
  "optional_host_permissions": ["*://*/*", "file:///*"]
}
```

**Analysis**:
- **tts**: Text-to-speech for reading highlights aloud (legitimate feature)
- **contextMenus**: Right-click menu for creating highlights (legitimate feature)
- **storage**: Local storage for highlight data and preferences (legitimate feature)
- **activeTab**: Access current tab for highlighting (legitimate, minimal scope)
- **scripting** (optional): Inject content scripts for highlight rendering (requires user permission)
- **webNavigation** (optional): Monitor page navigation for highlight restoration (requires user permission)
- **host_permissions** (optional): User must explicitly grant per-site access

**Verdict**: **SAFE** - Appropriate minimal permissions with good use of optional permissions model.

### Content Security Policy
```json
"content_security_policy": {
  "extension_pages": "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; upgrade-insecure-requests;"
}
```

**Analysis**:
- Blocks all external resources (`default-src 'none'`)
- Scripts only from extension itself (`script-src 'self'`)
- Styles from extension only (inline styles allowed for dynamic highlight styling)
- No external network communication permitted
- Forces HTTPS upgrades

**Verdict**: **SAFE** - Highly restrictive CSP prevents data exfiltration.

## Code Analysis

### Background Script (`js/background/main.js`)

**Functionality**:
- Database initialization and maintenance (PouchDB)
- Storage change listeners for syncing highlight definitions
- Context menu creation for highlight shortcuts
- Command handlers for keyboard shortcuts

**Key Operations**:
```javascript
// Database setup on install
static async #e() {
  const s = new e;
  await s.ensureDesignDocuments("auto"), await s.fixupIfRequired()
}

// Storage sync for highlight style changes
chrome.storage?.onChanged.addListener(o.#a)
```

**Network Activity**: NONE

**Verdict**: **CLEAN** - Pure local operations, no external communication.

### Content Script (`js/content_script/main.js`)

**Functionality**:
- DOM manipulation to create/remove highlight elements
- Range selection and XPath-based highlight positioning
- Event listeners for hover/focus interactions on highlights
- Message handlers for background script commands

**Key Operations**:
```javascript
// Highlight creation via DOM Range manipulation
mark(e, n, i, s = !0) {
  const a = this.#n.createElement(n);
  if (s) try {
    return e.surroundContents(a), i && (a.id = i), a.dataset.sshpid = t.newRandomID(), [a]
  } catch {}
  // ... fallback to manual range splitting
}

// Keydown listener ONLY on highlighted elements for delete functionality
e.addEventListener("keydown", this.#h, { capture: !1, passive: !0 })
```

**Keydown Handler Analysis**:
```javascript
async #d(e) {
  if (e.isComposing || "Backspace" !== e.key) return;
  e.stopPropagation();
  const t = new r(this.#n),
    n = t.getFirstMarkElement(e.target)?.id;
  return n ? h.deleteHighlight(n) : void 0
}
```

**Analysis**:
- Keydown listener is ONLY attached to highlighted `<mark>` elements via `focusin` event
- Only responds to Backspace key to delete the focused highlight
- Does NOT monitor keyboard input globally
- Does NOT capture or transmit keystrokes

**DOM Manipulation**: Limited to inserting/removing `<mark>` elements for highlights only.

**Network Activity**: NONE

**Verdict**: **CLEAN** - Legitimate DOM operations for highlighting. Keydown listener is NOT a keylogger (scoped to highlight elements only, only responds to Backspace for deletion).

### Storage Layer (`js/chunks/CvZYJjpo.js`)

**Database Implementation**:
```javascript
static #n() {
  if (!o.#i) throw new Error("PouchDB not available");
  return new PouchDB("sos", {
    auto_compaction: true,
    adapter: "idb",
    revs_limit: 10
  })
}
```

**Analysis**:
- Uses PouchDB 8.0.1 with IndexedDB adapter
- Database name: "sos" (stored locally in browser)
- Auto-compaction enabled for performance
- No replication or sync to external servers
- All highlight data stored client-side

**Data Stored**:
- Highlight positions (XPath ranges)
- Highlight text snippets (trimmed to 5000 chars for large selections)
- Highlight styles/colors
- Page URLs (for matching highlights to pages)
- Timestamps

**Verdict**: **CLEAN** - Pure local storage, no external database sync.

### Options/Popup Pages

**Functionality**:
- User interface for managing highlight styles
- Backup/restore functionality (local file save/load)
- Database diagnostics (PII-redacted export)
- Highlight overview/search

**Key Libraries**:
- Angular 1.x for UI
- jQuery 3.6.0
- Bootstrap (UI components)
- PouchDB replication-stream (local backup/restore only)

**Network Activity**:
- Only local `fetch()` call to load CSS from extension resources:
  ```javascript
  const i = await fetch(e);  // e = "/static/css/angular-csp.css" etc.
  ```

**Verdict**: **CLEAN** - No external network calls, only loading local resources.

## Vulnerability Assessment

### 1. Network Communication
- **Finding**: ZERO external network requests detected
- **Evidence**:
  - No `fetch()` or `XMLHttpRequest` to external domains
  - CSP blocks external resources
  - No hardcoded API endpoints found
  - Only local resource loading via `fetch()`
- **Severity**: N/A
- **Verdict**: **CLEAN**

### 2. Data Exfiltration
- **Finding**: No data exfiltration mechanisms
- **Evidence**:
  - No external API calls
  - No telemetry/analytics SDKs
  - PouchDB configured for local-only storage
  - Backup/export saves files locally (no upload)
- **Severity**: N/A
- **Verdict**: **CLEAN**

### 3. Third-Party SDKs
- **Finding**: No third-party analytics or tracking SDKs
- **Evidence**:
  - Only standard libraries (Angular, jQuery, PouchDB)
  - No Google Analytics, Sentry, Mixpanel, etc.
  - No obfuscated vendor code beyond minified libraries
- **Severity**: N/A
- **Verdict**: **CLEAN**

### 4. Keylogging / Input Monitoring
- **Finding**: No keylogging behavior
- **Evidence**:
  - Keydown listener ONLY on highlighted elements (via `focusin` event)
  - Only responds to Backspace key for deleting highlights
  - Does not capture text input or general keyboard activity
  - Listener is scoped and passive
- **Severity**: N/A
- **Verdict**: **CLEAN** (False positive from static analysis)

### 5. Extension Enumeration/Killing
- **Finding**: No extension manipulation
- **Evidence**:
  - No `chrome.management` API usage
  - No code to detect or disable other extensions
- **Severity**: N/A
- **Verdict**: **CLEAN**

### 6. Remote Configuration / Kill Switches
- **Finding**: No remote config mechanisms
- **Evidence**:
  - All configuration stored in local chrome.storage
  - No dynamic code loading from external sources
  - Highlight definitions hardcoded in extension
- **Severity**: N/A
- **Verdict**: **CLEAN**

### 7. Cookie/Session Harvesting
- **Finding**: No cookie access
- **Evidence**:
  - No `document.cookie` references
  - No cookie permissions in manifest
  - No session token extraction
- **Severity**: N/A
- **Verdict**: **CLEAN**

### 8. AI Conversation Scraping
- **Finding**: No AI platform targeting
- **Evidence**:
  - No content script injection on ChatGPT, Claude, etc.
  - User must manually grant per-site permissions
  - No DOM scraping of conversation elements
- **Severity**: N/A
- **Verdict**: **CLEAN**

### 9. Code Obfuscation
- **Finding**: Standard build tooling only
- **Evidence**:
  - Minified third-party libraries (Angular, jQuery, PouchDB)
  - Deobfuscated extension code shows clean module structure
  - No string encoding, eval(), or dynamic code generation
  - Variable names shortened by bundler (normal)
- **Severity**: N/A
- **Verdict**: **CLEAN**

### 10. Permissions Abuse
- **Finding**: Appropriate permission usage
- **Evidence**:
  - Optional permissions model (user must grant site access)
  - No broad `<all_urls>` by default
  - Scripting/webNavigation permissions are optional
  - activeTab provides minimal access
- **Severity**: N/A
- **Verdict**: **CLEAN**

## False Positive Analysis

| Pattern | Location | Reason | Legitimate Use |
|---------|----------|--------|----------------|
| `addEventListener("keydown")` | `js/content_script/main.js:188` | Keylogger flag | Scoped to highlighted elements only, responds to Backspace key for deleting highlights |
| `fetch()` | `js/overview/main.js:46` | External request flag | Loading local CSS files from extension (`/static/css/`) |
| `querySelector` / `getElementById` | Multiple files | DOM scraping flag | Legitimate DOM manipulation for highlight rendering |
| PouchDB `put/post` | `js/chunks/CvZYJjpo.js` | Database exfil flag | Local IndexedDB storage only, no replication |

## API Endpoints / External Domains

**No external API endpoints or domains detected.**

All URLs referenced are documentation/attribution links in UI only:
- https://www.dexterouslogic.com/ (developer website - display only)
- https://angularjs.org/ (library attribution - display only)
- https://pouchdb.com/ (library attribution - display only)

## Data Flow Summary

```
User Selection
    ↓
Content Script (Range capture)
    ↓
Background Script (Database write)
    ↓
PouchDB (IndexedDB storage)
    ↓
Content Script (DOM rendering as <mark>)
```

**No external data transmission at any stage.**

## Privacy Assessment

### Data Collection
- **User Data Collected**: Text snippets of user-created highlights, page URLs where highlights exist
- **Storage Location**: Local browser IndexedDB (PouchDB database "sos")
- **Third-Party Sharing**: NONE
- **Telemetry**: NONE
- **Analytics**: NONE

### User Control
- Users can export/import highlights as local files
- Users can delete all data via "Erase All" option
- Database diagnostics redact PII (page titles, URLs, text)
- No account creation or cloud sync

**Verdict**: **EXCELLENT** - Complete user privacy, no data leaves the browser.

## Overall Risk Assessment

### Risk Score: **CLEAN** (0/10)

### Risk Breakdown
- **Data Exfiltration Risk**: None
- **Privacy Violation Risk**: None
- **Malicious Behavior Risk**: None
- **Supply Chain Risk**: Low (standard open-source libraries)
- **Permission Abuse Risk**: None

### Justification
Super Simple Highlighter is a privacy-respecting, locally-focused extension that performs exactly as advertised. It:

1. **Uses minimal permissions** with optional permission model for site access
2. **Stores all data locally** in IndexedDB with no external sync
3. **Makes zero network requests** (CSP enforced)
4. **Contains no telemetry or analytics** of any kind
5. **Uses standard, unobfuscated code** with reputable libraries
6. **Provides user control** over data (export/import/delete)
7. **Follows security best practices** (restrictive CSP, MV3 compliance)

The extension is a model example of privacy-respecting browser extension development.

## Recommendations

### For Users
- **Safe to use**: This extension poses no security or privacy risks
- Grant permissions only on sites where you want highlighting functionality
- Use export feature periodically to backup highlights

### For Developers
- No security improvements needed
- Consider adding end-to-end encrypted cloud sync as optional feature (if desired)
- Code quality is excellent

## Conclusion

Super Simple Highlighter is **CLEAN** with no malicious behavior, privacy violations, or security concerns detected. The extension demonstrates exemplary security practices and respect for user privacy. It is safe for use by privacy-conscious users.

---

**Analyst Notes**: This extension serves as a positive example of how browser extensions should be built - minimal permissions, local-first architecture, no telemetry, and transparent functionality. No concerns raised during analysis.
