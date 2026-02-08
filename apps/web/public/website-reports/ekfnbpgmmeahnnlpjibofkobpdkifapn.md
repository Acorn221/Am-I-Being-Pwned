# ProKeys Security Analysis Report

## Extension Metadata
- **Name**: ProKeys
- **ID**: ekfnbpgmmeahnnlpjibofkobpdkifapn
- **Version**: 4.0.2
- **User Count**: ~80,000
- **Manifest Version**: 3
- **Author**: Aquila Softworks

## Executive Summary

ProKeys is a productivity extension that provides text snippet expansion, macro substitution, and auto-completion features. The extension has been thoroughly analyzed for security vulnerabilities. **Overall Risk: CLEAN**

The extension operates entirely offline with no external network connections, implements legitimate text expansion functionality with appropriate permissions, and follows secure coding practices. The clipboard access and code evaluation features are properly sandboxed and used only for their stated purposes.

## Manifest Analysis

### Permissions Declared
- `tabs` - Used for snippet injection into active tabs
- `storage` - Local storage for user snippets and settings
- `contextMenus` - Right-click menu for snippet insertion
- `clipboardRead` - Read clipboard for paste macro functionality
- `offscreen` - localStorage migration and clipboard operations
- `scripting` - Dynamic script injection for snippet expansion

### Host Permissions
- `<all_urls>` - Required for snippet injection on any webpage

### Content Security Policy
- Uses sandboxed page at `html/sandbox.html` for safe math expression evaluation
- No external script sources
- Appropriate CSP restrictions in place

## Vulnerability Analysis

### 1. Clipboard Access (CLEAN - FALSE POSITIVE)
**Severity**: INFORMATIONAL
**Files**: `js/offscreen.js` (lines 50-56), `js/background.js` (line 340)
**Code**:
```javascript
// offscreen.js
"clipboard" === e.type && o(function() {
  const e = t.new("textarea"),
    n = document.activeElement.appendChild(e).parentNode;
  e.focus(), document.execCommand("Paste", null, null);
  const o = e.value;
  return n.removeChild(e), o
}())

// background.js - Clipboard macro pattern
I.PASTE_MACRO_REGEX.test(o) ? chrome.runtime.sendMessage("givePasteData", u((t => {
  e(o.replace(I.PASTE_MACRO_REGEX, t))
})))
```

**Analysis**: This is a **legitimate feature** for the `[[%p]]` macro. Users explicitly create snippets containing this macro to insert clipboard content. The clipboard is only read when:
1. User activates a snippet containing `[[%p]]`
2. User presses the hotkey (default Shift+Space)
3. The macro is replaced with clipboard content in the active text field

This is not covert data exfiltration - it's documented functionality requested by the user.

**Verdict**: CLEAN - Legitimate feature with user consent

### 2. Code Evaluation in Sandbox (CLEAN - FALSE POSITIVE)
**Severity**: INFORMATIONAL
**Files**: `js/sandbox.js` (line 1), `js/background.js` (line 1303)
**Code**:
```javascript
// sandbox.js
if("eval"===type)try{
  result=eval(message.expression)
}catch(e){
  console.error(e),
  result=message.expression
}

// background.js
"eval" === e.type && n(await chrome.runtime.sendMessage({
  target: "offscreen",
  type: "sandbox",
  data: e
}))
```

**Analysis**: The extension uses `eval()` in a **properly isolated sandboxed iframe** for mathematical expression evaluation in snippets. This is the correct security pattern:
- Expressions come from user-created snippets only
- Evaluation happens in sandboxed context (CSP-restricted iframe)
- Used for "Mathomania" feature (e.g., `[[5*3+2]]` → `17`)
- No remote code execution possible
- No access to extension APIs from sandbox

**Verdict**: CLEAN - Proper sandboxing implementation

### 3. Extensive DOM Manipulation (CLEAN - EXPECTED BEHAVIOR)
**Severity**: INFORMATIONAL
**Files**: `js/detector.js` (various lines)
**Code Patterns**:
```javascript
- innerHTML manipulation
- textContent access
- selectionStart/End manipulation
- contenteditable detection
- Range and Selection API usage
```

**Analysis**: This is the **core functionality** of a text expansion extension. The code:
- Detects when user types in text fields
- Monitors caret position
- Replaces snippet names with expanded text
- Handles rich text (contenteditable) and plain text inputs
- Implements auto-bracket completion

All DOM manipulation is within the user's active tab for legitimate text replacement purposes.

**Verdict**: CLEAN - Essential functionality for text expansion

### 4. Storage Migration Pattern (CLEAN)
**Severity**: INFORMATIONAL
**Files**: `js/background.js` (lines 868-911)
**Code**:
```javascript
const _ = chrome.runtime.getURL("html/offscreen.html");
async function R() {
  // ... creates offscreen document ...
  await chrome.offscreen.createDocument({
    url: _,
    reasons: [chrome.offscreen.Reason.LOCAL_STORAGE],
    justification: "Migrating localStorage from MV2 version to MV3 chrome.storage"
  })
}
```

**Analysis**: Legitimate MV2 → MV3 migration pattern. Chrome Manifest V3 requires offscreen documents to access `localStorage` from the service worker. This is the **recommended approach** from Chrome's documentation.

**Verdict**: CLEAN - Standard migration pattern

### 5. Context Menu Snippet Insertion (CLEAN)
**Severity**: INFORMATIONAL
**Files**: `js/background.js` (lines 1222-1246)
**Analysis**: Creates dynamic context menus for snippet insertion. All snippets are user-created and stored locally. No data exfiltration occurs.

**Verdict**: CLEAN

## False Positive Analysis

| Feature | Why It Appears Suspicious | Why It's Actually Safe |
|---------|---------------------------|------------------------|
| Clipboard access | Uses `execCommand("Paste")` | Only triggered by user-activated `[[%p]]` macro in their own snippets |
| `eval()` usage | Code evaluation is dangerous | Properly sandboxed, user-controlled expressions only |
| `<all_urls>` permission | Overly broad | Required for snippet expansion on any website |
| Dynamic script injection | Could inject malicious code | Only injects own content scripts, no remote code |
| Extensive DOM access | Could scrape data | Only manipulates text fields user is actively typing in |

## Network Analysis

**External Connections**: NONE

The extension makes **zero network requests**. All functionality is local:
- No analytics
- No tracking
- No data exfiltration
- No remote configuration
- No CDN dependencies

The only URL references are:
1. Chrome Web Store (for reviews/donations) - in options page HTML
2. Uninstall survey form - standard Chrome pattern
3. PayPal donation link - in options page

None of these are accessed programmatically.

## Data Flow Summary

1. **User creates snippet** → Stored in `chrome.storage.local` or `chrome.storage.sync`
2. **User types snippet name** → Content script detects via keypress monitoring
3. **User presses hotkey** → Snippet expanded in active text field
4. **Snippet contains macro** → Processed locally:
   - `[[%d(...)]]` - Date/time formatting
   - `[[%u(...)]]` - URL component extraction (current page only)
   - `[[%p]]` - Clipboard content insertion
   - Math expressions - Evaluated in sandbox

All data stays on user's machine.

## API Endpoints

**None** - This extension makes no HTTP requests.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

ProKeys is a well-designed, privacy-respecting productivity extension with no security vulnerabilities. The features that may appear concerning on surface analysis (clipboard access, eval, DOM manipulation) are all:

1. **Legitimate** - Necessary for advertised functionality
2. **User-initiated** - Only activated by explicit user actions
3. **Properly isolated** - Sandboxing where appropriate
4. **Transparent** - Functionality matches description
5. **Privacy-preserving** - Zero network activity

### Why This Extension is Safe

- ✅ No external network connections
- ✅ All data stored locally
- ✅ Proper use of sandboxing for code evaluation
- ✅ Clipboard access only for user-created macros
- ✅ No obfuscation beyond standard minification
- ✅ No remote code loading
- ✅ No analytics or tracking
- ✅ Open about permissions (documented in help section)
- ✅ Mature codebase (v4.0.2) with good practices

### Security Best Practices Observed

1. **MV3 Migration** - Properly updated to Manifest V3
2. **Sandboxed Evaluation** - Code execution isolated from extension context
3. **Message Validation** - Checks message targets and types
4. **Error Handling** - Catches and logs chrome.runtime.lastError
5. **No Dynamic Script Loading** - All code bundled at install time
6. **CSP Compliant** - Uses sandboxed pages for dangerous operations

## Recommendations

**For Users**: This extension is safe to use. The permissions requested are appropriate for its functionality.

**For Developers**: Continue following security best practices. Consider:
- Publishing source code to GitHub for transparency
- Adding more detailed permission explanations in the store listing
- Documenting the clipboard macro feature more prominently

## Conclusion

ProKeys passes security review with a **CLEAN** rating. It's a legitimate productivity tool with no malicious behavior, privacy violations, or security vulnerabilities. The extension is an excellent example of proper security practices in Chrome extension development.

---

**Analysis Date**: 2026-02-07
**Analyst**: Claude Sonnet 4.5
**Analysis Method**: Static code analysis + manifest review + data flow tracing
