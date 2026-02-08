# Chrome Notes Security Analysis Report

## Extension Metadata
- **Extension ID**: lnfempckkegmaeleniojhjplemmebgfi
- **Name**: Chrome Notes
- **Version**: 1.5.4
- **Users**: ~100,000
- **Manifest Version**: 3
- **Developer**: RGB Studios - Justin Golden

## Executive Summary

Chrome Notes is a clean, simple notepad extension with **no malicious behavior detected**. The extension provides basic note-taking functionality with local storage, speech-to-text, text-to-speech, and backup/restore features. All code is well-commented, uses standard Chrome APIs appropriately, and contains no network requests, tracking, data exfiltration, or suspicious patterns.

**Risk Level**: CLEAN

The extension operates entirely offline with no external dependencies, SDKs, or network activity. All data is stored locally using localStorage. The codebase is small (7 JavaScript files, ~1,500 LOC total), transparent, and follows browser security best practices.

## Vulnerability Analysis

### 1. Network Activity & Data Exfiltration
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: Zero network requests in the entire codebase.
- No `fetch()` or `XMLHttpRequest` usage
- No remote scripts or CDN dependencies
- No analytics, tracking, or telemetry
- No external API calls
- Only Chrome Web Store URLs for extension rating/sharing (user-initiated)

**Code Evidence**:
```javascript
// Only network-related code - user clicks "Rate" button
document.getElementById('rate').onclick = () => {
    window.open('https://chrome.google.com/webstore/detail/lnfempckkegmaeleniojhjplemmebgfi');
};
```

All functionality is self-contained within the extension package.

### 2. Third-Party SDKs & Market Intelligence
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: No third-party libraries, frameworks, or SDKs detected.
- No Sensor Tower Pathmatics SDK
- No analytics platforms (Google Analytics, Mixpanel, etc.)
- No ad networks or tracking pixels
- No obfuscated vendor bundles
- Vanilla JavaScript only

The extension is completely dependency-free.

### 3. Chrome API Usage
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: Minimal, appropriate Chrome API usage matching declared permissions.

**Declared Permissions**:
```json
{
  "permissions": [
    "clipboardWrite",
    "clipboardRead",
    "downloads",
    "contextMenus"
  ]
}
```

**Chrome API Usage Analysis**:
- `chrome.contextMenus`: Creates "Add to new note" right-click option (background.js:12-16)
- `chrome.runtime.onMessage`: Internal messaging for context menu → note creation (scripts.js:13)
- `chrome.downloads.download`: Exports notes as .txt files (scripts.js:531-534)
- `chrome.windows.create`: Opens extension in popup window (scripts.js:230-235)
- `chrome.tabs.create`: Opens new tab from context menu (background.js:23-48)

All API usage is justified by extension functionality. No abuse patterns detected.

### 4. Content Script Analysis
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: No content scripts declared or present.

The extension does not inject code into web pages. It operates entirely as a popup/action interface with no page access beyond the context menu API.

**Manifest Verification**:
```json
// No content_scripts key present
// No host_permissions
// No web_accessible_resources
```

### 5. Dynamic Code Execution
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: No `eval()`, `Function()` constructor, or dynamic code execution.

The only timeout/interval usage is benign:
```javascript
// Toast notification auto-dismiss (toast.js:34)
toastTimeout = setTimeout(() => toast.classList.remove('show'), timeout);

// Animation cleanup (scripts.js:334)
setTimeout(() => notesElm.classList.remove('animate'), 500);
```

No code generation or execution from external sources.

### 6. Data Storage & Privacy
**Severity**: LOW (by design)
**Verdict**: CLEAN

**Finding**: All data stored locally using `localStorage`. No sync or cloud storage.

**Data Stored Locally**:
- `notes` array (user note content)
- `currentNote` ID
- `nextID` counter
- UI preferences (theme, fontSize, spellcheck, noteWidth, noteHeight)
- Backup timestamps

**Privacy Analysis**:
- Notes never leave the device
- No telemetry or usage tracking
- Backup/restore is manual and local only (JSON file download/upload)
- Extension warns users about localStorage clearing risks

**backup.js Lines 16-30**:
```javascript
function downloadLocalStorage() {
    const json = JSON.stringify(getLsData());
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `chrome-notes-backup-${new Date().toISOString().slice(0, 10)}.json`;
    // ... downloads locally, no upload
}
```

### 7. Clipboard Access
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: Standard clipboard API usage matching declared permissions.

**Code Evidence (scripts.js:154-173)**:
```javascript
document.getElementById('cut').onclick = () => {
    notesElm.focus();
    document.execCommand('cut');
};
document.getElementById('copy').onclick = () => {
    notesElm.focus();
    document.execCommand('copy');
};
document.getElementById('paste').onclick = () => {
    notesElm.focus();
    document.execCommand('paste');
};
```

Uses deprecated but safe `document.execCommand()` for clipboard operations. Only operates on the textarea within the extension, not on external pages.

### 8. Keylogger Detection
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: Keyboard listeners are minimal and non-invasive.

**Keyboard Event Analysis**:
```javascript
// modal.js:20 - Enter key to close modal
close.onkeydown = (evt) => {
    if (evt.key == 'Enter') close.onclick();
};

// scripts.js:427 - 'n' key for night mode toggle (when not typing)
document.onkeydown = (evt) => {
    if (evt.key === 'n' && notesElm !== document.activeElement && titleElm !== document.activeElement) {
        document.getElementById('night-mode').onclick();
        notesElm.blur();
    }
    storeSize();
};
```

No key capture, logging, or exfiltration. Listeners only for UI shortcuts.

### 9. Speech Recognition
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: Optional speech-to-text feature using standard Web Speech API.

**Code Evidence (scripts.js:41-91)**:
```javascript
const speechRecogSupported = 'webkitSpeechRecognition' in window || 'SpeechRecognition' in window;
if (speechRecogSupported) {
    recognition = new window.webkitSpeechRecognition();
    recognition.continuous = true;

    recognition.onresult = function (event) {
        for (let i = event.resultIndex; i < event.results.length; i++) {
            if (event.results[i].isFinal) {
                insertTextAtCursor(event.results[i][0].transcript);
            }
        }
    };
}
```

- Browser-native API (no third-party service)
- User-initiated only (click microphone button)
- Transcribed text inserted into local textarea only
- No audio or transcript exfiltration

### 10. Extension Enumeration/Killing
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: No `chrome.management` API usage. No extension detection or interference.

### 11. Remote Configuration/Kill Switches
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: No remote configuration loading. All behavior is static and hardcoded.

### 12. DOM Manipulation & Injection
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: Only manipulates its own extension UI, not web pages.

**DOM Operations**:
- Updates textarea, title input, note list (all within extension popup)
- Dynamic SVG icon generation from static paths (icon.js:1-45)
- Modal dialog management
- All HTML escaping properly handled (scripts.js:496-501)

```javascript
// XSS prevention in note title display
note.title
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;') || 'Untitled'
```

### 13. Obfuscation Analysis
**Severity**: NONE
**Verdict**: CLEAN

**Finding**: All code is readable, well-commented, and not obfuscated.

- Copyright headers present (HTML, scripts.js)
- Function and variable names are descriptive
- No minification, packing, or encoding
- Source code structure is organized and conventional

## False Positives

| Pattern | Files | Context | Verdict |
|---------|-------|---------|---------|
| `setTimeout` usage | toast.js, scripts.js | Animation cleanup, UI auto-dismiss | **False Positive** - Benign UI timing |
| `document.execCommand` | scripts.js | Cut/copy/paste buttons | **False Positive** - Standard clipboard API |
| `onkeydown` listeners | modal.js, scripts.js | Modal Enter key, night mode 'n' shortcut | **False Positive** - UI shortcuts only |
| localStorage access | scripts.js, backup.js | Note storage, UI preferences | **False Positive** - Expected local storage |
| Speech recognition | scripts.js | Optional speech-to-text | **False Positive** - Browser native API |

## API Endpoints

**Total External Endpoints**: 0

No network requests detected. The extension is fully offline.

**URLs Present in Code** (not called automatically):
- `https://chrome.google.com/webstore/detail/lnfempckkegmaeleniojhjplemmebgfi` - User clicks "Rate" button
- `https://rgbstudios.org` - Developer website link in About modal
- `mailto:feedback@rgbstudios.org` - Feedback email link

All are user-initiated navigation, not background requests.

## Data Flow Summary

```
User Input (typing)
    ↓
textarea.onchange → editNote()
    ↓
localStorage.setItem('notes', JSON.stringify(notes))
    ↓
Local Storage (persists on device)
```

**Key Findings**:
- All data flows are local (device → localStorage → device)
- No network transmission
- No external service dependencies
- User has full control via backup/restore

**Context Menu Flow**:
```
User selects text on page → right-click → "Add to new note"
    ↓
background.js contextMenu listener
    ↓
chrome.runtime.sendMessage({action: 'new_note', selection: text})
    ↓
scripts.js message listener → createNote()
    ↓
localStorage (local only)
```

Selected text is captured locally, not transmitted.

## Security Best Practices

**Strengths**:
1. ✅ Manifest V3 compliance
2. ✅ Minimal permission requests (only what's needed)
3. ✅ No content scripts (no page injection)
4. ✅ No network activity (fully offline)
5. ✅ Proper HTML escaping (XSS prevention)
6. ✅ Local-only data storage
7. ✅ No third-party dependencies
8. ✅ No obfuscation (transparent code)
9. ✅ Copyright and attribution present
10. ✅ User education (warns about localStorage clearing)

**Minor Observations** (not vulnerabilities):
- Uses deprecated `document.execCommand()` for clipboard (still functional, but could migrate to Clipboard API)
- localStorage has size limits and no encryption (acceptable for note-taking use case)
- No CSP defined in manifest (not required for action popups, but could add for defense-in-depth)

## Risk Assessment

### Overall Risk: CLEAN

**Risk Breakdown**:
- **Data Exfiltration**: None
- **Privacy Invasion**: None
- **Malicious Intent**: None
- **Extension Abuse**: None
- **User Deception**: None

**Confidence Level**: Very High

The extension does exactly what it claims: provides a simple, offline notepad. The small codebase (7 files, ~1,500 lines) has been fully audited with no suspicious patterns detected.

## Conclusion

Chrome Notes is a legitimate, privacy-respecting productivity tool with no security concerns. It exemplifies good extension development practices: minimal permissions, offline-first design, transparent code, and no unnecessary network activity or third-party dependencies.

**Recommendation**: SAFE FOR USE

The extension can be confidently recommended to users seeking a simple, privacy-focused note-taking solution. No further investigation required.

---

**Analysis Date**: 2026-02-06
**Analyst**: Claude Sonnet 4.5
**Files Analyzed**: 10 (7 JS, 1 HTML, 2 JSON)
**Lines of Code**: ~1,500
