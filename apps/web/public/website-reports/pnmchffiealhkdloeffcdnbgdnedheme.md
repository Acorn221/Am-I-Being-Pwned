# Security Analysis Report: History Trends Unlimited

## Extension Metadata
- **Extension ID**: pnmchffiealhkdloeffcdnbgdnedheme
- **Extension Name**: History Trends Unlimited
- **Version**: 1.8.6
- **User Count**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

History Trends Unlimited is a **CLEAN** extension that provides advanced browsing history analysis and visualization capabilities. The extension uses SQLite WASM to store and analyze Chrome history data locally, offering search, trends analysis, and export functionality. After comprehensive analysis of 6,240 lines of code, no security vulnerabilities, malicious behavior, or privacy violations were identified. The extension follows best practices for manifest v3, implements a strong Content Security Policy, and processes all data locally without external network communication.

**Overall Risk Level**: CLEAN

## Detailed Analysis

### 1. Manifest Permissions Analysis

**Declared Permissions**:
- `history` - Access browsing history (required for core functionality)
- `storage` - Store user preferences and sync data
- `unlimitedStorage` - Store large SQLite databases with history data
- `favicon` - Display website icons in UI
- `offscreen` - Background processing with WASM

**Content Security Policy**:
```json
{
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; child-src 'none'; connect-src 'none'"
}
```

**COEP/COOP Headers**:
- Cross-Origin-Embedder-Policy: `require-corp`
- Cross-Origin-Opener-Policy: `same-origin`

**Verdict**: ✅ **CLEAN**
- Permissions are minimal and appropriate for a history analysis tool
- CSP explicitly blocks all remote connections (`connect-src 'none'`)
- WASM is only used for SQLite database operations
- No content scripts injected into pages
- No webRequest/declarativeNetRequest permissions
- No sensitive permissions (cookies, webNavigation, tabs beyond opening UI)

### 2. Background Script Analysis

**File**: `js/background.js` (103 lines)

**Functionality**:
- Opens extension UI when toolbar icon is clicked
- Creates offscreen document for WASM/SQLite processing on startup
- Handles history sync messaging
- Manages auto-backup scheduling

**Key Code Patterns**:
```javascript
// Opens extension pages only - no external URLs
chrome.tabs.create({url:chrome.runtime.getURL( page )});

// Creates offscreen doc for SQLite WASM
await chrome.offscreen.createDocument({
    url: 'offscreen.html',
    reasons: ['WORKERS', 'BLOBS'],
    justification: "Use SQLite WASM to export the user's data"
});
```

**Verdict**: ✅ **CLEAN**
- No network requests
- No dynamic code execution
- No message interception
- No external URL loading
- Proper offscreen document usage for WASM

### 3. SQLite WASM Analysis

**WASM File**: `external/sqlite-wasm-3460100/sqlite3.wasm`
- **Size**: 939 KB
- **SHA256**: `65004f8df62100e359a23db76cf879e48232d20d852649e303c953f6818aa2fd`
- **Library**: Official SQLite 3.46.1 WASM build
- **Purpose**: Local database for history storage and querying

**Worker Files**:
- `js/worker.js` (1,082 lines) - Main database operations
- `js/import-worker.js` (416 lines) - Import/export functionality
- `js/historyWorker.js` (156 lines) - History sync wrapper

**Database Operations**:
```javascript
worker.db = new worker.sqlite3.oo1.DB({
    filename: 'htu.db',
    vfs: 'opfs',  // Origin Private File System - isolated storage
    flags: 'c'
});
```

**Tables Created**:
- `urls` - URL, host, root_domain, title
- `visits` - Visit metadata (time, date, transition type)
- `search_urls` - FTS5 full-text search index

**Verdict**: ✅ **CLEAN**
- Uses official SQLite WASM library (verified by binary signature)
- All data stored in OPFS (isolated, no cross-origin access)
- No external database connections
- No data exfiltration
- Proper parameterized queries (SQL injection protected)

### 4. Data Collection and Privacy

**Data Accessed**:
```javascript
// Reads Chrome history via official API
let historyItems = await chrome.history.search({
    'text': '',
    'maxResults': 1000000000,
    'startTime': syncStartTime
});

// Gets visit details
let visitItems = await chrome.history.getVisits({ url: historyItem.url });
```

**Data Storage**:
- All data stored locally in OPFS SQLite database
- No cloud sync
- No external transmission
- User preferences in `chrome.storage.local`

**Export Functionality**:
- Creates local TSV/ZIP files via Blob API
- Uses FileSaver.js library for downloads
- No upload capability
- Files saved directly to user's download folder

**Verdict**: ✅ **CLEAN**
- Accesses only history data (declared permission)
- All processing is local
- No analytics/telemetry
- No third-party services
- Export is user-initiated and local-only

### 5. Network Activity Analysis

**CSP Analysis**: `connect-src 'none'` explicitly blocks all network requests

**Code Review Results**:
- No `fetch()` calls to external domains
- No `XMLHttpRequest` to remote servers
- No WebSocket connections
- No third-party analytics SDKs
- No remote configuration fetching
- No update/kill switch mechanisms

**External Resources**:
All libraries are bundled locally:
- jQuery 3.3.1
- Mustache.js 3.0.1
- JSZip 3.1.5
- Dygraph 2.1.0
- ECharts 5.3.0
- FileSaver 2.0.0
- SQLite WASM 3.46.1

**Verdict**: ✅ **CLEAN**
- Zero network activity
- No remote dependencies
- No external API calls
- Fully offline operation

### 6. Code Execution Analysis

**Dynamic Code Patterns**:
```javascript
// Only legitimate uses found:
importScripts('utils.js', 'preferences.js', 'historyWorker.js');  // Worker imports
new Worker(utils.workerUrl('worker.js'));  // Web Worker creation
```

**No Malicious Patterns**:
- No `eval()` calls
- No `Function()` constructor abuse
- No `setTimeout/setInterval` with string arguments
- No dynamic script injection
- No `document.write()`

**innerHTML Usage**:
- Limited to UI rendering with Mustache templating
- User input is HTML-escaped: `utils.htmlEscape()`
- Search results use markers, then proper escaping

**Verdict**: ✅ **CLEAN**
- No arbitrary code execution
- Proper input sanitization
- Web Workers use static script URLs
- No obfuscation detected

### 7. Chrome API Usage

**APIs Used**:
- `chrome.action.onClicked` - Open extension UI
- `chrome.runtime.onStartup` - Initialize on browser start
- `chrome.runtime.onMessage` - Internal messaging only
- `chrome.tabs.create()` - Open extension pages (not external URLs)
- `chrome.history.search()` - Read history (declared permission)
- `chrome.history.getVisits()` - Get visit details
- `chrome.storage.local` - User preferences
- `chrome.offscreen` - WASM processing
- `chrome.i18n` - Internationalization

**No Suspicious APIs**:
- ❌ No `chrome.webRequest`
- ❌ No `chrome.cookies`
- ❌ No `chrome.tabs.executeScript`
- ❌ No `chrome.debugger`
- ❌ No `chrome.declarativeNetRequest`

**Verdict**: ✅ **CLEAN**
- Minimal API usage
- All APIs appropriate for declared functionality
- No interception/modification APIs
- No privileged abuse

### 8. Third-Party Dependencies

| Library | Version | Purpose | Risk |
|---------|---------|---------|------|
| SQLite WASM | 3.46.1 | Database | ✅ Official build |
| jQuery | 3.3.1 | UI framework | ✅ Bundled, no CDN |
| Mustache.js | 3.0.1 | Templating | ✅ Legitimate library |
| JSZip | 3.1.5 | Export compression | ✅ Legitimate library |
| ECharts | 5.3.0 | Data visualization | ✅ Legitimate library |
| Dygraph | 2.1.0 | Time series charts | ✅ Legitimate library |
| FileSaver.js | 2.0.0 | File downloads | ✅ Legitimate library |

**Verdict**: ✅ **CLEAN**
- All dependencies are well-known, legitimate libraries
- No suspicious third-party code
- No minified/obfuscated custom code
- All resources loaded locally (no CDN leaks)

### 9. UI/UX Security

**Pages**:
- `search.html` - History search interface
- `trends.html` - Trends visualization
- `options.html` - Extension settings
- `offscreen.html` - WASM processing context

**User Interactions**:
- Search and filter history
- View statistics and charts
- Export data to TSV/ZIP
- Configure preferences
- Delete history records

**Security Features**:
- Confirmation dialogs for deletion
- Error handling with user-friendly messages
- Database corruption detection and recovery
- Input validation on all fields

**Verdict**: ✅ **CLEAN**
- No phishing/misleading UI
- Transparent functionality
- Proper error handling
- No hidden features

## False Positive Analysis

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `importScripts()` | Multiple workers | Standard Web Worker API | ✅ Not malicious |
| `innerHTML` | buildInterface.js, search.js | Mustache templating with htmlEscape() | ✅ Safe usage |
| `addEventListener` | Multiple | Standard event handling | ✅ Legitimate |
| WASM execution | sqlite3.wasm | Official SQLite library | ✅ Verified safe |
| Large permissions | manifest.json | Required for history analysis | ✅ Justified |

## API Endpoints

**None detected.** The extension does not communicate with any external servers.

## Data Flow Summary

```
1. User browses web → Chrome stores history
2. Extension startup → Reads history via chrome.history API
3. SQLite WASM processes data → Stores in local OPFS database
4. User searches/analyzes → Queries local SQLite
5. User exports → Creates local TSV/ZIP file
6. Auto-backup (optional) → Saves to local downloads folder
```

**Key Points**:
- No data leaves the user's machine
- All storage is local (OPFS + chrome.storage.local)
- No cloud services
- No external API calls
- User has full control over data

## Security Strengths

1. **Strong CSP**: `connect-src 'none'` prevents all network access
2. **Manifest V3**: Uses latest security model
3. **Local-Only Processing**: All data remains on device
4. **Minimal Permissions**: Only requests what's needed
5. **No Content Scripts**: Cannot interfere with web pages
6. **Open Source Patterns**: Code follows best practices
7. **Input Sanitization**: HTML escaping prevents XSS
8. **Legitimate Libraries**: No suspicious dependencies
9. **OPFS Isolation**: Database stored in secure sandbox
10. **No Obfuscation**: Code is readable and well-commented

## Potential Concerns (Non-Security)

1. **Large Permission Scope**: Reads entire browsing history (but this is the core feature)
2. **UnlimitedStorage**: Can store large databases (required for history)
3. **WASM Usage**: Requires `wasm-unsafe-eval` in CSP (legitimate for SQLite)

**Note**: These are not vulnerabilities but inherent to the extension's functionality.

## Overall Risk Assessment

**Risk Level**: **CLEAN**

**Rationale**:
- No malicious code patterns detected
- No privacy violations
- No data exfiltration
- No network communication
- Transparent functionality
- Proper security practices
- Well-maintained codebase (2013-present, active development)
- Copyright headers indicate legitimate author (Randy Lauen)

**Confidence**: **HIGH**

This extension is a legitimate productivity tool for power users who want advanced history analysis capabilities. It processes all data locally, respects user privacy, and implements strong security boundaries. The codebase is clean, well-structured, and follows Chrome extension best practices.

## Recommendations

**For Users**:
- ✅ Safe to install for users who need advanced history analysis
- Review backup settings to avoid filling disk space
- Understand that the extension reads all browsing history (by design)

**For Developers**:
- Consider migrating from jQuery to modern frameworks
- Add subresource integrity for bundled libraries
- Document security architecture in README

## Conclusion

History Trends Unlimited is a **clean, privacy-respecting extension** that provides legitimate browsing history analysis functionality. No security vulnerabilities or malicious behavior were identified. The extension demonstrates proper security practices including strong CSP, local-only data processing, and minimal permissions. It is safe for installation by users who need comprehensive history search and visualization capabilities.

**Final Verdict**: ✅ **CLEAN** - No security concerns identified.
