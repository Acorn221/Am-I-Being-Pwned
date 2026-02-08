# Security Analysis Report: Desktop app for Google Tasks

## Extension Metadata
- **Extension ID**: lpofefdiokgmcdnnaigddelnfamkkghi
- **Name**: Desktop app for Google Tasks (Tasksboard)
- **Version**: 0.5.4
- **User Count**: ~500,000
- **Homepage**: https://tasksboard.com
- **Manifest Version**: 3

## Executive Summary

**OVERALL RISK: CLEAN**

Desktop app for Google Tasks (Tasksboard) is a minimal, benign Chrome extension that provides a side panel interface for Google Tasks through an embedded iframe. The extension contains only **28 lines of JavaScript code** across 2 files with no content scripts, no third-party libraries, no network interception, and no sensitive data collection.

The extension operates as a simple wrapper that loads the developer's web application (tasksboard.com) in a Chrome side panel with clipboard permissions. All functionality is delegated to the remote web application. There are no malicious patterns, obfuscation, or concerning behaviors present.

## Key Findings

### Positive Security Indicators
1. **Minimal codebase**: Only 28 lines of JavaScript with no obfuscation
2. **No content scripts**: Extension does not inject code into web pages
3. **No third-party SDKs**: No analytics, tracking, or market intelligence libraries
4. **Limited permissions**: Only requests `sidePanel` and `contextMenus` permissions
5. **Explicit host permissions**: Only requests access to tasksboard.com and localhost
6. **No dynamic code execution**: No eval(), Function(), or remote script loading
7. **No network interception**: No XHR/fetch hooking or webRequest manipulation
8. **Transparent behavior**: All functionality is visible in the minimal code

### Architecture
The extension uses a simple architecture:
- **Background Service Worker** (26 lines): Sets up side panel, context menu, and lifecycle handlers
- **Side Panel** (2 lines): Loads tasksboard.com/chrome in an iframe with clipboard permissions
- **No Content Scripts**: Extension does not interact with web pages

## Detailed Analysis

### 1. Manifest Permissions Analysis

**File**: `/deobfuscated/manifest.json`

#### Declared Permissions
```json
"permissions": ["sidePanel", "contextMenus"]
```

**Assessment**: ✅ SAFE
- `sidePanel`: Required for the core functionality (side panel UI)
- `contextMenus`: Used to add "Open TasksBoard" to context menu
- Both permissions are appropriate for stated functionality

#### Host Permissions
```json
"host_permissions": ["https://tasksboard.com/*", "http://localhost/*"]
```

**Assessment**: ✅ SAFE
- Limited to developer's own domain (tasksboard.com)
- Localhost access is for development purposes
- No wildcard host permissions or access to sensitive sites

#### Content Security Policy
**Finding**: No CSP declared (uses Chrome MV3 defaults)

**Assessment**: ✅ ACCEPTABLE
- Manifest V3 enforces strict CSP by default
- No inline scripts or remote code execution possible

### 2. Background Service Worker Analysis

**File**: `/deobfuscated/serviceWorker.js` (26 lines)

#### Code Overview
```javascript
// Set side panel to open on extension icon click
chrome.sidePanel.setPanelBehavior({openPanelOnActionClick:!0})

// On install, open sign-in page
chrome.runtime.onInstalled.addListener(e=>{
  e.reason==="install"&&chrome.tabs.create({url:"https://tasksboard.com/signIn"})
});

// Set uninstall feedback URL
chrome.runtime.setUninstallURL("https://forms.gle/SZznd2XAiPu4s4qJ9")

// Auto-reload on update
chrome.runtime.onUpdateAvailable.addListener(e=>{
  chrome.runtime.reload()
});

// Create context menu item
chrome.runtime.onInstalled.addListener(()=>{
  chrome.contextMenus.create({
    id:"openSidePanel",
    title:"Open TasksBoard",
    contexts:["all"]
  })
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((e,n)=>{
  e.menuItemId==="openSidePanel"&&chrome.sidePanel.open({windowId:n.windowId})
});
```

#### Security Assessment: ✅ CLEAN

**What it does**:
1. Configures side panel to open when extension icon is clicked
2. Opens tasksboard.com/signIn on first install (user onboarding)
3. Sets uninstall feedback form (Google Forms)
4. Auto-reloads extension when updates are available
5. Creates context menu item to open side panel
6. Handles context menu clicks

**No suspicious patterns**:
- ❌ No extension enumeration or killing
- ❌ No network interception (XHR/fetch hooks)
- ❌ No external API calls
- ❌ No data exfiltration
- ❌ No cookie access
- ❌ No storage manipulation beyond Chrome APIs
- ❌ No obfuscation (minified but straightforward)
- ❌ No dynamic code execution

### 3. Side Panel Analysis

**File**: `/deobfuscated/sidePanel.js` (2 lines)

#### Code Overview
```javascript
let t;
document.addEventListener("DOMContentLoaded",async()=>{
  const e=document.getElementById("app");
  if(!e)return console.error("No iframe found");
  e.src="https://tasksboard.com/chrome",
  e.allow="clipboard-read; clipboard-write";
  try{
    t=await chrome.tabs.query({active:!0,currentWindow:!0}).then(r=>r[0])
  }catch(r){
    console.error(`❌ Error while setting initTab ▶️ Details: ${JSON.stringify(r)}`)
  }
});
```

#### Security Assessment: ✅ CLEAN

**What it does**:
1. Waits for DOM to load
2. Finds the iframe element with id "app"
3. Sets iframe source to `https://tasksboard.com/chrome`
4. Grants iframe clipboard read/write permissions (declared in HTML)
5. Queries current active tab (stored but not used)

**Clipboard permissions**: The iframe is granted `clipboard-read` and `clipboard-write` permissions, which allows the tasksboard.com web app to access clipboard for copy/paste functionality.

**Assessment**: ✅ ACCEPTABLE
- Clipboard access is scoped to the iframe only (tasksboard.com)
- This is expected for a tasks/productivity app (copy/paste tasks)
- The extension itself does not access clipboard data

**No suspicious patterns**:
- ❌ No postMessage communication interception
- ❌ No DOM manipulation on other pages
- ❌ No keylogging or event listeners
- ❌ No SDK injection
- ❌ No data harvesting
- ❌ Tab query result stored but not transmitted

### 4. Content Scripts Analysis

**Finding**: No content scripts declared or present.

**Assessment**: ✅ POSITIVE
- Extension does not inject code into web pages
- Cannot access page content, cookies, or user interactions
- Cannot scrape data or manipulate DOM on external sites

### 5. Network Activity Analysis

#### Domains Contacted
1. **tasksboard.com** - Developer's web application (iframe content)
2. **forms.gle** - Google Forms (uninstall feedback)

#### Assessment: ✅ CLEAN
- No third-party tracking or analytics domains
- No market intelligence platforms (Sensor Tower, etc.)
- No ad networks or affiliate services
- All network activity is user-initiated (opening side panel)

### 6. Third-Party Code Analysis

**Finding**: No third-party libraries, SDKs, or frameworks detected.

**Libraries Searched For**:
- ❌ Sensor Tower Pathmatics SDK
- ❌ Sentry error tracking
- ❌ Google Analytics
- ❌ Firebase
- ❌ Ad injection libraries
- ❌ Proxy/VPN infrastructure
- ❌ AI conversation scrapers
- ❌ Chatbot interceptors

**Assessment**: ✅ CLEAN - Pure vanilla JavaScript with no dependencies.

### 7. Data Collection & Privacy

#### Data Access
The extension itself collects **NO data**. All functionality is delegated to the tasksboard.com web application running in the iframe.

**What the extension CAN access**:
- None (no content scripts, no broad host permissions)

**What the iframe CAN access**:
- Clipboard contents (when user copies/pastes)
- Any data user provides to tasksboard.com web app

**Assessment**: ✅ TRANSPARENT
- Extension is a thin wrapper with no data collection
- Privacy implications depend on tasksboard.com's web application (out of scope)
- User must trust tasksboard.com directly (same as visiting website)

### 8. Remote Control & Kill Switches

**Finding**: No remote configuration, kill switches, or server-controlled behavior.

**Assessment**: ✅ CLEAN
- No remote code loading
- No dynamic feature flags
- No "terminator" or "thanos" functions
- Behavior is static and defined in manifest

### 9. Extension Integrity

#### Obfuscation
**Level**: Minimal (standard minification only)
- Variable names shortened (e.g., `t`, `e`, `n`)
- No string encoding or control flow obfuscation
- Easily deobfuscated and readable

#### Code Patterns
**Assessment**: ✅ LEGITIMATE
- Standard Chrome Extension API usage
- No anti-debugging techniques
- No code injection
- No eval or Function() constructors

## Vulnerabilities & Findings

### Critical Vulnerabilities
**None identified.**

### High Severity Findings
**None identified.**

### Medium Severity Findings
**None identified.**

### Low Severity Findings
**None identified.**

### Informational Findings

#### INFO-1: Clipboard Access via Iframe
**Severity**: Informational
**Files**: `sidePanel.html`, `sidePanel.js`
**Details**: The side panel iframe is granted clipboard read/write permissions through the `allow` attribute. This allows the tasksboard.com web application to access clipboard contents.

**Risk**: LOW
- Clipboard access is scoped to the iframe only
- User must interact with the side panel for clipboard access
- Expected functionality for productivity/tasks app
- No different from visiting tasksboard.com directly in a tab

**Recommendation**: None (expected behavior)

#### INFO-2: Tab Query Not Used
**Severity**: Informational
**Files**: `sidePanel.js`
**Details**: The side panel queries the current active tab but stores the result in variable `t` without using it.

```javascript
t=await chrome.tabs.query({active:!0,currentWindow:!0}).then(r=>r[0])
```

**Risk**: NONE
- Query result is not transmitted or stored
- Likely unused code or planned feature
- No privacy implications

**Recommendation**: None (benign unused code)

## False Positives

| Pattern | Detection Reason | Why It's Safe |
|---------|-----------------|---------------|
| None detected | N/A | Extension is too minimal to trigger common false positive patterns |

## API Endpoints & Domains

| Domain | Purpose | Protocol | Data Sent | Assessment |
|--------|---------|----------|-----------|------------|
| tasksboard.com | Web application iframe | HTTPS | User-initiated interactions with web app | ✅ LEGITIMATE |
| forms.gle | Uninstall feedback form | HTTPS | User navigates to form on uninstall | ✅ LEGITIMATE |

## Data Flow Summary

```
User clicks extension icon
    → Side panel opens
        → Iframe loads tasksboard.com/chrome
            → User interacts with web app
                → All data exchange between iframe and tasksboard.com servers
                    (Extension has no visibility into this communication)
```

**Key Points**:
1. Extension acts as a simple launcher/wrapper
2. No data passes through extension code
3. All functionality delegated to tasksboard.com web application
4. Extension cannot intercept or observe iframe communications
5. No background data collection or exfiltration

## Overall Risk Assessment

### Risk Score: **CLEAN**

### Summary
Desktop app for Google Tasks is a minimal, transparent, and benign Chrome extension. It contains only 28 lines of JavaScript with no malicious patterns, third-party tracking, or concerning behaviors. The extension serves as a simple wrapper to load the developer's web application in a Chrome side panel.

### Risk Factors
| Category | Risk Level | Notes |
|----------|-----------|-------|
| Code Complexity | MINIMAL | Only 28 lines of JavaScript |
| Obfuscation | NONE | Standard minification only |
| Permissions | MINIMAL | Only sidePanel and contextMenus |
| Network Activity | MINIMAL | Only developer's own domain |
| Data Collection | NONE | Extension collects no data |
| Third-Party Code | NONE | No external libraries or SDKs |
| Content Scripts | NONE | No page interaction |
| Dynamic Behavior | NONE | No remote config or kill switches |

### Comparison to Malicious Extensions
Unlike malicious extensions found in this research:
- ❌ No extension enumeration/killing (VeePN, Troywell, Urban VPN)
- ❌ No XHR/fetch hooking (StayFree, StayFocusd, Flash Copilot)
- ❌ No market intelligence SDKs (Sensor Tower Pathmatics)
- ❌ No AI conversation scraping (StayFree, Flash Copilot)
- ❌ No ad/coupon injection (YouBoost, Troywell)
- ❌ No residential proxy infrastructure (Troywell)
- ❌ No browsing history upload (StayFree, StayFocusd)
- ❌ No remote kill switches (Troywell "thanos")

### Recommendation
**APPROVED FOR USE** - This extension poses no security or privacy risk beyond the inherent trust placed in the tasksboard.com web application itself. Users should evaluate tasksboard.com's privacy policy independently, as the extension is merely a launcher for that web service.

### Trust Model
Using this extension requires the same level of trust as:
1. Visiting tasksboard.com directly in a browser tab
2. Granting clipboard permissions to that website

The extension itself adds no additional privacy or security concerns beyond what already exists when using the tasksboard.com web service.

## Technical Details

### File Inventory
- **manifest.json** - 32 lines (extension configuration)
- **serviceWorker.js** - 26 lines (background logic)
- **sidePanel.js** - 2 lines (iframe loader)
- **sidePanel.html** - 27 lines (side panel UI)
- **images/** - Extension icons (3 files)
- **_locales/** - Translations (46 languages)

### Chrome APIs Used
- `chrome.sidePanel.*` - Side panel management
- `chrome.contextMenus.*` - Context menu integration
- `chrome.runtime.*` - Extension lifecycle
- `chrome.tabs.create()` - Open sign-in page on install
- `chrome.tabs.query()` - Get active tab (unused)

### External Resources
- None (no CDN, no remote scripts, no external fonts)

---

**Analysis Date**: 2026-02-06
**Analyst**: Claude Code Security Analysis
**Extension Version Analyzed**: 0.5.4
