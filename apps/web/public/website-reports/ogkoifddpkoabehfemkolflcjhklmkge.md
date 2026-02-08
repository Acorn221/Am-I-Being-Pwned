# Vulnerability Report: Tweaks for YouTube

## Extension Metadata
- **Extension Name**: Tweaks for YouTube
- **Extension ID**: ogkoifddpkoabehfemkolflcjhklmkge
- **Version**: 3.86.2
- **User Count**: ~60,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Tweaks for YouTube is a legitimate YouTube enhancement extension that provides extensive customization options for the YouTube player and interface. The extension has **MEDIUM** risk due to its powerful custom CSS/JavaScript injection capabilities, which could be misused if a user enters malicious code. However, there is no evidence of malicious behavior in the extension's code itself.

**Overall Risk: MEDIUM**

The primary security concern is the extension's intentional feature that allows users to inject arbitrary JavaScript and CSS into YouTube pages. While this is a legitimate power-user feature, it creates potential for abuse if users unknowingly paste malicious code.

## Vulnerability Analysis

### 1. Custom JavaScript Injection Feature (MEDIUM)
**Severity**: MEDIUM
**Files**: `custom-css-and-js.bundle.js`, `background.bundle.js`
**Verdict**: LEGITIMATE FEATURE WITH SECURITY IMPLICATIONS

**Description**:
The extension provides a user-facing feature to inject custom JavaScript and CSS code into YouTube pages. The code is stored in `chrome.storage.local` and executed on YouTube pages.

**Code Evidence**:
```javascript
// custom-css-and-js.bundle.js:1028-1035
function d(e) {
  if (u) return chrome.runtime.sendMessage({
    action: "loadCustomJS",
    payload: e
  });
  const t = document.createElement("script");
  t.textContent = e, document.head.append(t), t.remove()
}
```

```javascript
// background.bundle.js:1249-1264
if ("loadCustomJS" === e && (null === (i = chrome.scripting) || void 0 === i || i.executeScript({
  target: {
    tabId: o.tab.id,
    allFrames: !1
  },
  func: e => {
    const t = "undefined" != typeof trustedTypes && trustedTypes.createPolicy(Date.now().toString(), {
      createScript: e => e
    }),
    a = document.createElement("script");
    a.textContent = t ? t.createScript(e) : e, document.head.append(a), a.remove()
  },
  args: [t],
  world: "MAIN",
  injectImmediately: !0
}))
```

**Risk Assessment**:
- User-provided JavaScript runs in the `MAIN` world with full page access
- Code has access to all YouTube data, cookies, and DOM
- Uses Trusted Types API when available (security best practice)
- No server communication for custom code (stored locally only)
- Social engineering risk: users could be tricked into pasting malicious code

**Mitigation**:
This is an intentional power-user feature. The extension does properly use Trusted Types when available and stores code locally without server transmission.

### 2. Extensive DOM Manipulation Permissions
**Severity**: LOW
**Files**: `youtube.bundle.js`, `youtube-music.bundle.js`
**Verdict**: LEGITIMATE FUNCTIONALITY

**Description**:
The extension heavily manipulates YouTube's DOM to customize the player interface, add features, and modify UI elements. This is the core functionality of the extension.

**Permissions Used**:
- Content scripts run on all YouTube domains
- `run_at: "document_start"` and `run_at: "document_end"`
- Access to video player elements
- CSS injection for UI customization

**Risk Assessment**:
- Appropriate for the extension's purpose
- No evidence of data exfiltration
- No tracking or analytics code detected

### 3. Storage API Usage
**Severity**: LOW
**Files**: `background.bundle.js`, `custom-css-and-js.bundle.js`
**Verdict**: LEGITIMATE FUNCTIONALITY

**Description**:
The extension uses `chrome.storage.local` to persist user settings and custom code.

**Code Evidence**:
```javascript
// background.bundle.js:1114-1133
chrome.storage[n.type].get(e, (e => {
  if (chrome.runtime.lastError) return o(chrome.runtime.lastError);
  // ... storage validation and migration logic
}))
```

**Risk Assessment**:
- Standard chrome.storage API usage
- No sensitive data storage
- Settings migration logic present (good practice)
- No sync storage usage (prevents unintended data sharing)

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| React component code | `background.bundle.js:6-36` | React library boilerplate |
| Script injection | `custom-css-and-js.bundle.js:1028-1035` | Intentional feature for custom JS |
| executeScript usage | `background.bundle.js:1249` | Required for MV3 custom JS injection |
| Trusted Types bypass | `background.bundle.js:1256` | Fallback for browsers without Trusted Types |

## API Endpoints

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `chrome.storage.local` | Store user settings and custom code | LOW |
| `chrome.runtime.sendMessage` | Internal extension messaging | LOW |
| `chrome.tabs.create` | Open tabs (embed mode feature) | LOW |
| `chrome.contextMenus` | Search YouTube context menu | LOW |
| `chrome.commands` | Keyboard shortcuts | LOW |
| `chrome.scripting.executeScript` | Custom JS injection (MV3) | MEDIUM |

**No external HTTP/HTTPS endpoints detected.**

## Data Flow Summary

1. **User Input → Storage**:
   - User enters custom CSS/JS in options page
   - Settings stored in `chrome.storage.local`
   - No server transmission

2. **Storage → Execution**:
   - Custom CSS injected as `<style>` element
   - Custom JS executed via `chrome.scripting.executeScript` (MV3) or direct script injection (MV2)
   - Code runs in MAIN world with full page access

3. **Extension Features**:
   - Content scripts modify YouTube DOM for UI customization
   - Background service worker handles keyboard shortcuts and tab management
   - No data collection or external communication

## Permissions Analysis

### Declared Permissions
- `contextMenus` - Used for "Search YouTube for..." context menu ✓
- `scripting` - Used for custom JS injection feature ✓
- `storage` - Used to persist user settings ✓

### Host Permissions
- `*://www.youtube.com/*` ✓
- `*://music.youtube.com/*` ✓
- `*://www.youtube-nocookie.com/*` ✓
- `*://youtube.googleapis.com/*` ✓

**Assessment**: All permissions are justified and actively used.

## Security Recommendations

1. **For Users**:
   - Only paste custom JavaScript from trusted sources
   - Understand that custom JS has full access to YouTube pages
   - Review any code before adding it to the extension

2. **For Developers** (if applicable):
   - Consider adding code validation or warnings for dangerous patterns (eval, fetch to external domains)
   - Add user prompts when enabling custom JS for the first time
   - Consider sandboxing custom JS execution if technically feasible

## Overall Risk Assessment

**MEDIUM**

### Risk Breakdown:
- **Malicious Code**: CLEAN (no evidence of malicious behavior)
- **Privacy**: CLEAN (no data collection or tracking)
- **Data Exfiltration**: CLEAN (no external network requests)
- **Custom Code Execution**: MEDIUM (intentional feature, user-controlled)
- **Permissions Abuse**: CLEAN (appropriate permission usage)

### Justification:
The extension is a legitimate YouTube customization tool with a substantial codebase (~88,000 lines). The MEDIUM risk rating is assigned solely due to the custom JavaScript injection feature, which is a documented and intentional capability that empowers users but also creates potential for abuse through social engineering. The extension itself contains no malicious code, tracking, or unauthorized data collection.

### Recommended Actions:
- ALLOW for general use
- INFORM users about the custom code injection feature's security implications
- MONITOR for reports of social engineering attempts targeting this feature
