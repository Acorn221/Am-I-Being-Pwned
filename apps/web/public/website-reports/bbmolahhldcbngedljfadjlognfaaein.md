# Vulnerability Assessment Report

## Extension Metadata

- **Name**: CheerpJ Applet Runner
- **ID**: bbmolahhldcbngedljfadjlognfaaein
- **Version**: 2025.11
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Publisher**: Leaning Technologies

## Executive Summary

CheerpJ Applet Runner is a legitimate Chrome extension developed by Leaning Technologies to enable Java applet execution in modern browsers without Java installed. The extension uses WebAssembly technology (CheerpJ) to emulate Java runtime environments.

**Overall Risk Level: LOW**

The extension exhibits legitimate functionality with minimal security concerns. The main findings involve user-agent spoofing and navigator API manipulation (required for applet compatibility), license validation infrastructure, and WebAssembly execution. No malicious behavior, data exfiltration, or suspicious remote connections were detected.

## Vulnerability Analysis

### 1. User-Agent Spoofing and Browser Fingerprint Manipulation

**Severity**: LOW (Legitimate use case)
**File**: `spoof.js` (lines 1-56)
**Verdict**: FALSE POSITIVE - Required for applet compatibility

**Details**:
The extension modifies navigator properties to spoof Java plugin availability:

```javascript
Object.defineProperties(Navigator.prototype, {
    userAgent:{ value: newUA, configurable: false, enumerable: true, writable: false},
    javaEnabled: { value: function() { return true; }, configurable: false, enumerable: true, writable: false},
    mimeTypes: { value: mimes, configurable: false, enumerable: true, writable: false}
});
Object.defineProperty(window, "chrome", {value: null});
```

- Replaces Chrome/Chromium version in UA string to "Chromium/44"
- Adds fake Java applet MIME types: `application/x-java-applet`
- Makes `navigator.javaEnabled()` return `true`
- Hides `window.chrome` object
- Runs in MAIN world context (lines 32-35 in `bg.js`)

**Justification**: This is necessary to convince legacy Java applet code that Java is available. Without this, applets won't attempt to initialize. This is the core functionality of the extension.

### 2. Dynamic User-Agent Header Modification

**Severity**: LOW (Legitimate use case)
**File**: `bg.js` (lines 75-128)
**Verdict**: FALSE POSITIVE - Enterprise policy support

**Details**:
Uses `declarativeNetRequest` to modify request headers:

```javascript
{
    id: 1,
    priority: 1,
    action: {
        type: "modifyHeaders",
        requestHeaders: [{
            header: "user-agent",
            operation: "set",
            value: e
        }]
    },
    condition: {
        resourceTypes: ["main_frame", "sub_frame"]
    }
}
```

- Modifies User-Agent and sec-ch-ua-platform headers
- Configured via managed storage (Group Policy Object)
- Only activates when `userAgent` GPO is set

**Justification**: Enterprise-grade feature for compatibility with Java servers that verify client platforms. Transparent to users and controlled by IT admins via GPO.

### 3. License Validation Remote Endpoint

**Severity**: LOW (Legitimate licensing)
**File**: `extension_license_bg.js` (line 83)
**Verdict**: CLEAN - Standard license validation

**Details**:
```javascript
const t = await fetch(`https://jnlp-runner.leaning-technologies.workers.dev/verify?licenseKey=${e}&installId=${n}&extension=` + a);
```

- Single remote endpoint: `https://jnlp-runner.leaning-technologies.workers.dev/verify`
- Validates license keys for commercial use
- Uses JWT tokens with RSA-256 signature verification
- Local crypto validation (lines 20-30)
- No telemetry or analytics data sent

**Justification**: Standard commercial licensing system. The extension is free for personal use but requires licenses for commercial use. No privacy concerns - only sends license key and random installation ID.

### 4. Cross-Frame Script Injection

**Severity**: LOW (Required for applet support)
**File**: `loader.js` (lines 178-199)
**Verdict**: FALSE POSITIVE - Applet initialization

**Details**:
```javascript
function cj3InjectInFrame(f, scriptText)
{
    f.addEventListener("load", function() { cj3InjectInFrame(f, scriptText); });
    if(f.contentDocument == null)
    {
        // Third party frame
        return;
    }
    if(f.contentDocument.readyState != "loading")
    {
        var s = f.contentDocument.createElement("script");
        s.textContent = scriptText;
        f.contentDocument.head.appendChild(s);
    }
}
```

- Injects CheerpJ loader into same-origin frames/iframes
- Bails out on cross-origin frames (line 182-185)
- Required to support applets embedded in framesets

**Justification**: Legacy Java applets often use HTML frames. The extension respects same-origin policy and only injects code into accessible frames.

### 5. WebAssembly Execution

**Severity**: LOW (Core functionality)
**Files**: `cheerpj/cj3.wasm`, `cheerpj/cj3n8.wasm`, `cheerpj/main.wasm`
**Verdict**: CLEAN - Legitimate Java VM emulation

**Details**:
- Executes WebAssembly modules for Java runtime emulation
- WASM files total ~3MB (typical for JVM implementations)
- Loaded from local extension resources only
- No dynamic WASM compilation from remote sources

**Justification**: CheerpJ is a known Java-to-JavaScript/WebAssembly compiler product. These WASM modules implement the Java Virtual Machine in the browser.

## False Positives Summary

| Pattern | Location | Reason |
|---------|----------|--------|
| `navigator.userAgent` override | `spoof.js:37` | Required for Java applet detection |
| `javaEnabled()` override | `spoof.js:38` | Required for Java applet detection |
| `mimeTypes` override | `spoof.js:39` | Required for Java MIME type registration |
| `window.chrome = null` | `spoof.js:40` | Hides extension from applet code |
| `declarativeNetRequest` UA modification | `bg.js:75-128` | Enterprise GPO-controlled compatibility |
| Frame script injection | `loader.js:178-199` | Same-origin applet support |
| `atob()` usage | `extension_license_bg.js:26,29,30` | JWT token decoding (standard) |
| Dynamic script creation | `inject.js:34-47` | CheerpJ loader initialization |

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://jnlp-runner.leaning-technologies.workers.dev/verify` | License validation | License key, random install ID, extension type | LOW |
| `https://labs.leaningtech.com/feedback-appletrunner` | Uninstall feedback | None (just URL redirect) | NONE |
| `https://labs.leaningtech.com/payment-*` | License purchase | None (external link) | NONE |

## Data Flow Summary

### Data Collection
- **None** - No analytics, telemetry, or user behavior tracking
- **License Data**: For paid users, stores license JWT in `chrome.storage.local`
- **Settings**: Clipboard mode and debug options stored locally
- **Install ID**: Random 16-char hex string for license validation

### Data Transmission
- **Outbound**: Only license key validation requests (optional, only for commercial users)
- **No Third-Party Services**: No Google Analytics, Sentry, or other SDKs

### Permissions Usage
- `scripting`: Injects content scripts for applet detection
- `activeTab`: Enables/disables extension per domain
- `storage`: Stores user settings and license data locally
- `declarativeNetRequestWithHostAccess`: UA header modification (GPO-controlled)
- `alarms`: Daily license expiration check
- `optional_host_permissions`: User must grant per domain

## Positive Security Indicators

1. **Minimal Permissions**: Only requests necessary permissions, hosts are optional
2. **Open Source Components**: CheerpJ is a known commercial product by Leaning Technologies
3. **No Obfuscation**: Code is readable and well-structured
4. **No Analytics**: Zero telemetry or tracking infrastructure
5. **Transparent Licensing**: Clear commercial vs personal use model
6. **Proper CSP**: `script-src 'self'; object-src 'self'`
7. **Version Info**: Regular updates (2025.11 version is recent)
8. **Professional Development**: High code quality, proper error handling

## Extension Behavior Assessment

**Installation**:
- Opens welcome page explaining functionality
- Extension disabled by default (gray icon)
- User must explicitly enable per domain

**Runtime**:
- Monitors DOM for `<applet>`, `<object>`, `<embed>` tags
- Injects CheerpJ loader only on enabled domains
- Downloads Java class files on-demand to emulate applet execution

**Transparency**:
- Clear UI showing enabled/disabled state
- Links to documentation and GitHub issues
- Shows license status in popup

## Risk Assessment by Category

| Category | Risk Level | Notes |
|----------|-----------|-------|
| Data Exfiltration | CLEAN | No user data collection or transmission |
| Malicious Scripts | CLEAN | No obfuscation, no suspicious code patterns |
| Remote Code Execution | CLEAN | Only loads local WASM/JS resources |
| Privacy Violation | CLEAN | No tracking, fingerprinting, or analytics |
| Extension Killing | CLEAN | No extension enumeration detected |
| Ad Injection | CLEAN | No ad SDKs or DOM manipulation for ads |
| Cookie Harvesting | CLEAN | No cookie access or transmission |
| Keylogging | CLEAN | No keyboard event capture |
| XHR/Fetch Hooking | CLEAN | No global hook patterns |
| Market Intelligence | CLEAN | No Sensor Tower, Pathmatics, etc. |

## Recommendations

1. **For Users**: Safe to use for running legacy Java applets. Enable only on trusted domains.
2. **For Enterprise**: GPO-controlled UA spoofing is legitimate but should be documented in security policies.
3. **For Researchers**: Excellent example of legitimate WASM usage and browser extension development.

## Overall Risk Level: LOW

**Justification**:
- CheerpJ Applet Runner is a legitimate productivity tool from a reputable company
- All suspicious patterns have legitimate technical justifications
- No evidence of malicious behavior, data harvesting, or privacy violations
- Code quality and security practices are above average
- Appropriate for whitelist/trust

**Commercial Use Note**: Extension is free for personal use but requires a paid license for commercial/enterprise use. This is clearly communicated and enforced through the license validation system.
