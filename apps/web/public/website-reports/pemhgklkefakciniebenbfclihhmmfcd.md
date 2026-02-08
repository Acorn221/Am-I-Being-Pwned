# Vulnerability Analysis Report: Visualping

## Metadata
- **Extension Name**: Visualping
- **Extension ID**: pemhgklkefakciniebenbfclihhmmfcd
- **Version**: 4.8.1
- **User Count**: ~100,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Visualping is a legitimate website monitoring extension that allows users to track changes on web pages. The extension uses a local SQLite database (via WebAssembly) to store monitoring jobs and captures. The security analysis reveals **LOW overall risk** with no critical vulnerabilities or malicious behavior detected.

The extension's primary functionality involves:
- Page change monitoring with CSS selector picking
- Local screenshot capture and comparison
- Cookie forwarding for authenticated page monitoring
- Telemetry reporting to Visualping's backend
- Client-side SQLite database for local storage

## Vulnerability Details

### 1. Cookie Access - LOW SEVERITY
**Files**: `popup.bundle.js`
**Lines**: 27405-27420
**Code**:
```javascript
async function pl(e) {
  const t = cl(e);
  return function(e) {
    return e.filter((e => "/" === e.path))
  }(await async function(e) {
    return (await chrome.cookies.getAll({
      domain: e
    })).filter((e => e.name && "string" == typeof e.value && e.domain))
  }(t)).map((e => ({
    cookie: {
      field: e.name,
      value: e.value,
      domain: e.domain
    }
  })))
}
```

**Verdict**: **BENIGN** - Cookie access is legitimate and scoped to the monitored URL's domain. This is necessary functionality to monitor authenticated pages (e.g., checking if a user's account page changed). Cookies are only retrieved for the specific domain being monitored, not exfiltrated globally.

### 2. Telemetry/Analytics - LOW SEVERITY
**Files**: `service_worker.bundle.js`
**Lines**: 68-95
**Code**:
```javascript
function r(e, t) {
  try {
    const r = function() {
      const e = chrome.runtime.id,
        t = chrome.runtime.getManifest();
      return {
        chromeVersion: /Chrome\/([0-9.]+)/.exec(navigator.userAgent)[1],
        platformOS: n.os,
        platformArch: n.arch,
        manifest: t,
        extensionId: e,
        digest: `${t.name}@${e}@${t.version}`
      }
    }();
    if (i.includes(r.extensionId)) return;
    const s = {
      extId: r.extensionId,
      extVersion: r.manifest.version,
      platform: `${r.platformOS}-${r.platformArch}`,
      chromeVersion: r.chromeVersion,
      eventType: e,
      eventParams: t
    };
    fetch(`https://account.api.visualping.io/fyi?src=${encodeURIComponent(r.digest)}&data=${encodeURIComponent(JSON.stringify(s))}`)
  } catch (e) {
    console.error(e)
  }
}
```

**Verdict**: **BENIGN** - Standard analytics reporting to vendor's API. Collects platform metadata (OS, Chrome version, extension version) and event types. No sensitive user data (URLs, page content, cookies) is transmitted. This is typical for legitimate extension telemetry.

### 3. Local SQLite Database - LOW SEVERITY
**Files**: `787.bundle.js`, `diff.bundle.js`, `popup.bundle.js`, `offscreen.bundle.js`
**WASM**: `14d9d4b0cf6409daa3ff.wasm` (SQLite3 via Emscripten)

**Database Operations**:
```javascript
await this.database.executeSql("INSERT INTO jobs(job_id, url, name, mode, regex, selector, check_interval, html, crc_checksum, last_check, last_changed, crop_scroll_top, crop_orig_width, crop_orig_height, crop_width, crop_height, crop_x, crop_y, trigger, active) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", t)

await this.database.executeSql("INSERT INTO captures(job_id, image_mime, img_data, html, created_at) VALUES(?,?,?,?,?)", a)

await this.database.executeSql("SELECT * FROM jobs ORDER BY job_id DESC;", [])
```

**Verdict**: **BENIGN** - All database operations are local-only using SQLite WASM. Stores monitoring jobs, screenshots, and HTML snapshots in browser's local storage/IndexedDB. No network exfiltration of database contents detected. Schema is appropriate for page monitoring functionality.

### 4. Dynamic Code Evaluation - FALSE POSITIVE
**Files**: Multiple bundle files (jQuery library code)
**Lines**: Various (e.g., `picker.bundle.js:131`, `popup.bundle.js:2455`)

**Code Pattern**:
```javascript
globalEval: function(e) {
  var t, n = eval;
  (e = m.trim(e)) && (1 === e.indexOf("use strict") ?
    ((t = s.createElement("script")).text = e, s.head.appendChild(t).parentNode.removeChild(t)) :
    n(e))
}
```

**Verdict**: **FALSE POSITIVE** - This is part of jQuery v2.2.4 library's `globalEval` function, used for executing inline scripts during DOM manipulation. Not used for malicious dynamic code execution.

### 5. Content Script Injection - LOW SEVERITY
**Files**: `service_worker.bundle.js`
**Lines**: 18-36
**Code**:
```javascript
return chrome.scripting.executeScript({
  files: ["picker.bundle.js", "js/jquery-original.js"],
  target: {
    tabId: i.tabID
  }
}).then((() => {
  chrome.scripting.executeScript({
    args: [n],
    func: e,
    target: {
      tabId: i.tabID
    }
  }, (() => console.log("after initialize"))),
  chrome.scripting.insertCSS({
    files: ["styles/picker.css"],
    target: {
      tabId: i.tabID
    }
  })
}))
```

**Verdict**: **BENIGN** - Injects element picker UI when user explicitly requests it. Does not inject on all pages automatically. Used for CSS selector picking functionality. No malicious DOM manipulation detected.

### 6. Broad Permissions - MEDIUM SEVERITY
**Manifest Permissions**:
- `unlimitedStorage` - Needed for storing monitoring data/screenshots
- `activeTab` - Limited to user-activated tabs
- `tabs` - Used for monitoring tab states
- `notifications` - For change alerts
- `scripting` - For element picker injection
- `offscreen` - For background processing
- `cookies` - For authenticated page monitoring
- `alarms` - For periodic checks
- `<all_urls>` (host_permissions) - Monitors any URL user specifies

**Verdict**: **ACCEPTABLE** - Permissions are justified by core functionality. The `<all_urls>` permission is necessary since users can monitor any website. Extension only acts on user-specified URLs, not all browsing activity.

## False Positives Table

| Pattern | File | Reason |
|---------|------|--------|
| `eval` usage | jQuery library files | Standard jQuery 2.2.4 `globalEval` function |
| `new Function` | React/bundler polyfills | Webpack runtime helpers for module loading |
| `innerHTML` usage | jQuery DOM manipulation | Standard library DOM insertion methods |
| localStorage/sessionStorage | SQLite WASM VFS | Virtual file system for SQLite persistence layer |

## API Endpoints

| Endpoint | Purpose | Data Transmitted |
|----------|---------|------------------|
| `https://account.api.visualping.io/fyi` | Telemetry/Analytics | Extension version, platform info, event types (no sensitive data) |

## Data Flow Summary

1. **User Input**: User selects elements to monitor via picker UI
2. **Local Storage**: Monitoring jobs stored in SQLite WASM database (IndexedDB/localStorage)
3. **Screenshot Capture**: Page captures stored locally as base64 image data
4. **Change Detection**: Client-side diff comparison using diff.bundle.js
5. **Cookie Forwarding**: Retrieves cookies for monitored domain only (for auth)
6. **Telemetry**: Sends usage metrics (no page content/URLs) to Visualping API
7. **Notifications**: Chrome notifications API for change alerts

**Data Exfiltration**: None detected. All monitoring data remains local except anonymous usage metrics.

## Overall Risk Assessment

### Risk Level: **LOW**

### Justification:
- **No malicious behavior detected**: Extension performs legitimate page monitoring
- **Privacy-respecting**: Monitored content stays local; only anonymous telemetry sent
- **Appropriate permissions**: All permissions justified by core functionality
- **Known libraries**: Uses standard jQuery, React, SQLite WASM (Emscripten)
- **No obfuscation**: Code is minified but not maliciously obfuscated
- **No remote code execution**: No dynamic script loading from external sources
- **Scoped cookie access**: Only retrieves cookies for monitored domains
- **Local-first architecture**: All processing happens client-side

### Recommendations:
1. Users should be aware that the extension can access cookies for monitored websites
2. Extension vendor should document data collection practices (telemetry)
3. Consider adding CSP directives to further restrict script execution

### Comparison to Malicious Extensions:
Unlike malicious extensions, Visualping does **NOT**:
- Inject tracking scripts on all pages
- Exfiltrate browsing history or page content
- Replace/inject ads or affiliate links
- Access cookies outside monitored domains
- Use residential proxy infrastructure
- Implement extension enumeration/killing
- Hook fetch/XHR for surveillance
- Load remote configuration/kill switches

## Conclusion

Visualping is a **legitimate, safe extension** for page change monitoring with appropriate security controls. The LOW risk rating reflects standard extension practices with no evidence of malicious intent or privacy violations beyond disclosed functionality.
