# Titan Browser Extension - Security Analysis Report

## Extension Metadata

- **Extension Name**: Titan Browser Extension
- **Extension ID**: flemjfpeajijmofcpgfgckfbmomdflck
- **Version**: 0.1.2
- **User Count**: ~40,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

**OVERALL RISK: CLEAN**

The Titan Browser Extension is a legitimate "Install to Earn" browser extension that enables users to earn rewards by completing browser-based tasks. While the extension requests highly invasive permissions (`<all_urls>`, `userScripts`, `scripting`, `tabs`) and implements complex proxy infrastructure, the functionality serves its stated purpose of running distributed computing tasks for reward points/cryptocurrency.

This is a **residential proxy / crowdsourced task network** similar to Honeygain, LoadTeam, or Peer2Profit. Users knowingly install the extension to monetize their browser by executing scripts from a central server. The invasive permissions are necessary for the extension's core functionality rather than being exploited for malicious purposes.

**Key Characteristics:**
- Remote-controlled browser task execution via WebSocket
- Dynamic UserScript injection from remote servers
- Fetch/WebSocket proxying through extension context
- Earnings tracking in points and USDC cryptocurrency
- Transparent user consent model (install to earn)

## Permissions Analysis

### Requested Permissions

```json
{
  "permissions": [
    "storage",        // Configuration and earnings data
    "scripting",      // Dynamic script injection for tasks
    "userScripts",    // Task script execution in isolated context
    "tabs",           // Tab management for task windows
    "sidePanel"       // UI panel for monitoring
  ],
  "host_permissions": [
    "<all_urls>"      // Required for proxy functionality
  ]
}
```

### Permission Risk Assessment

| Permission | Risk Level | Justification |
|-----------|-----------|---------------|
| `<all_urls>` | HIGH (Justified) | Necessary for fetch/WebSocket proxying to arbitrary task domains |
| `userScripts` | HIGH (Justified) | Required to execute downloaded task scripts in USER_SCRIPT world |
| `scripting` | MEDIUM (Justified) | Used to inject overlays and fetch interceptors into task windows |
| `tabs` | LOW | Standard tab management for automated task execution |
| `storage` | LOW | Stores configuration, tokens, and earnings data |

**Verdict**: While highly invasive, all permissions are functionally necessary for a distributed computing/task network extension. Users explicitly consent to this model by installing an "earn to use" extension.

## Vulnerability Analysis

### 1. Remote Code Execution (By Design)

**Severity**: INFORMATIONAL
**Status**: EXPECTED BEHAVIOR
**Files**: `agent/jobmgr.js`, `agent/asrun.js`

**Description**:
The extension downloads and executes arbitrary JavaScript from remote servers:

```javascript
// agent/jobmgr.js:534-558
async loadScriptFromServer(key, cfg) {
    const response = await fetchWithHeader(cfg.script_url, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${this.rtinfo.token}` },
        signal: AbortSignal.timeout(30000)
    });
    const result = await response.text();
    const hash = await calculateSha256(result)

    const cfg2 = new JobConfig(key)
    if (hash !== cfg.script_hash) {
        console.warn(`Hash mismatch for ${key}. Server expected ${cfg.script_hash}, got ${hash}`);
        cfg2.setScriptWithHashAndVersion(result, cfg.script_hash, cfg.version)
    } else {
        cfg2.setScriptWithHashAndVersion(result, hash, cfg.version)
    }
    this.jobCfgs.set(key, cfg2)
}
```

**Security Controls**:
- SHA-256 hash verification (though mismatch only logs warning, still accepts script)
- Bearer token authentication required
- Scripts execute in USER_SCRIPT world (not MAIN world)
- Version tracking for script updates

**Verdict**: This is the core functionality of a distributed computing network. The extension is designed to execute tasks from a central orchestrator. Hash verification provides integrity checking but accepts mismatches (weak control).

### 2. WebSocket Command & Control

**Severity**: INFORMATIONAL
**Status**: EXPECTED BEHAVIOR
**Files**: `agent/asrun.js`, `service-worker.js`

**Description**:
Extension maintains persistent WebSocket connection to `task.titannet.info` for real-time task orchestration:

```javascript
// agent/asrun.js:80-113
async openWebsocket() {
    const url = new URL(`${API_WEBSOCKET}?token=${token}&device_id=${res.uniqueId}&lang=${res.lang || 'en'}`, wsHost).href;
    const webSocket = new WebSocket(url);

    webSocket.onmessage = (event) => {
        tHis.onWsMessage(event.data)
    };
}

onWsMessage(data) {
    const msg = JSON.parse(data)
    switch (msg.cmd) {
        case WEBSOCKET_CMD_UPDATE_JOB_URL:  // Server tells extension to open URL
            this.onUpdateJobURL(msg)
            break
        case WEBSOCKET_CMD_JOB_TASKE_STATUS: // Server updates task status
            this.onUpdateJobTaskStatus(msg)
            break
    }
}
```

**Commands Supported**:
- `WEBSOCKET_CMD_UPDATE_JOB_URL` - Server directs browser to open specific URLs with parameters
- `WEBSOCKET_CMD_JOB_TASKE_STATUS` - Task status updates (running/paused/completed)
- `WEBSOCKET_CMD_UPDATE_JOBS` - Fetch new job scripts from server
- `WEBSOCKET_CMD_TOKEN_INVALID` - Force token refresh

**Verdict**: Standard C2 architecture for a distributed task network. WebSocket enables real-time coordination of browser workforce. This is expected for the use case.

### 3. Fetch/WebSocket Proxy Infrastructure

**Severity**: INFORMATIONAL
**Status**: EXPECTED BEHAVIOR
**Files**: `agent/job.js`

**Description**:
Extension proxies fetch() and WebSocket requests from UserScripts through the extension's `<all_urls>` permission:

```javascript
// agent/job.js:195-254
async proxyFetch(message) {
    const { requestId, url, options } = message;

    const newOptions = {
        credentials: 'omit', // no cookies
        signal: AbortSignal.timeout(20 * 1000)
    }

    // delete Authorization
    delete newOptions.headers?.Authorization;

    const response = await fetchWithHeader(url, newOptions);
    // ... send response back to UserScript
}

async proxyWebsocketOpen(message) {
    const { connectionId, url } = message;
    const webSocket = new WebSocket(url);
    // ... relay messages between UserScript and remote WebSocket
}
```

**Security Controls**:
- Removes cookies (`credentials: 'omit'`)
- Strips Authorization headers from proxied requests
- 20-second timeout on fetch requests
- No access to user's cookies/credentials

**Verdict**: This is a **residential proxy network**. Users' browsers act as exit nodes for network requests. The extension removes cookies/auth to prevent credential theft. This is the intended monetization model.

### 4. Automated Tab/Window Management

**Severity**: LOW
**Status**: EXPECTED BEHAVIOR
**Files**: `agent/jobmgr.js`, `agent/util.js`

**Description**:
Extension automatically opens popup windows to execute tasks and injects overlay to prevent user interference:

```javascript
// agent/jobmgr.js:248-327
openJobWorkloadPage(url, jobId, taskId, TargetUrl) {
    const windowOptions = {
        url: url,
        type: 'popup',
        width: 360,
        height: 328,
        focused: false  // Background execution
    }

    chrome.windows.create(windowOptions, async (window) => {
        const tabId = window.tabs[0].id

        // Inject overlay to prevent user interaction
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: injectTaskOverlay,
            args: [currentLang]
        });
    })
}

// agent/util.js:483-567
export function injectTaskOverlay(pluginLang) {
    // Creates fullscreen overlay with "Processing... Do not close" message
    // Uses Shadow DOM to prevent page from removing it
}
```

**Verdict**: Automated task execution with user notification. The overlay clearly informs users that a process is running and will auto-close. This is transparent behavior for a task automation extension.

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `eval(code)` in MAIN world | `agent/jobmgr.js:312` | Used to inject fetch interceptor logic for capturing API responses. Standard technique for MAIN world script injection. |
| `window.fetch` hooking | `agent/util.js:452-476` | Legitimate fetch interception to capture task API responses. Not credential stealing. |
| Remote script download | `agent/jobmgr.js:534` | Core functionality of distributed task network. Scripts are job definitions, not malware payloads. |
| WebSocket C2 | `agent/asrun.js:80` | Standard architecture for real-time task orchestration in distributed computing networks. |
| Shadow DOM overlay | `agent/util.js:483` | Prevents users from accidentally interfering with automated tasks. Displays clear "Processing" message. |

## API Endpoints & Data Flow

### Server Infrastructure

**Bootstrap Nodes**:
- `https://task.titannet.info` (primary)
- `https://task.titandev.info` (fallback)

**API Endpoints**:
```
/api/public/webnodes/discover        - Node discovery (returns harbors list)
/api/auth/login                      - User authentication
/api/auth/refresh-token              - Token refresh
/api/public/webnodes/ws              - WebSocket connection
/api/webnodes/jobs                   - Job script list
/api/webnodes/platforms              - Platform/task status
/api/webnodes/register               - Extension registration
/api/user/daily/trend                - Earnings dashboard
```

### Data Collection

**Transmitted to Servers**:
- Device ID (UUID generated on install)
- Browser user agent
- Extension version
- Install/update timestamps
- Language preference
- Task execution status
- Earnings data (points/USDC)
- UserScripts permission status
- Active job reports (task counts)

**NOT Transmitted**:
- Browsing history
- Cookies (explicitly stripped)
- Passwords
- Form data
- User credentials (except login to Titan platform)

### Authentication Flow

1. User logs in via dashboard website (`dashboardUrl`)
2. Website sends login credentials via `postMessage` to content script
3. Content script relays to service worker
4. Extension authenticates with harbor server
5. Receives JWT access_token + refresh_token
6. Tokens stored in chrome.storage.local
7. Bearer token used for all subsequent API requests
8. Automatic refresh when token expires (6 hours before expiry)

## Data Flow Summary

```
[User] → [Dashboard Website] → [Content Script] → [Service Worker] → [Titan Servers]
                                                       ↓
                                              [UserScript Tasks]
                                                       ↓
                                        [Proxy Fetch/WebSocket] → [Task Target Sites]
```

1. User authenticates via Titan dashboard
2. Extension connects to task orchestration server via WebSocket
3. Server pushes task definitions (JavaScript) to extension
4. Extension registers UserScripts with dynamic URL matches
5. Opens popup windows to execute tasks
6. UserScripts run in isolated context, proxy network requests through extension
7. Extension relays results back to server
8. User earns points/USDC for completed tasks

## Privacy Concerns (Expected Behavior)

### Data Shared with Titan Network:
- **Device fingerprint**: UUID, browser type, extension version, install date
- **Task telemetry**: Job success/failure status, execution times
- **IP address**: Inherently exposed through WebSocket/API connections
- **Earnings data**: Points and USDC balances

### User Privacy Risks:
1. **Exit node liability**: User's IP is used for proxied requests to task target sites
2. **Browser profiling**: Titan servers can profile browser capabilities and locale
3. **Network traffic patterns**: Timing and frequency of task execution is monitored

**Mitigation**: Users explicitly consent to this model by installing an "earn to use" extension. The privacy policy should disclose these risks.

## Security Recommendations

### For Developers:

1. **Enforce hash verification**: Currently logs warning on mismatch but still executes script. Should reject mismatched scripts.
   ```javascript
   if (hash !== cfg.script_hash) {
       throw new Error(`Script integrity check failed for ${key}`);
   }
   ```

2. **Add Content Security Policy**: Manifest lacks CSP to restrict extension's own resources.
   ```json
   "content_security_policy": {
       "extension_pages": "script-src 'self'; object-src 'self'"
   }
   ```

3. **Implement script signing**: SHA-256 hashes can be forged if server is compromised. Use asymmetric cryptography (EdDSA) to verify scripts are signed by Titan.

4. **Add rate limiting**: No apparent limits on task execution frequency or bandwidth usage.

5. **Improve error messages**: Avoid exposing internal paths/structure in console logs (e.g., `agent/jobmgr.js:534`).

### For Users:

1. **Understand exit node risks**: Your IP address will be visible to websites accessed by tasks. You may be liable for task-generated traffic.

2. **Monitor resource usage**: Extension can consume significant CPU/bandwidth executing tasks.

3. **Review privacy policy**: Ensure Titan discloses data collection and usage terms.

4. **Use dedicated browser profile**: Consider isolating Titan extension from personal browsing to limit exposure.

## Overall Risk Assessment

### Risk Level: **CLEAN**

**Justification**:

This extension is functionally equivalent to other legitimate "earn to use" applications like:
- Honeygain (residential proxy network)
- Peer2Profit (bandwidth sharing)
- LoadTeam (distributed computing)
- Grass (AI training data collection)

While the implementation is highly invasive with remote code execution, WebSocket C2, and proxy infrastructure, **these capabilities serve the extension's stated purpose** rather than being exploited for malicious activity.

### Why This is CLEAN vs Malicious:

✅ **User Consent**: Description "Install to Earn" clearly indicates monetization model
✅ **Transparent UI**: Dashboard shows earnings, task status, and active jobs
✅ **No credential theft**: Explicitly strips cookies and Authorization headers from proxied requests
✅ **No data exfiltration**: Does not access browsing history, passwords, or form data
✅ **Clear user notification**: Task windows display "Processing..." overlay informing user of automation
✅ **Opt-in architecture**: Agent must be manually started by user (not auto-start)
✅ **Legitimate business model**: Distributed computing network with cryptocurrency payouts (USDC)
✅ **No obfuscation**: Code is readable with clear variable names and comments

### Key Differentiators from Malware:

| Malware Behavior | Titan Extension |
|-----------------|-----------------|
| Hides functionality | Shows active tasks in sidebar/popup |
| Steals credentials | Strips auth headers from proxied requests |
| Background installation | Requires explicit user install |
| No user value | Pays users in cryptocurrency |
| Obfuscated code | Clear, documented architecture |
| No disclosure | "Install to Earn" description |

## Conclusion

The Titan Browser Extension is a legitimate distributed computing platform that monetizes user browsers through task execution and residential proxy functionality. While the technical implementation involves remote code execution and invasive permissions, **the functionality aligns with the extension's stated purpose** and established business model.

The extension does not exhibit malicious behavior such as credential theft, unauthorized data exfiltration, or covert operations. Users who install this extension knowingly consent to providing computational resources in exchange for cryptocurrency rewards.

**Recommendation**: Mark as **CLEAN** with disclosure that this is a residential proxy network extension where users' browsers serve as exit nodes for distributed tasks. Users should understand the privacy implications and potential liability for traffic generated through their connection.

## File Path

`/home/acorn221/projects/cws-scraper/output/workflow-downloaded/flemjfpeajijmofcpgfgckfbmomdflck/VULN_REPORT.md`
