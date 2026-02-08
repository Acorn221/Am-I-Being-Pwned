# ScriptCat - Security Analysis Report

## Metadata
- **Extension Name**: ScriptCat
- **Extension ID**: ndcooeababalnlpkfedmmbbbgkljhpjf
- **Version**: 1.2.6
- **User Count**: ~70,000
- **Analysis Date**: 2025-02-07
- **Manifest Version**: 3

## Executive Summary

ScriptCat is a userscript manager extension similar to Tampermonkey/Greasemonkey that allows users to install and run custom JavaScript code on web pages. While the extension appears to be a legitimate userscript manager with proper functionality, it presents **HIGH RISK** due to its extreme permissions, arbitrary code execution capabilities, and potential for abuse if user-installed scripts are malicious.

The extension itself is not malware, but its core functionality - executing arbitrary third-party JavaScript with full page access - creates significant security exposure. The extension implements Greasemonkey API compatibility (GM_xmlhttpRequest, GM_setValue, etc.) and can inject user-provided scripts into any website.

## Vulnerability Details

### FINDING 1: Arbitrary Code Execution via User Scripts
**Severity**: HIGH
**Affected Files**:
- `src/service_worker.js` (installScript, installByUrl functions)
- `src/inject.js` (script injection engine)
- `src/content.js` (content script coordinator)
- `src/sandbox.html` (sandboxed script execution)

**Description**:
ScriptCat allows users to install arbitrary JavaScript from remote URLs (including file:// protocol) and executes this code in web page contexts. The extension intercepts .user.js file requests and automatically prompts for installation.

**Evidence**:
```javascript
// Automatic script installation from file:// and HTTP URLs
listenerScriptInstall(){
  chrome.webRequest.onBeforeRequest.addListener(e=>{
    if("GET"!==e.method)return;
    let t=null;
    if(e.url.startsWith("file://")&&e.url.endsWith(".user.js"))
      t=e.url;
    // Redirects to installation page
    this.openInstallPageByUrl(t,"user")
  },{urls:["file:///*/*.user.js*"]})
}

// Script execution in inject context
execScriptEntry(e){
  let {scriptLoadInfo:t,scriptFunc:n,envInfo:r}=e,
      o=new eS(t,"content",this.msg,n,r);
  o.exec()
}
```

**Risk Assessment**:
This is expected behavior for a userscript manager, but creates a massive attack surface. If users install malicious scripts, those scripts have full page access and can:
- Steal credentials and session tokens
- Modify banking/financial transactions
- Inject malware or phishing content
- Exfiltrate sensitive data
- Perform unauthorized actions

**Verdict**: LEGITIMATE FUNCTIONALITY WITH HIGH INHERENT RISK

---

### FINDING 2: Excessive Permissions
**Severity**: HIGH
**Affected Files**: `manifest.json`

**Description**:
The extension requests maximum Chrome permissions including:
- `<all_urls>` host permissions (access to all websites)
- `webRequest` (intercept all network traffic)
- `cookies` (read/modify all cookies)
- `scripting` (inject code into any page)
- `userScripts` (Chrome's userscript API)
- `declarativeNetRequest` (modify request headers)
- `storage` (unlimited storage)
- `tabs` (access to all tab information)
- `webNavigation` (track browsing history)

**Evidence**:
```json
"permissions":["tabs","alarms","storage","cookies","offscreen","scripting",
"downloads","activeTab","webRequest","userScripts","contextMenus",
"webNavigation","notifications","clipboardWrite","unlimitedStorage",
"declarativeNetRequest"],
"host_permissions":["<all_urls>"]
```

**Risk Assessment**:
These permissions are technically necessary for a full-featured userscript manager but create extensive attack surface. The extension can:
- Monitor all browsing activity
- Access credentials on any website
- Modify network requests
- Inject arbitrary code

**Verdict**: LEGITIMATE BUT EXCESSIVE - Required for functionality but extremely dangerous if compromised

---

### FINDING 3: Network Request Header Modification
**Severity**: MEDIUM
**Affected Files**: `src/options.js`, service worker

**Description**:
The extension uses `chrome.declarativeNetRequest` to dynamically modify HTTP headers on user-initiated requests, implementing CORS bypass functionality for userscripts.

**Evidence**:
```javascript
async request(e,t){
  let n=(t=t||{}).headers||new Headers;
  return await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds:[100],
    addRules:[{
      id:100,
      action:{
        type:"modifyHeaders",
        // Modifies request headers dynamically
      }
    }]
  })
}
```

**Risk Assessment**:
This enables userscripts to bypass CORS restrictions, which could be abused to:
- Make cross-origin requests to sensitive APIs
- Bypass security controls
- Exfiltrate data to unauthorized domains

**Verdict**: LEGITIMATE USERSCRIPT FEATURE - Required for GM_xmlhttpRequest API but security-sensitive

---

### FINDING 4: Automatic Script Update with Remote Code Execution
**Severity**: MEDIUM
**Affected Files**: `src/service_worker.js` (checkScriptUpdate, _checkScriptUpdate)

**Description**:
ScriptCat automatically checks for and can silently update installed userscripts from remote URLs. The update mechanism fetches remote JavaScript and can auto-install under certain conditions.

**Evidence**:
```javascript
async _checkScriptUpdate(e){
  let r="system"===e.checkType&&
         await this.systemConfig.getSilenceUpdateScript();
  // Fetches remote script updates
  let a=await this.checkUpdatesAvailable(i.map(e=>e.uuid),s)
  // Silent auto-update for some scripts
  for(let e=0,t=l.length;e<t;e++){
    let t=l[e],r=t.script.downloadUrl||t.script.checkUpdateUrl;
    // Auto-installs updated code
    await this.installScript({script:s,code:n,upsertBy:"system"})
  }
}
```

**Risk Assessment**:
If a legitimate script's update URL is compromised or performs a malicious update, all users would automatically receive malicious code. This is standard userscript manager behavior but presents supply-chain attack risk.

**Verdict**: LEGITIMATE UPDATE MECHANISM - Standard for userscript managers but creates supply-chain risk

---

### FINDING 5: No Malicious Network Activity Detected
**Severity**: CLEAN
**Affected Files**: All analyzed

**Description**:
Comprehensive analysis of the extension's own code found NO evidence of:
- Unauthorized data exfiltration
- Tracking/analytics beacons
- Cryptocurrency mining
- Ad injection by the extension itself
- Hidden network connections
- Credential theft by extension code

**Evidence**:
- No hardcoded external API endpoints (only docs.scriptcat.org for documentation)
- No tracking/analytics libraries
- No cryptocurrency mining code
- No credential harvesting in extension code
- All network calls are user-initiated (script installation, updates)

**Verdict**: CLEAN - Extension code itself is not malicious

---

## False Positives

| Pattern | Context | Verdict |
|---------|---------|---------|
| `eval()` usage | Not found in extension code | N/A |
| `new Function()` | Not found in extension code | N/A |
| GM_xmlhttpRequest | Greasemonkey API implementation for userscripts | LEGITIMATE |
| postMessage usage | IPC between content/inject/sandbox contexts | LEGITIMATE |
| chrome.webRequest | Required for .user.js file interception | LEGITIMATE |
| declarativeNetRequest | CORS bypass for GM API compatibility | LEGITIMATE |
| chrome.cookies access | Required for GM_cookie API | LEGITIMATE |
| chrome.scripting | Required to inject userscripts | LEGITIMATE |
| Keyboard event listeners | UI functionality in options/editor | LEGITIMATE |
| localStorage/storage usage | Script/settings persistence | LEGITIMATE |

## API Endpoints

| Endpoint | Purpose | Risk Level |
|----------|---------|------------|
| docs.scriptcat.org | Documentation links | LOW |
| User-specified URLs | Script installation sources | HIGH (user-controlled) |
| User-specified URLs | Script update endpoints | HIGH (user-controlled) |

**Note**: The extension itself does not communicate with tracking services. All network activity is user-initiated for script installation/updates.

## Data Flow Summary

### Sensitive Data Accessed
1. **All website content** - Via `<all_urls>` permission and injected scripts
2. **All cookies** - Via `cookies` permission (for GM_cookie API)
3. **HTTP headers** - Via webRequest and declarativeNetRequest
4. **Form data** - Potentially accessible to injected userscripts
5. **Browsing history** - Via webNavigation permission

### Data Storage
- **chrome.storage.local**: User scripts, script settings, values (GM_setValue)
- **chrome.storage.session**: Temporary runtime state
- **IndexedDB**: Script resources, compiled code cache

### Data Transmission
- **Outbound**: User-installed scripts may send data anywhere (uncontrolled)
- **Extension itself**: No unauthorized data transmission detected

### Security Controls
- **Sandboxed execution**: Uses sandbox.html for isolated script compilation
- **Script isolation**: Each userscript runs in isolated context
- **No automatic execution**: Scripts require user installation
- **Update controls**: Users can disable auto-updates per script

## Overall Risk Assessment

**RISK LEVEL: HIGH**

### Risk Factors
1. **Extreme permissions** - Full access to all websites, cookies, requests
2. **Arbitrary code execution** - Executes user-provided JavaScript
3. **Supply chain risk** - Auto-updates from third-party sources
4. **User education required** - Users must understand script trustworthiness
5. **Massive attack surface** - Any installed malicious script compromises security

### Mitigating Factors
1. **Extension code is clean** - No malware in the extension itself
2. **Legitimate purpose** - Established category (userscript manager)
3. **User control** - Users choose which scripts to install
4. **Isolation mechanisms** - Scripts run in separate contexts
5. **Open source** - Code appears to match open-source project

### Threat Model
**Primary Risk**: Users installing malicious userscripts that:
- Steal banking credentials
- Modify financial transactions
- Harvest session tokens
- Inject phishing content
- Cryptocurrency wallet theft
- Corporate data exfiltration

**Secondary Risk**: Compromise of popular userscript sources leading to supply-chain attacks

**Extension Risk**: The extension code itself appears benign

## Recommendations

### For Users
1. **Only install scripts from trusted sources** (GreasyFork, OpenUserJS with reviews)
2. **Review script code before installation** - Check for suspicious network calls
3. **Disable auto-updates for critical scripts** - Manually review updates
4. **Use on non-sensitive browsing only** - Avoid on banking/work accounts
5. **Limit installed scripts** - Each script increases attack surface

### For Developers
1. **Implement script code review UI** - Show users what code they're installing
2. **Add permission system** - Let users restrict script capabilities
3. **Implement script sandboxing** - Further isolate script execution
4. **Add network monitoring** - Alert users to unexpected script network activity
5. **Verify script signatures** - Implement code signing for trusted sources

### For Security Teams
1. **BLOCK in enterprise environments** - Too risky for corporate networks
2. **Monitor for installation** - Flag any presence of userscript managers
3. **User education** - Explain risks of arbitrary code execution
4. **Incident response** - Treat as potential backdoor if detected

## Conclusion

ScriptCat is a **legitimate userscript manager** extension that is **not malware**, but represents **HIGH RISK** due to its inherent functionality. The extension code itself is clean and implements expected userscript manager features including:
- Greasemonkey API compatibility (GM_xmlhttpRequest, GM_setValue, etc.)
- Automatic .user.js file detection and installation
- Script update mechanisms
- Userscript injection into web pages

**The risk comes from the extension's purpose**: executing arbitrary third-party JavaScript with maximum privileges. This is functionally equivalent to installing a browser backdoor, even though the extension operates as designed.

**Appropriate use cases**: Advanced users, web developers, automation enthusiasts who understand JavaScript and security implications.

**Inappropriate use cases**: Corporate environments, non-technical users, sensitive accounts (banking, healthcare, government).

**Final Verdict**: The extension is **technically clean but functionally dangerous**. Risk level depends entirely on user behavior and installed scripts.

---

**Overall Risk**: **HIGH**
**Analysis Confidence**: High
**Analyst Recommendation**: Flag for user education; block in enterprise; monitor installed scripts
