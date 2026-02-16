# Security Analysis: CK-Authenticator G3 (odoanpnonilogofggaohhkdkdgbhdljp)

## Extension Metadata
- **Name**: CK-Authenticator G3
- **Extension ID**: odoanpnonilogofggaohhkdkdgbhdljp
- **Version**: 5.0
- **Manifest Version**: 3
- **Estimated Users**: ~1,000,000
- **Developer**: ContentKeeper (Enterprise Web Filter Provider)
- **Analysis Date**: 2026-02-14

## Executive Summary
CK-Authenticator G3 is an enterprise web content filtering authenticator that integrates Chrome browsers with ContentKeeper web filter appliances. The extension uses WebAssembly for client-side encryption of authentication credentials and communicates with on-premise ContentKeeper servers using HTTP authentication injection. While the extension appears to be a legitimate enterprise tool, it has **MEDIUM** risk due to several concerning patterns: `wasm-unsafe-eval` CSP policy, hardcoded private IP addresses for authentication servers, broad webRequest permissions with <all_urls> access, and User-Agent header modification.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Unsafe CSP Policy for WASM Execution
**Severity**: MEDIUM
**Files**:
- `/manifest.json` (line 24)

**Analysis**:
The extension uses `wasm-unsafe-eval` in its Content Security Policy to allow WebAssembly execution:

**Code Evidence** (`manifest.json`):
```json
"content_security_policy": {
    "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

**Risk Factors**:
- `wasm-unsafe-eval` directive weakens CSP protection by allowing WASM compilation
- While necessary for WASM modules, this creates potential attack surface if WASM binary is compromised
- The WASM module (`ckenc.wasm`) performs cryptographic operations and is difficult to audit

**Legitimate Use**:
The extension uses Emscripten-compiled WebAssembly module (`ckenc.js` + `ckenc.wasm`) for client-side encryption/decryption. The module exports two functions:
- `encryptData(data)` - Encrypts user email + timestamp
- `decryptData(data)` - Decrypts server responses

**Code Evidence** (`ckenc.js`, lines 1-2):
```javascript
var _decryptData=Module["_decryptData"]=function(){return(_decryptData=Module["_decryptData"]=Module["asm"]["h"]).apply(null,arguments)};
var _encryptData=Module["_encryptData"]=function(){return(_encryptData=Module["_encryptData"]=Module["asm"]["j"]).apply(null,arguments)};
```

**Verdict**: **MEDIUM RISK** - While the CSP bypass is concerning, it appears necessary for legitimate cryptographic operations. The WASM binary should be independently audited by enterprise security teams.

---

### 2. Hardcoded Private IP Addresses
**Severity**: MEDIUM
**Files**:
- `/serviceWorker.js` (lines 15-19, 51, 58, 62-65, etc.)

**Analysis**:
The extension uses two hardcoded IP addresses from the TEST-NET-1 range (RFC 5737) for authentication server communication:

**Code Evidence** (`serviceWorker.js`):
```javascript
// Line 51
getCKPortIP("192.0.2.1",parsePortIPData)

// Line 63
sendDataToSYNResp("192.0.2.1",ckAuthData)
// Fallback to second IP on error:
sendDataToSYNResp("192.0.2.2",ckAuthData)

// Line 75-76
tickleUser("192.0.2.1")
// Fallback:
tickleUser("192.0.2.2")
```

**Security Concerns**:
1. **IP Range Issues**: 192.0.2.0/24 is reserved for documentation examples (RFC 5737) and should not be routable
2. **Hardcoded Endpoints**: No dynamic server discovery or configuration
3. **HTTP-Only Communication**: All requests to these IPs use `http://` (not HTTPS)
4. **No Certificate Validation**: Plain HTTP means no TLS/SSL protection for credential exchange
5. **Network Dependency**: Extension assumes these IPs are accessible on local network

**Data Flow**:
1. Extension sends `?get_ck_ip` request to 192.0.2.1/2
2. Server responds with encrypted message containing client's external IP
3. Extension decrypts using WASM and extracts `<x>` (client IP) and `<ip>` (CK server IP)
4. Extension sends periodic "ping" with encrypted user email + Chrome version

**Code Evidence** (`serviceWorker.js`, lines 50-56):
```javascript
function prepDataForCK(){
  if(thisCKPortIP&&userEmail)try{
    var encryptedMessage=encryptData("<st>Chrome</st><v>1</v><uname>"+userEmail+"</uname><iip>"+thisChromeIP+"</iip>");
    if(!isWebAssemblyErrorMessage(encryptedMessage)){
      var ckAuthData="<ckauth>"+encryptedMessage+"</ckauth>";
      sendDataToSYNResp("192.0.2.1",ckAuthData)
    }
  }catch(exception){console.log("Module not ready. Prep data")}
}
```

**Verdict**: **MEDIUM RISK** - Using TEST-NET IPs suggests this is placeholder code or the extension relies on network-level DNS/routing magic to redirect these IPs to actual ContentKeeper appliances. This is unusual and reduces transparency.

---

### 3. HTTP Authentication Credential Injection
**Severity**: MEDIUM
**Files**:
- `/serviceWorker.js` (lines 18-38)

**Analysis**:
The extension intercepts HTTP 407 (Proxy Authentication Required) and 401 (Unauthorized) responses and automatically injects credentials:

**Code Evidence** (`serviceWorker.js`, lines 24-38):
```javascript
function gotCredentials(requestDetails,callback){
  if(userEmail&&moduleInitialized){
    new Date;
    const secondsSinceEpoch=Math.round(Date.now()/1e3);
    var credentials={},
        data=`${userEmail},${String(secondsSinceEpoch)}`;
    try{
      var messageResult=encryptData(data);
      if(!isWebAssemblyErrorMessage(messageResult)){
        var messageTokens=messageResult.split(",");
        credentials.username=messageTokens[0],
        credentials.password=messageTokens[1],
        callback({authCredentials:credentials})
      }
    }catch(exception){console.log("Module not ready. Credentials")}
  }
}
```

**Mechanism**:
1. Extension listens for 407/401 responses on ALL URLs (`<all_urls>`)
2. Encrypts `userEmail + timestamp` using WASM
3. Splits encrypted result by comma to get username/password tokens
4. Injects credentials into HTTP auth challenge automatically

**Listener Registration** (`serviceWorker.js`, line 18):
```javascript
chrome.webRequest.onAuthRequired.addListener(provideCredentialsAsync,{urls:[target]},["asyncBlocking"])
```

**Security Concerns**:
- **Broad Scope**: Operates on `<all_urls>` instead of specific domains
- **Automatic Injection**: No user confirmation required for credential submission
- **Encrypted Tokens**: Username/password are encrypted outputs, not plaintext user credentials
- **Timestamp-Based**: Credentials include epoch timestamp, suggesting time-limited tokens

**Verdict**: **MEDIUM RISK** - While this is likely the core authentication mechanism for enterprise web filtering, the broad scope and automatic injection create risk if the extension is compromised or if ContentKeeper servers are spoofed.

---

### 4. User-Agent Header Modification
**Severity**: LOW
**Files**:
- `/serviceWorker.js` (lines 91-106)

**Analysis**:
The extension modifies the User-Agent header for specific requests and injects custom authentication hash:

**Code Evidence** (`serviceWorker.js`, lines 91-106):
```javascript
chrome.webRequest.onBeforeSendHeaders.addListener(function(details){
  var headers=details.requestHeaders,
      url=details.url,
      ippos1=url.search("192.0.2.1"),
      ippos2=url.search("192.0.2.2"),
      i=0,l=headers.length;
  if(ckIDHash.length>1)
    for(i=0,l=headers.length;i<l;++i)
      if("User-Agent"==headers[i].name){
        headers[i].value=headers[i].value+"ck={"+ckIDHash+"}",
        LOG(headers[i].value);
        break
      }
  return(ippos1>0||ippos2>0)&&i<headers.length&&(headers[i].value="CKAuthenticator/Chromebook"),
         {requestHeaders:headers}
},{urls:[target]},["requestHeaders"])
```

**Behavior**:
1. **For All Requests**: If `ckIDHash` exists, appends `ck={HASH}` to User-Agent header
2. **For 192.0.2.x Requests**: Replaces entire User-Agent with `CKAuthenticator/Chromebook`

**ckIDHash Source** (`serviceWorker.js`, lines 79-89):
```javascript
chrome.webRequest.onHeadersReceived.addListener(function(details){
  if(!(platformSupported<1)){
    var headers=details.responseHeaders,i=0;
    for(i=0;i<headers.length;i++)
      if(nHeader=headers[i],"X-CKBYOD"==nHeader.name){
        LOG("found authentication hash!"),
        ckIDHash=nHeader.value,
        chrome.action.setBadgeBackgroundColor({color:greenColor}),
        chrome.action.setBadgeText({text:"on"}),
        chrome.action.setIcon({path:"img/ckauth19x.png"});
        break
      }
  }
},{urls:["http://*/*"]},["responseHeaders"])
```

**Mechanism**:
- Extension extracts `X-CKBYOD` header from HTTP responses (note: only `http://`, not `https://`)
- Stores hash value in `ckIDHash` variable
- Appends hash to User-Agent for all subsequent requests
- Changes badge to "on" with green color when hash is received

**Verdict**: **LOW RISK** - User-Agent modification is limited to adding authentication tokens and identifying the extension to ContentKeeper servers. This is expected behavior for enterprise authentication systems.

---

### 5. Identity Email Access and Usage
**Severity**: LOW
**Files**:
- `/serviceWorker.js` (lines 64-68, 50-56)
- `/manifest.json` (line 22)

**Analysis**:
The extension requests and uses the user's Google Chrome profile email via `identity.email` permission:

**Code Evidence** (`serviceWorker.js`, lines 64-68):
```javascript
function getUserInfo(userInfo){
  userEmail=userInfo.email,
  userDomain=userEmail.split("@")[1]
}
function getUserEmail(){
  chrome.identity.getProfileUserInfo(function(userInfo){
    getUserInfo(userInfo)
  })
}
```

**Permission** (`manifest.json`, line 22):
```json
"permissions": ["webRequest", "webRequestBlocking", "identity", "identity.email"]
```

**Usage**:
1. **Authentication**: User email is encrypted with timestamp and sent to ContentKeeper servers
2. **Token Generation**: Email is input to WASM encryption function to generate auth tokens
3. **Periodic Pings**: Email is included in encrypted authentication pings every 30 seconds

**Code Evidence** (`serviceWorker.js`, line 52):
```javascript
var encryptedMessage=encryptData("<st>Chrome</st><v>1</v><uname>"+userEmail+"</uname><iip>"+thisChromeIP+"</iip>");
```

**Data Transmitted**:
- User's Chrome profile email address
- Client IP address (received from ContentKeeper server)
- Chrome version identifier
- Timestamp

**Encryption**: All email data is encrypted via WASM before transmission (encryption algorithm not visible without reversing WASM binary).

**Verdict**: **LOW RISK** - Email access is appropriate for enterprise authentication. However, users should be aware their profile email is transmitted to ContentKeeper servers (encrypted).

---

## Network Activity Analysis

### External Endpoints

| Endpoint | Protocol | Purpose | Data Transmitted | Frequency |
|----------|----------|---------|------------------|-----------|
| `192.0.2.1` | HTTP | Primary CK server | Encrypted auth data (email + IP + timestamp) | Every 30 sec |
| `192.0.2.2` | HTTP | Fallback CK server | Same as above | On primary failure |

### Request Flow

**Step 1: IP Discovery** (`?get_ck_ip`)
```
GET http://192.0.2.1/?get_ck_ip&ts=[timestamp]
Response: <get_ck_ip>[encrypted_data]</get_ck_ip>
Decrypted: <x>CLIENT_IP</x><ip>CK_SERVER_IP</ip>
```

**Step 2: Authentication Ping** (`?send_ck_ping`)
```
GET http://192.0.2.1/?send_ck_ping=<ckauth>[encrypted]</ckauth>&ts=[timestamp]
Encrypted payload contains:
  <st>Chrome</st>
  <v>1</v>
  <uname>user@domain.com</uname>
  <iip>CLIENT_IP</iip>
```

**Step 3: User Tickle** (`?tickle_user`) - After receiving X-CKBYOD hash
```
GET http://192.0.2.1/?tickle_user&<h>HASH_VALUE</h>&ts=[timestamp]
Response: SUCCESS/FAILURE
```

### Data Flow Summary

**Data Collection**:
- Chrome profile email address (`identity.email` permission)
- Client IP address (from ContentKeeper server response)
- User-Agent string (browser identification)
- Authentication hash (from `X-CKBYOD` response header)

**Data Transmitted**:
- Encrypted user email (every 30 seconds)
- Encrypted timestamp (every 30 seconds)
- Encrypted client IP (every 30 seconds)
- Authentication hash (in User-Agent header for all requests)

**Encryption**: All sensitive data encrypted via WebAssembly module before transmission. Encryption algorithm unknown without WASM binary analysis.

**Network Pattern**: Continuous heartbeat every 30 seconds to maintain active authentication status with ContentKeeper web filter.

---

## Behavior Patterns

### Extension Lifecycle

**On Install/Startup**:
1. Initialize WebAssembly module (`testWebAssemblyReady()`)
2. Get user's Chrome profile email (`getUserEmail()`)
3. Set alarm for 2 seconds (`setAlarm(2000)`)
4. Start authentication loop (`ring()` function)

**Every 30 Seconds** (when authenticated):
1. Send encrypted auth ping to 192.0.2.1 (or .2 as fallback)
2. Update badge status (green "on" = connected, red "off" = disconnected)
3. If `ckIDHash` exists, send tickle request to keep session alive
4. Schedule next ring in 30 seconds

**Every 2 Seconds** (when not authenticated):
1. Retry authentication sequence
2. Show grey badge with "off" status
3. Log connection issues

**On HTTP Auth Challenge** (407/401):
1. Encrypt `userEmail + timestamp` via WASM
2. Inject encrypted tokens as HTTP auth credentials
3. Track request ID to prevent retry loops

**On X-CKBYOD Header Received**:
1. Extract hash value from `X-CKBYOD` response header
2. Store in `ckIDHash` variable
3. Update badge to green "on" status
4. Start sending User-Agent modifications with hash

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `webRequest` | Required for intercepting auth challenges and monitoring responses | HIGH (broad scope) |
| `webRequestBlocking` | Required for synchronous credential injection | HIGH (blocking) |
| `identity` | Profile access for authentication | MEDIUM (privacy) |
| `identity.email` | User email required for auth tokens | MEDIUM (privacy) |
| `host_permissions: <all_urls>` | Required for HTTP auth on any domain | HIGH (very broad) |

**Assessment**: Permissions are appropriate for enterprise web filter authentication, but scope is extremely broad (`<all_urls>`). This creates significant risk if the extension is compromised, as it can intercept ALL web traffic.

**Recommendation**: ContentKeeper should consider scoping permissions to specific domains or IP ranges if possible, though enterprise proxy scenarios may require `<all_urls>`.

---

## Content Security Policy

**Declared CSP** (`manifest.json`, lines 23-25):
```json
"content_security_policy": {
    "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

**Analysis**:
- ✅ Scripts limited to `'self'` (no external script loading)
- ✅ Objects limited to `'self'`
- ⚠️ `wasm-unsafe-eval` required for WebAssembly compilation
- ❌ CSP only applies to extension pages, not injected content

**Risk**: The `wasm-unsafe-eval` directive is necessary for WASM but weakens CSP protections. If the WASM binary is compromised via update mechanism, it could execute arbitrary code.

---

## Code Quality Observations

### Positive Indicators
1. ✅ No dynamic code execution (`eval()`, `Function()`) in JavaScript
2. ✅ No external script loading
3. ✅ No third-party analytics or tracking SDKs
4. ✅ Encryption used for credential transmission
5. ✅ Fallback server mechanism (192.0.2.1 → 192.0.2.2)
6. ✅ Request throttling and deduplication

### Concerning Patterns
1. ❌ WebAssembly binary not auditable without reverse engineering
2. ❌ HTTP-only communication (no HTTPS/TLS)
3. ❌ Hardcoded IP addresses from reserved test range
4. ❌ `<all_urls>` permission scope
5. ❌ Automatic credential injection without user confirmation
6. ❌ User-Agent modification on all requests
7. ❌ Continuous 30-second beacon to external servers

### Obfuscation Level
**MEDIUM** - JavaScript is minified but not heavily obfuscated. Core logic is auditable. However, the WebAssembly module is opaque and requires binary analysis to understand encryption algorithms and key management.

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | Legitimate enterprise proxy auth |
| Cookie harvesting | ✗ No | No cookie access observed |
| Remote code loading | ⚠️ WASM | WASM module loaded, but appears static |
| Credential theft | ⚠️ Partial | Collects email, but for legitimate auth |
| Network surveillance | ⚠️ Yes | Can intercept all HTTP auth challenges |
| User-Agent modification | ✅ Yes | Adds auth hash to UA string |

---

## WASM Analysis

### File Information
- **File**: `ckenc.wasm`
- **Size**: Unknown (not extracted in deobfuscated output)
- **Loaded by**: `ckenc.js` (Emscripten wrapper)

### Exported Functions
1. `encryptData(string) → string` - Encrypts user data
2. `decryptData(string) → string` - Decrypts server responses

### Error Messages
- `"Input data is NULL"`
- `"Input data is invalid"`

### Usage Pattern
```javascript
// Encryption example
var data = `${userEmail},${String(secondsSinceEpoch)}`;
var messageResult = encryptData(data);
// Returns: "token1,token2" (comma-separated encrypted tokens)

// Decryption example
var decryptedMessage = decryptData(encryptedServerResponse);
// Returns: "<x>IP</x><ip>IP</ip>" (XML-like format)
```

### Security Questions
1. **Encryption Algorithm**: Unknown - requires WASM binary reverse engineering
2. **Key Management**: No visible key exchange mechanism - likely hardcoded or derived
3. **Cryptographic Strength**: Cannot assess without algorithm analysis
4. **Side-Channel Attacks**: WASM may be vulnerable to timing attacks

**Recommendation**: Enterprise security teams should:
- Reverse engineer `ckenc.wasm` to verify encryption algorithms
- Assess cryptographic strength and key management
- Verify no backdoors or weak crypto implementations
- Test for side-channel vulnerabilities

---

## Privacy Impact Assessment

### Data Collected
1. Chrome profile email address
2. External IP address (from ContentKeeper server)
3. Browser User-Agent string
4. Authentication session hash

### Data Transmitted
All data encrypted via WASM before transmission:
- User email + timestamp (every 30 seconds)
- Client IP address (every 30 seconds)
- Chrome version identifier (every 30 seconds)

### Data Recipients
- ContentKeeper web filter appliances at `192.0.2.1` and `192.0.2.2`
- Note: These IPs suggest on-premise deployment (enterprise network)

### Privacy Risk Level: **MEDIUM**

**Rationale**:
- ✅ Data stays within enterprise network (not sent to external cloud services)
- ✅ Encryption used for data in transit
- ❌ Continuous monitoring (30-second beacons)
- ❌ Can intercept HTTP auth on all domains
- ❌ No HTTPS/TLS for transport security

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:

**Enterprise Context**:
This appears to be a legitimate enterprise web content filtering solution by ContentKeeper, a known provider of school/business web filtering appliances. The extension's behavior is consistent with enterprise proxy authentication systems.

**Risk Factors**:

1. **HIGH PRIVILEGE**: `webRequest` + `webRequestBlocking` + `<all_urls>` gives complete visibility and control over all web traffic
2. **CSP BYPASS**: `wasm-unsafe-eval` weakens protections and makes WASM binary critical security component
3. **UNENCRYPTED TRANSPORT**: HTTP-only communication with authentication servers (no HTTPS/TLS)
4. **OPAQUE CRYPTO**: WebAssembly encryption module not auditable without reverse engineering
5. **CONTINUOUS BEACONING**: 30-second heartbeat creates constant network activity
6. **HARDCODED IPS**: Use of TEST-NET IP range suggests unusual network configuration

**Mitigating Factors**:

1. ✅ Legitimate business purpose (enterprise web filtering)
2. ✅ Published by known enterprise security vendor (ContentKeeper)
3. ✅ ~1M users suggests widespread enterprise deployment
4. ✅ No evidence of data exfiltration to external parties
5. ✅ Encryption used for sensitive data transmission
6. ✅ No obvious malicious patterns (extension killing, ad injection, etc.)

### Recommendations

**For End Users**:
- ⚠️ This extension should ONLY be installed in managed enterprise environments
- ⚠️ Do NOT install on personal Chrome profiles
- ⚠️ Understand that your email and browsing activity may be monitored by your organization
- ⚠️ Extension requires ContentKeeper appliance on network to function

**For Enterprise IT**:
- 🔍 Audit the `ckenc.wasm` binary to verify encryption algorithms
- 🔍 Verify the 192.0.2.1/2 IP addresses are correctly routed to your ContentKeeper appliances
- 🔍 Consider implementing HTTPS for authentication server communication
- 🔍 Review logs for unauthorized credential injection attempts
- 🔍 Restrict extension installation to managed Chrome instances only
- 🔍 Monitor for extension updates that could modify WASM binary

**For ContentKeeper (Vendor)**:
- 🔧 Implement HTTPS/TLS for authentication server communication
- 🔧 Consider certificate pinning to prevent MITM attacks
- 🔧 Provide documentation on WASM encryption algorithms
- 🔧 Add domain/IP scoping options to reduce `<all_urls>` necessity
- 🔧 Implement user confirmation for credential injection (optional mode)
- 🔧 Explain the TEST-NET IP address usage (unusual choice)

---

## Technical Summary

**Lines of Code**: ~300 (JavaScript) + WASM binary
**External Dependencies**: None (beyond WASM module)
**Third-Party Libraries**: Emscripten runtime (for WASM)
**Remote Code Loading**: WASM binary (static, not dynamically loaded)
**Dynamic Code Execution**: WASM only (JavaScript contains no `eval()`)

---

## Conclusion

CK-Authenticator G3 is a **legitimate enterprise web filtering authentication extension** by ContentKeeper, designed to integrate Chrome browsers with ContentKeeper web filter appliances. The extension exhibits several concerning technical patterns (CSP bypass, HTTP-only communication, broad permissions, opaque WASM crypto) that would be considered HIGH RISK in a consumer context.

However, in the **intended enterprise deployment scenario**, these patterns are consistent with legitimate enterprise proxy authentication systems. The MEDIUM risk rating reflects the technical security concerns while acknowledging the legitimate business purpose.

**Final Verdict: MEDIUM** - Appropriate for managed enterprise deployment ONLY. Should NOT be used on personal devices or outside of ContentKeeper-equipped networks.

**Key Security Gaps**:
1. HTTP-only communication (no TLS)
2. Opaque WebAssembly cryptography
3. Unusual use of TEST-NET IP addresses
4. Very broad permission scope

**For Organizations Using ContentKeeper**: This extension is likely safe within your controlled environment, but you should verify the WASM binary integrity and ensure proper network security controls are in place.
