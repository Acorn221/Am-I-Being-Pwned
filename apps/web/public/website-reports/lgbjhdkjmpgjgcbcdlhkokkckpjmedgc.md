# Security Analysis: DualSafe Password Manager & Digital Vault (lgbjhdkjmpgjgcbcdlhkokkckpjmedgc)

## Extension Metadata
- **Name**: DualSafe Password Manager & Digital Vault
- **Extension ID**: lgbjhdkjmpgjgcbcdlhkokkckpjmedgc
- **Version**: 1.4.35
- **Manifest Version**: 3
- **Estimated Users**: ~300,000
- **Developer**: ITOP
- **Analysis Date**: 2026-02-14

## Executive Summary
DualSafe Password Manager is a **HIGH RISK** cloud-synced password manager with significant privacy and security concerns. While the extension implements client-side AES-256-CBC encryption with HMAC-SHA256, it exhibits several red flags including mandatory cloud sync to questionable infrastructure, manipulation of Chrome's privacy settings to disable native password management, obfuscated backup domains, and server-side master key storage. The extension captures all user credentials through content scripts on every webpage and transmits them to external servers including suspicious .xyz backup domains.

**Overall Risk Assessment: HIGH**

## Vulnerability Assessment

### 1. Chrome Privacy Settings Manipulation (PRIVACY VIOLATION)
**Severity**: HIGH
**Files**: `background.service_worker.js`

**Analysis**:
The extension actively manipulates Chrome's privacy settings to disable native browser features, forcing users to rely exclusively on DualSafe:

**Code Evidence**:
```javascript
chrome.privacy.services.autofillEnabled.get
chrome.privacy.services.autofillEnabled.set
chrome.privacy.services.passwordSavingEnabled.get
chrome.privacy.services.passwordSavingEnabled.set
```

**Impact**:
- Disables Chrome's built-in autofill functionality
- Disables Chrome's native password saving
- Creates vendor lock-in - users cannot use browser features alongside the extension
- Reduces competition and user choice
- If the extension is removed, users lose all password management until they re-enable native features

**Justification**:
While password managers may need to disable conflicting features, this should be:
1. Clearly disclosed to users
2. Optional/configurable
3. Not done silently without user consent

**Verdict**: **HIGH RISK** - Anti-competitive behavior and privacy manipulation without transparent disclosure.

---

### 2. Mandatory Cloud Sync to Untrusted Infrastructure (CRITICAL CONCERN)
**Severity**: HIGH
**Files**: `ini.js`, `background.service_worker.js`

**Analysis**:
The extension maintains base64-obfuscated URLs for cloud sync endpoints including suspicious backup domains:

**Decoded URLs** (from `ini.js`):
```javascript
// Primary endpoints
urlbase: "https://pwm.itopupdate.com/"
thirdbase: "https://sso.itopupdate.com/"

// Backup/candidate domains (SUSPICIOUS)
candidate: [
  "https://pwm.kxvrqpr2.xyz/",
  "https://pwm.lywsrqs3.xyz/",
  "https://pwm.itopupdate.com/"
]
thirdbaseCandidate: [
  "https://api.kxvrqpr2.xyz/",
  "https://api.lywsrqs3.xyz/",
  "https://sso.itopupdate.com/"
]
```

**Red Flags**:
1. **Obfuscation**: URLs are base64-encoded in `ini.js` to hide them from casual inspection
2. **Suspicious TLDs**: `.xyz` domains (kxvrqpr2.xyz, lywsrqs3.xyz) are commonly associated with temporary/throwaway infrastructure
3. **Random naming**: Domain names appear randomly generated rather than professional brand identifiers
4. **No local-only mode**: No evidence of offline/local-only operation
5. **Automatic fallback**: Extension will automatically failover to .xyz domains if primary fails

**Server Communication**:
```javascript
async PostJson(url, obj, ext_headers) {
  // AES-encrypts request body with hardcoded key
  var key = CryptoJS.enc.Utf8.parse("7F37B64034E84931BDD06DC9B6A7DB72");
  let body = JSON.stringify(obj);
  body = CryptoJS.AES.encrypt(body, key, {mode:CryptoJS.mode.ECB}).toString();

  // Sends encrypted data with access token
  headers.append("token", accessToken);
  let request = new Request(url, {method:"post", headers, body});
  // ...
}
```

**Verdict**: **HIGH RISK** - Reliance on questionable infrastructure with obfuscated backup domains raises serious trust concerns.

---

### 3. Master Key Server-Side Storage (ARCHITECTURAL FLAW)
**Severity**: HIGH
**Files**: `background.service_worker.js`

**Analysis**:
While the extension implements client-side encryption, the encrypted master key is transmitted and stored on the server:

**Code Evidence**:
```javascript
async setSMK(uname, pwd) {
  // Client-side: derives key from password using PBKDF2
  let buf = await pbkdf2(fromUtf8(pwd), fromUtf8(uname), iterations, 256);
  this.sbuf = await stretchKey(buf);
  await this.save();
}

async encryptSK(sk) {
  // Encrypts symmetric key with master password-derived key
  return await aesEncrypt(sk.key.arr, this.sbuf.encKey, this.sbuf.macKey);
}

// Server sync
await UserInfo.build()).PostJson(config.set_masterkey_hash, {
  new_psk: newpsk,
  new_rkey: rsk,  // Encrypted master key sent to server
  new_masterkey_hash: hash
})
```

**Cryptographic Flow**:
1. User enters master password
2. PBKDF2 derives key from password + username (salt)
3. Master symmetric key (SK) is generated locally
4. SK is encrypted with password-derived key → `rsk`
5. **`rsk` (encrypted master key) is sent to server**
6. Vault items encrypted with SK

**Security Implications**:
- If the password-derived key is compromised (weak password, PBKDF2 cracked), the server-stored encrypted master key can be decrypted
- Server has persistent access to encrypted master keys for all users
- Creates a honeypot target - single server breach could expose all encrypted master keys
- No zero-knowledge architecture - server can theoretically access encrypted keys

**Comparison to Best Practices**:
- **Bitwarden/1Password**: Master key never leaves device, server only stores vault encrypted with master key
- **DualSafe**: Encrypted master key stored server-side, creating additional attack vector

**Verdict**: **HIGH RISK** - Architectural design creates unnecessary server-side key storage, violating zero-knowledge principles.

---

### 4. Credential Capture on All Pages (EXPECTED BUT EXPANSIVE)
**Severity**: MEDIUM (expected for password manager, but warrants scrutiny)
**Files**: `manifest.json`, `document_start.js`, `document_end.js`

**Analysis**:
Content scripts run on all pages to detect and fill login forms:

**Manifest Configuration**:
```json
"content_scripts": [{
  "all_frames": true,
  "js": ["polyfill/polyfill-firefox.js", "events.js", "ini.js", "document_start.js"],
  "matches": ["*://*/*"],
  "run_at": "document_start"
}, {
  "all_frames": true,
  "js": ["document_end.js"],
  "matches": ["*://*/*"],
  "run_at": "document_end"
}]
```

**Credential Detection** (from `fillHelper.js`):
```javascript
// Detects input fields and injects autofill icons
async showicon() {
  for (var t of this.inputsMate) {
    if ("LOGIN" === this.TYPE) {
      // Injects DualSafe icon next to password fields
      t.icon = new injIconInput(t.elem, "skin/icons/logo_20.png");
      t.icon.start();
      t.onFc = this.onFcIcon.bind(t);
      t.icon.on("click", t.onFc);
    }
  }
}
```

**What Gets Captured**:
- Usernames from detected login forms
- Passwords from password fields
- Payment card data (card number, CVV, expiration)
- Personal information (name, address, email, birthday)

**Data Flow**:
1. Content scripts detect form fields
2. User fills credentials
3. Extension captures on submit
4. Encrypts with AES-256-CBC-HMAC-SHA256
5. Transmits to pwm.itopupdate.com

**Verdict**: **MEDIUM** - Expected behavior for password manager, but combined with questionable infrastructure creates heightened risk.

---

### 5. Keylogging Flags (LEGITIMATE USE CASE)
**Severity**: LOW (False Positive)
**Files**: `events.js`, content scripts

**Analysis**:
Static analysis detected keylogging patterns, but investigation reveals legitimate use:

**Code Evidence** (`events.js`):
```javascript
// Event listeners for form interaction
this.elem.addEventListener("mousedown", this.this_onfcInput);
this.elem.addEventListener("focus", this.this_onfcInput);
this.elem.addEventListener("blur", this.this_onBlur);
this.elem.addEventListener("keydown", this.this_onkeydown);
```

**Purpose**:
- Detects when user focuses on login fields to show autofill suggestions
- Captures Enter key (keyCode 13) to dismiss autofill popup
- Does NOT capture actual key values for exfiltration
- Standard password manager behavior

**Verdict**: **LOW RISK** - False positive, legitimate form interaction detection.

---

### 6. PostMessage Without Origin Validation (POTENTIAL XSS)
**Severity**: MEDIUM
**Files**: `events.js`, `fillHelper.js`

**Analysis**:
The extension uses `postMessage` communication between content scripts and injected iframes without strict origin validation:

**Code Evidence**:
```javascript
window.addEventListener("message", r => {
  if (r && r.data && r.data.type) {
    if ("REG_SRC" === r.data.type) {
      // Processes message without origin check
      r.source.postMessage(e, "*");  // Wildcard origin
    }
  }
});

// Injected iframe communication
top.postMessage({type:"SETFILLIFRAME", data:{...}}, "*");  // Wildcard
```

**Vulnerability**:
- Messages sent to `"*"` (wildcard) allow any origin to receive
- Incoming messages not validated against expected origins
- Malicious page could potentially:
  - Eavesdrop on internal extension messages
  - Inject fake autofill prompts
  - Trigger unintended extension actions

**Exploitation Difficulty**: Medium-High (requires precise timing and message format knowledge)

**Verdict**: **MEDIUM RISK** - Improper origin validation creates potential attack surface for sophisticated XSS.

---

### 7. Dynamic Code Execution (THIRD-PARTY LIBRARIES)
**Severity**: LOW
**Files**: `document_start.js`, `document_end.js`, `background.service_worker.js`

**Analysis**:
Static analysis flagged `eval()` and `Function()` calls, but these appear limited to bundled third-party libraries:

**Context**:
- jQuery, Bootstrap, jsPDF libraries contain eval-like constructs
- Minified/obfuscated legitimate code triggers false positives
- No evidence of runtime code execution from external sources

**Verdict**: **LOW RISK** - False positives from bundled libraries, not intentional malicious eval.

---

### 8. Document.write Usage (LEGACY PATTERN)
**Severity**: LOW
**Files**: Various HTML templates

**Analysis**:
Uses `document.write` in some contexts, which is discouraged but not inherently malicious:

**Context**: Appears in templating/HTML generation for injected UI elements

**Verdict**: **LOW RISK** - Code quality issue, not security vulnerability.

---

### 9. Remote Configuration (OBFUSCATED ENDPOINTS)
**Severity**: MEDIUM
**Files**: `ini.js`

**Analysis**:
Configuration including server endpoints is stored in obfuscated form:

**Code Evidence**:
```javascript
self.GLOBAL_CONF = {
  __encode: "b64",
  urlbase: "aHR0cHM6Ly9wd20uaXRvcHVwZGF0ZS5jb20v",  // Base64
  thirdbase: "aHR0cHM6Ly9zc28uaXRvcHVwZGF0ZS5jb20v",
  candidate: [...],  // Backup domains
  debug_element: false,
  showInspection: false
};
```

**Concerns**:
- Obfuscation suggests intent to hide endpoints from users
- Could be changed remotely via extension updates without user awareness
- No transparency about where data is sent

**Verdict**: **MEDIUM RISK** - Lack of transparency about server infrastructure.

---

### 10. Analytics/Tracking (USAGE STATISTICS)
**Severity**: LOW
**Files**: `background.service_worker.js`, `events.js`

**Analysis**:
Extension sends usage statistics to stats.itopupdate.com:

**Code Evidence**:
```javascript
const useOfStatistical = async e => {
  handle.sendMessage("COUNT_USED", {code: e})
};

// Statistics endpoint
`https://stats.itopupdate.com/iusage.php?app=dpmext1&pr=${pr}&ver=${ver}&lang=${lang}&type=${type}`
```

**Data Sent**:
- Feature usage codes (e.g., "329" for login autofill, "339" for registration)
- Extension version
- Language
- Usage type

**Privacy Impact**: Minimal - usage telemetry, not sensitive user data

**Verdict**: **LOW RISK** - Standard usage analytics, no sensitive data transmitted.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Encryption | Risk |
|--------|---------|------------------|------------|------|
| `pwm.itopupdate.com` | Primary vault sync | Encrypted vault items, encrypted master key | AES-256-CBC + HTTPS | High (untrusted infra) |
| `sso.itopupdate.com` | Authentication/SSO | Login credentials, auth tokens | AES-ECB + HTTPS | High (authentication) |
| `stats.itopupdate.com` | Usage analytics | Feature usage codes, version, language | HTTPS | Low (telemetry) |
| `goto.itopupdate.com` | Redirects/navigation | Minimal metadata | HTTPS | Low |
| `pwm.kxvrqpr2.xyz` | Backup sync (suspicious) | Same as primary | AES-256-CBC + HTTPS | **Critical** (suspicious TLD) |
| `pwm.lywsrqs3.xyz` | Backup sync (suspicious) | Same as primary | AES-256-CBC + HTTPS | **Critical** (suspicious TLD) |
| `api.kxvrqpr2.xyz` | Backup API (suspicious) | Auth/API calls | AES-ECB + HTTPS | **Critical** (suspicious TLD) |
| `api.lywsrqs3.xyz` | Backup API (suspicious) | Auth/API calls | AES-ECB + HTTPS | **Critical** (suspicious TLD) |

### Data Flow Summary

**Credential Capture Flow**:
1. Content script detects login form on any webpage
2. User fills credentials
3. Extension captures username + password
4. Encrypts with AES-256-CBC-HMAC-SHA256 using master symmetric key
5. Transmits encrypted vault item to `pwm.itopupdate.com` (or .xyz fallback)
6. Encrypted master key (protected by password-derived key) also stored server-side

**Encryption Details**:
- **Algorithm**: AES-256-CBC with HMAC-SHA256
- **Key Derivation**: PBKDF2 (password + username salt)
- **IV**: Random 16-byte IV per encrypted blob
- **Format**: `IV_base64|CT_base64|MAC_base64`

**Positive**: Strong encryption algorithm
**Negative**: Master key architecture and server trust model

---

## Permission Analysis

| Permission | Justification | Risk Level | Notes |
|------------|---------------|------------|-------|
| `privacy` | Manipulate Chrome privacy settings | **HIGH** | Used to disable native autofill/password saving - anti-competitive |
| `tabs` | Access current tab for autofill | Medium | Standard for password managers |
| `storage` | Local vault storage | Low | Expected functionality |
| `idle` | Auto-lock on idle | Low | Security feature |
| `alarms` | Scheduled tasks | Low | Likely for sync/lock timers |
| `host_permissions: <all_urls>` | Autofill on all sites | High | Broad but necessary for password manager |

**Assessment**: The `privacy` permission combined with silent manipulation of browser settings is the primary concern.

---

## Cryptographic Analysis

### Strengths
1. **AES-256-CBC**: Industry-standard symmetric encryption
2. **HMAC-SHA256**: Authenticated encryption prevents tampering
3. **PBKDF2**: Proper key derivation from passwords
4. **Random IVs**: Each encrypted blob uses unique initialization vector
5. **Key stretching**: Uses `stretchKey()` to expand key material

### Weaknesses
1. **AES-ECB Mode**: Server communication uses ECB mode (weaker than CBC)
   ```javascript
   CryptoJS.AES.encrypt(body, key, {mode:CryptoJS.mode.ECB})
   ```
   ECB mode is vulnerable to pattern analysis attacks

2. **Hardcoded Server Encryption Key**:
   ```javascript
   var key = CryptoJS.enc.Utf8.parse("7F37B64034E84931BDD06DC9B6A7DB72");
   ```
   Same key used for all users' server communications - if leaked, all traffic can be decrypted

3. **Server-Side Master Key Storage**: Encrypted master keys stored on server create single point of failure

4. **PBKDF2 Iterations**: Code doesn't show iteration count - if too low, vulnerable to brute force

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | Not applicable |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote code loading | ✗ No | All code bundled in CRX |
| Cookie harvesting (beyond auth) | ✗ No | Only manages own auth tokens |
| Hidden data exfiltration | ⚠ Partial | Vault sync is disclosed but domains are obfuscated |
| Privacy setting manipulation | ✓ **Yes** | Disables Chrome autofill/password saving |

---

## Red Flags Summary

1. **Suspicious Backup Domains**: `.xyz` TLDs with random names suggest temporary infrastructure
2. **Base64 URL Obfuscation**: Hiding server endpoints indicates lack of transparency
3. **Chrome Privacy Manipulation**: Disabling native features without clear disclosure
4. **Server-Side Master Key**: Violates zero-knowledge architecture principles
5. **Hardcoded Encryption Key**: Shared key for all server communications
6. **No Local-Only Mode**: Forces cloud dependency
7. **ECB Mode**: Weaker encryption for server API calls
8. **ITOP Brand**: Unknown/unverified password manager vendor

---

## Overall Risk Assessment

### Risk Level: **HIGH**

**Justification**:

**Critical Concerns**:
1. **Untrusted Infrastructure**: Primary concern is reliance on questionable server infrastructure (itopupdate.com + suspicious .xyz backups) for storing encrypted master keys and vault data
2. **Privacy Manipulation**: Silently disables Chrome's native password management, creating vendor lock-in
3. **Architectural Flaw**: Server-side master key storage violates zero-knowledge best practices
4. **Transparency Deficit**: Obfuscated domains, unknown vendor, no security audit disclosures

**Mitigating Factors**:
1. Implements strong client-side encryption (AES-256-CBC-HMAC)
2. No evidence of plaintext credential transmission
3. No obvious data exfiltration beyond disclosed sync functionality
4. No malicious add-on injection or proxy behavior

**The Core Issue**:
While DualSafe implements reasonably strong cryptography, the fundamental trust model is broken. Users must trust:
- Unknown vendor (ITOP)
- Questionable server infrastructure (.xyz domains)
- Server-side master key storage
- Silent disabling of browser features

For a password manager handling 300K users' credentials, this trust burden is **unacceptably high**.

---

## Recommendations

### For Users (Current)
1. **Migrate Immediately**: Export passwords and switch to trusted password manager (Bitwarden, 1Password, Dashlane)
2. **Re-enable Chrome Features**: After uninstalling, go to Settings → Autofill → Passwords and re-enable native features
3. **Change Critical Passwords**: Assume passwords may be accessible to server operator
4. **Monitor Accounts**: Watch for unauthorized access to accounts stored in DualSafe

### For Platform (Chrome Web Store)
1. **Require Disclosure**: Extensions manipulating `chrome.privacy` must clearly disclose to users
2. **Flag Suspicious Domains**: Extensions with .xyz backup domains should trigger review
3. **Security Audit**: Require independent audit for password managers with >100K users
4. **Zero-Knowledge Verification**: Validate claims of client-side-only encryption

### For Developer (ITOP)
If legitimate, to rebuild trust:
1. **Remove Privacy Manipulation**: Make autofill disabling optional with clear consent
2. **Adopt Zero-Knowledge**: Implement architecture where master key never reaches server
3. **Drop .xyz Domains**: Use professional infrastructure with transparent ownership
4. **Security Audit**: Publish independent third-party security audit
5. **Open Source Crypto**: Release encryption/key management code for community review

---

## Technical Summary

**Encryption**: AES-256-CBC-HMAC-SHA256 (strong) but ECB for server comms (weak)
**Key Management**: PBKDF2 password derivation (good) but server-side master key storage (bad)
**Network Security**: HTTPS (good) but untrusted endpoints (bad)
**Privacy**: Disables native browser features without clear disclosure (bad)
**Transparency**: Obfuscated domains, unknown vendor (bad)

**Lines of Code**: ~750KB minified/bundled
**External Dependencies**: jQuery, Bootstrap, CryptoJS, jsPDF (standard libraries)
**Remote Code Loading**: None detected
**Dynamic Code Execution**: Only in bundled libraries (false positives)

---

## Conclusion

DualSafe Password Manager exhibits **HIGH RISK** characteristics that disqualify it from being recommended for securing user credentials. While the cryptographic implementation shows technical competence, the architectural choices (server-side master keys, questionable infrastructure), privacy violations (manipulating Chrome settings), and transparency issues (obfuscated domains, unknown vendor) create an unacceptable risk profile.

**The extension appears to be a functioning password manager, not outright malware**, but the trust model and infrastructure raise serious concerns about long-term security and user privacy. The presence of suspicious .xyz backup domains, combined with server-side master key storage, suggests either:
1. Poor security architecture decisions by well-meaning but inexperienced developers, OR
2. Intentional design to maintain server-side access to user vaults

Without independent security audit, transparent ownership disclosure, and infrastructure improvements, **users should avoid this extension and migrate to established, audited password managers**.

**Final Verdict: HIGH RISK** - Not recommended for production use with 300K users.
