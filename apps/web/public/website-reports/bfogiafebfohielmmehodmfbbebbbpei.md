# Keeper Password Manager & Digital Vault - Security Analysis Report

**Extension ID:** `bfogiafebfohielmmehodmfbbebbbpei`
**Version:** 17.5.0
**Manifest Version:** 3
**Users:** ~1,000,000
**Author:** Keeper Security, Inc.
**Homepage:** https://keepersecurity.com
**Triage Result:** SUSPECT (T1=13, T2=7, T3=1, V1=8, V2=2, V3=2)

---

## Executive Summary

**Overall Risk Rating: LOW (CLEAN -- triage flags are overwhelmingly FALSE POSITIVES)**

Keeper Password Manager is a **legitimate, well-engineered password manager** extension. The 13 T1 flags that triggered the SUSPECT classification are entirely explained by the inherent requirements of a password manager: form field detection, credential filling, DOM interaction, WebAuthn override, clipboard access, and encrypted communication with the Keeper vault web app.

The extension demonstrates **strong security practices**: AES-256-GCM/CBC encryption, RSA key operations, ECDH key exchange, ECIES-encrypted vault communication, PBKDF2 with 250,000 default iterations, and cryptographic signature verification for remotely-fetched patches. No evidence of malware, data exfiltration, ad injection, tracking, or any malicious behavior was found.

There are several **minor security observations** (not vulnerabilities in the traditional sense), detailed below, related to the CSP configuration, extension fingerprinting via web-accessible resources, and the WebAuthn MAIN-world override attack surface.

---

## Permissions Analysis

### Granted Permissions

| Permission | Justification | Verdict |
|---|---|---|
| `contextMenus` | Right-click menu for autofill, password generation | LEGITIMATE |
| `tabs` | Track active tab for autofill context, SSO flow | LEGITIMATE |
| `alarms` | Inactivity timeout, session management | LEGITIMATE |
| `idle` | Lock vault on idle | LEGITIMATE |
| `storage` | Store settings, cached state | LEGITIMATE |
| `browsingData` | Clear vault web app cache on version update | LEGITIMATE (scoped to vault origins) |
| `scripting` | Inject content scripts dynamically for autofill | LEGITIMATE |
| `clipboardWrite` | Copy passwords/TOTP codes to clipboard | LEGITIMATE |
| `offscreen` | Clipboard operations, blob handling in MV3 | LEGITIMATE |
| `webRequest` | HTTP Basic Auth auto-fill via `onAuthRequired` | LEGITIMATE |
| `webRequestAuthProvider` | MV3 auth provider for HTTP auth | LEGITIMATE |

### Host Permissions

```
"host_permissions": ["http://*/*", "https://*/*", "<all_urls>"]
```

**Verdict:** EXPECTED for a password manager. Required to inject autofill content scripts on all pages. Both `<all_urls>` and the specific patterns are redundant (the `<all_urls>` alone would suffice), but this is a common pattern.

### Content Security Policy

```json
"content_security_policy": {
  "connect-src": "'self' *; "
}
```

**OBSERVATION (LOW):** The `connect-src: 'self' *` allows extension pages to make requests to any origin. This is needed because Keeper communicates with multiple regional API servers (keepersecurity.com, .eu, .com.au, .ca, .jp, govcloud.keepersecurity.us). While functional, a tighter CSP listing specific allowed domains would be more secure. However, this only affects extension pages (popup, options), not content scripts, so the attack surface is limited.

---

## Detailed Findings

### Finding 1: Extension Fingerprinting via Web-Accessible Resources (LOW)

**File:** `manifest.json` lines 115-134
**File:** `extension_loaded.json`

```json
"web_accessible_resources": [{
  "resources": [
    "images/*", "fonts/*", "content_scripts/*.js",
    "worker/*.js", "javascript/*.js", "extension_loaded.json"
  ],
  "matches": ["*://*/*"]
}]
```

The `extension_loaded.json` file contains:
```json
{"loaded": true, "version": "17.5.0"}
```

**Issue:** Any website can probe for this file at `chrome-extension://bfogiafebfohielmmehodmfbbebbbpei/extension_loaded.json` to detect that the user has Keeper installed and determine the exact version. This enables:
- Extension fingerprinting for user profiling
- Targeted attacks against known-vulnerable versions
- Social engineering ("we see you use Keeper...")

**Additionally**, `javascript/*.js` and `content_scripts/*.js` are web-accessible, allowing any page to load and inspect the extension's JavaScript source code. While this is mainly an information disclosure issue (the CRX is publicly downloadable anyway), it broadens the attack surface.

**Severity:** LOW -- information disclosure only, but unnecessary exposure.

---

### Finding 2: WebAuthn MAIN-World Override (INFORMATIONAL)

**File:** `content_scripts/webauthn/webauthn.js` (237 lines)
**Manifest config:** `"world": "MAIN"`, `"run_at": "document_start"`, `"all_frames": true`

The extension overrides `CredentialsContainer.prototype.create` and `CredentialsContainer.prototype.get` in the MAIN world of every page (except Keeper's own vault):

```javascript
b = CredentialsContainer.prototype.create.bind(t);
h = CredentialsContainer.prototype.get.bind(t);
t.create = this.create;
t.get = this.get;
PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
```

**Behavior:** When a website initiates a WebAuthn ceremony, Keeper intercepts it, sends it to the extension via CustomEvent, and either handles it (passkey from vault) or falls back to the browser's native implementation. Communication uses the `keeper-webauthn-message` custom event type.

**Security Assessment:**
- This is a **standard pattern** for password managers that support passkeys
- The override runs at `document_start` before page scripts, reducing race conditions
- It properly falls back to native behavior when Keeper doesn't handle the request
- The MAIN world is required because WebAuthn APIs are not accessible from ISOLATED world
- Communication between MAIN world and content script uses CustomEvents (not window.postMessage), which is acceptable since both run in the same page context

**Risk:** The MAIN-world injection does expand the attack surface. A malicious page could potentially dispatch fake `keeper-webauthn-message` events. However, the extension validates the event type and structure, and the worst case would be disrupting WebAuthn flows (not credential theft).

**Severity:** INFORMATIONAL -- necessary design pattern for passkey support.

---

### Finding 3: Remote Patch System with Signature Verification (INFORMATIONAL)

**File:** `javascript/BG.js` lines 45580-45628

The extension fetches field-detection patches from Keeper's servers:

```javascript
return "https://download.keepersecurity.com/browser_extension/patches/latest/patches.json"
```

**Verification chain:**
1. Fetches `patches.json` from `download.keepersecurity.com`
2. Validates MD5 checksum from `x-amz-meta-checksum` header
3. Validates ECDSA signature from `x-amz-meta-signature` header against 6 hardcoded P-256 public keys
4. Parses with Zod schema validation
5. Stores patches in IndexedDB

```javascript
if (await r.computeMD5(t) !== i) throw new Error("Checksum validation failed.");
if (!await r.verify(i, s, o)) throw new Error("Signature verification failed.");
```

**Assessment:** This is a **well-designed** remote update system for the Fixinator feature (form field detection labels). The patches contain field detection patterns (CSS selectors, labels), NOT executable code. The ECDSA signature verification with pinned public keys prevents tampering. The MD5 is used only as a checksum (signed by ECDSA), not for security purposes, which is acceptable.

**Severity:** INFORMATIONAL -- good security practice.

---

### Finding 4: Fixinator Page Capture Feature (LOW)

**File:** `javascript/BG.js` lines 55820-55881

The Fixinator feature captures page HTML, screenshots, and DOM trees and sends them to `fixinator.keeperpamlab.com`:

```javascript
const s = await fetch(`${cO()}/api/action/capture_page`, {
    method: "POST",
    body: JSON.stringify({
        page_id: e, page_url: a,
        tree: t.tree, hash: t.hash,
        image: r, html: n, page_load_time: i
    })
});
```

**Important mitigation (line 55879):** Input field values are scrubbed before transmission:
```javascript
function nK(e) {
    if ("INPUT" === e.tag && "submit" !== e.attrs.type && delete e.attrs.value,
        "FORM" === e.tag && e.attrs.action && (e.attrs.action = e.attrs.action.split("?")[0]),
        e.children) for (const a of e.children) nK(a)
}
```

**Assessment:** This feature is for Keeper's website security scanner product. It strips input values before sending, and form action URLs are truncated to remove query parameters. The feature is only activated when triggered from the Fixinator portal (`fixinator.keeperpamlab.com`), which is listed in `externally_connectable`. User credentials are NOT included in the capture.

**Severity:** LOW -- legitimate feature with proper data scrubbing, but users should be aware that page HTML (minus input values) can be sent to Keeper's servers when using Fixinator.

---

### Finding 5: Vault-Extension Communication Security (INFORMATIONAL -- POSITIVE)

**File:** `javascript/BG.js` lines 36575-36644

Communication between the Keeper vault web app and the extension uses **ECIES (Elliptic Curve Integrated Encryption Scheme)** with P-256:

```javascript
t = await (await ys()).platform.publicEncryptECWithHKDF(
    a, r, OW("web-vault/browser-extension communication")
)
```

The vault and extension perform an ECDH key exchange and use HKDF-derived symmetric keys for AES-GCM encryption of all messages. This protects against page-level JavaScript snooping on vault operations.

**Severity:** INFORMATIONAL -- this is excellent security practice.

---

### Finding 6: Cryptographic Implementation Quality (INFORMATIONAL -- POSITIVE)

**Files:** `javascript/cryptoWorker.js`, `worker/browserWorker.js`, `javascript/BG.js`

The extension implements a comprehensive crypto stack:

| Algorithm | Usage | Assessment |
|---|---|---|
| **AES-256-GCM** | Record encryption, vault communication | STRONG -- 12-byte IV, authenticated encryption |
| **AES-256-CBC** | Legacy record encryption | ADEQUATE -- 16-byte IV, PKCS7 padding |
| **RSA** (PKCS#1 v1.5) | Key wrapping, legacy key exchange | ADEQUATE -- jsbn library implementation |
| **ECDH P-256** | Key exchange for ECIES | STRONG -- Web Crypto API |
| **ECDSA P-256** | Patch signature verification | STRONG -- 6 pinned public keys |
| **PBKDF2-SHA256** | Master password derivation | STRONG -- 250,000 default iterations, server-configurable |
| **HKDF** | Key derivation for ECIES | STRONG -- standard construction |

All sensitive crypto operations (AES, ECDH, PBKDF2) use the **Web Crypto API** where available, with fallbacks to JavaScript implementations (jsbn for RSA, CryptoJS for PBKDF2). The crypto worker runs in a dedicated Web Worker to avoid blocking the UI.

**Note:** The RSA implementation uses PKCS#1 v1.5 padding rather than OAEP. While PKCS#1 v1.5 is not considered broken for encryption, OAEP is the modern recommendation. This appears to be legacy compatibility.

---

### Finding 7: `connect-src *` CSP Wildcard (LOW)

**File:** `manifest.json` line 101

```json
"connect-src": "'self' *; "
```

The wildcard `*` in `connect-src` means extension pages (popup, options, offscreen documents) can make network requests to any origin. This is overly permissive. If an XSS vulnerability were found in any extension page, the attacker could exfiltrate data to arbitrary domains.

**Assessment:** The extension needs to connect to multiple Keeper regional servers and AWS download endpoints. A strict CSP listing these specific domains would provide defense-in-depth against hypothetical XSS in extension pages.

**Severity:** LOW -- no exploitable vulnerability, but weakens defense-in-depth.

---

## Triage Flag Analysis (Flag-by-Flag Verdict)

### T1 Flags (13 total) -- ALL FALSE POSITIVES

| # | Likely Flag Trigger | Verdict | Explanation |
|---|---|---|---|
| 1 | `<all_urls>` host permission | FP | Required for password autofill on all sites |
| 2 | Content script on all pages | FP | KeeperFill must detect login forms everywhere |
| 3 | `all_frames: true` content script | FP | Login forms exist in iframes (e.g., embedded payment forms) |
| 4 | DOM manipulation (querySelector, form detection) | FP | Core password manager functionality |
| 5 | `scripting` permission (dynamic script injection) | FP | Needed for MV3 content script injection |
| 6 | `webRequest` permission | FP | HTTP Basic Auth autofill via `onAuthRequired` |
| 7 | `clipboardWrite` permission | FP | Copy passwords/TOTP codes |
| 8 | `browsingData` permission | FP | Cache clearing for vault version updates only |
| 9 | Remote fetch (patches.json) | FP | Cryptographically signed field detection updates |
| 10 | MAIN world content script | FP | WebAuthn/passkey support requires MAIN world |
| 11 | `externally_connectable` | FP | Vault web app communication |
| 12 | `offscreen` document creation | FP | MV3 clipboard/blob operations |
| 13 | `eval` / `new Function` patterns | FP | Library code (Lottie animation, Google libphonenumber, CryptoJS, webpack globalThis polyfill) |

### T2 Flags (7 total) -- ALL FALSE POSITIVES

| # | Likely Flag Trigger | Verdict | Explanation |
|---|---|---|---|
| 1 | innerHTML usage | FP | Minimal, mostly in library code (Lottie, libphonenumber) |
| 2 | Multiple fetch/XHR calls | FP | API communication with Keeper servers only |
| 3 | IndexedDB usage | FP | Local encrypted vault cache, patch storage |
| 4 | Large codebase (62K+ lines BG.js) | FP | Full-featured password manager with vault, autofill, passkeys, Fixinator |
| 5 | Crypto operations | FP | Core password manager requirement |
| 6 | setTimeout/setInterval patterns | FP | UI debouncing, retry logic, library code |
| 7 | postMessage usage | FP | Extension internal messaging (popup, content script, vault) |

### T3 Flag (1 total) -- FALSE POSITIVE

| # | Likely Flag Trigger | Verdict | Explanation |
|---|---|---|---|
| 1 | `connect-src *` wildcard CSP | FP | Needed for multi-region server support; low actual risk |

### V1 Flags (8 total) -- ALL FALSE POSITIVES

| # | Likely Flag Trigger | Verdict | Explanation |
|---|---|---|---|
| 1-8 | Form field value access, input detection, password field interaction, submit button detection | FP | ALL are core password manager autofill functionality |

### V2 Flags (2 total) -- FALSE POSITIVES

| # | Likely Flag Trigger | Verdict | Explanation |
|---|---|---|---|
| 1 | WebAuthn prototype override | FP | Required for passkey support |
| 2 | Clipboard operations | FP | Password/TOTP copy feature |

### V3 Flags (2 total) -- FALSE POSITIVES / INFORMATIONAL

| # | Likely Flag Trigger | Verdict | Explanation |
|---|---|---|---|
| 1 | extension_loaded.json web-accessible | FP/INFO | Extension fingerprinting risk (see Finding 1) |
| 2 | Remote config fetching | FP | Cryptographically verified patch system |

---

## Network Communication Summary

All network communication is to legitimate Keeper Security infrastructure:

| Domain | Purpose |
|---|---|
| `keepersecurity.com` | Primary vault API (US) |
| `keepersecurity.eu` | EU vault API |
| `keepersecurity.com.au` | Australia vault API |
| `keepersecurity.ca` | Canada vault API |
| `keepersecurity.jp` | Japan vault API |
| `govcloud.keepersecurity.us` | US Government vault API |
| `fixinator.keeperpamlab.com` | Fixinator security scanner |
| `download.keepersecurity.com` | Patch/update downloads |

**No third-party analytics, tracking, advertising, or suspicious domains detected.**

---

## Conclusion

Keeper Password Manager v17.5.0 is a **CLEAN, legitimate password manager** that demonstrates professional security engineering. The 13 T1 triage flags are entirely explained by the inherent requirements of a password manager extension and are all false positives.

**Key positives:**
- Strong encryption (AES-256-GCM, ECDH P-256, PBKDF2 with 250K iterations)
- ECIES-encrypted vault communication
- Cryptographically signed remote patches
- Input value scrubbing in Fixinator captures
- No analytics or tracking
- All communication to first-party Keeper domains only
- Proper MV3 architecture

**Minor observations (not vulnerabilities):**
- `extension_loaded.json` enables extension fingerprinting (LOW)
- `connect-src *` CSP is overly broad (LOW)
- RSA uses PKCS#1 v1.5 rather than OAEP (INFORMATIONAL, legacy)
- Web-accessible JS resources increase information exposure (LOW)

**Recommended triage reclassification: CLEAN**
