# Security Analysis: Passky - Password Manager

| Field | Value |
|-------|-------|
| Extension ID | `ngncpgfjhnkgfcjamgljadegplonbihi` |
| Version | 8.1.2 |
| Manifest Version | 3 |
| Users | ~1,000 |
| Risk | **CLEAN** |
| Date | 2026-02-09 |

## Summary

Open-source password manager with client-side XChaCha20 encryption, minimal permissions, and no malicious behavior; low-severity self-XSS in popup innerHTML usage.

## Vulnerabilities

### VULN-01: Self-XSS via innerHTML in Extension Popup [LOW]

**Files:** `js/passwords.js:94-119`, `js/settings.js:85-88`, `js/login.js:91`

```javascript
// passwords.js line 94-104: Website and username from decrypted passwords inserted into innerHTML
html_passwords += "<img id='icon-" + id + "' class='h-10 w-10 rounded-full cursor-pointer' loading='lazy' src='https://www.google.com/s2/favicons?domain=" + website + "' alt=''>";
// ...
html_passwords += website;
// ...
html_passwords += username;
// ...
document.getElementById("table-data").innerHTML = html_passwords;
```

```javascript
// settings.js line 85-88: YubiKey IDs inserted via innerHTML
html += "<li class='passwordsBorderColor py-4 flex'>...<p class='secondaryColor text-sm font-medium'>" + yubico[i] + "</p>...</li>";
document.getElementById('yubico-list').innerHTML = html;
```

**Analysis:** Decrypted password data (website, username) is concatenated directly into HTML strings and set via innerHTML within the extension popup. If a user stores a password entry with a malicious website or username value containing HTML/script tags, it could execute within the extension popup context. However, the extension's strict CSP (`script-src 'self'`) blocks inline script execution, significantly limiting the impact. Additionally, this requires the user to have stored the malicious value themselves (self-XSS), making exploitation impractical in normal scenarios.

**Verdict:** LOW -- Self-XSS in extension popup mitigated by strict CSP; no practical attack vector for external actors.

---

## Flags

| Category | Evidence |
|----------|----------|
| xss | `js/passwords.js:94-122`: Decrypted password data (website, username) inserted via innerHTML without sanitization in extension popup |

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| innerHTML assignments | `js/default-functions.js:45-49`, `js/login.js:61-66`, `js/register.js:48-63` | Static SVG icon HTML strings, no user-controlled data |
| innerHTML assignments | `js/qrcode.js:757` | QR code library rendering table elements |
| `document.onkeydown` returning false | `js/header.js:88-94` | Dev tools shortcut prevention -- anti-debug measure common in password managers, not malicious |
| context menu prevention | `js/header.js:96` | Right-click prevention -- standard UI preference for password managers |

## Endpoints

| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| eu.passky.org | Primary Passky API server (Europe) | Hashed credentials (Argon2id), encrypted passwords (XChaCha20), account management requests |
| us.passky.org | Secondary Passky API server (America) | Same as above |
| www.google.com/s2/favicons | Website favicon retrieval (opt-in) | Website domain names from stored passwords |
| passky.org | Homepage / Terms of Service links | None (static links only) |
| crowdin.com | Translation project link | None (static link only) |

## Data Flow

1. **Account Creation/Login**: User provides username and password. Password is hashed client-side using Blake2b + Argon2id before being sent to the Passky server. The raw password never leaves the client.

2. **Password Storage**: When saving a password entry, all fields (website, username, password, message) are encrypted client-side using XChaCha20 with a key derived from the user's master password via Blake2b + Argon2id. Only encrypted ciphertext is sent to the server.

3. **Password Retrieval**: Encrypted passwords are fetched from the server and decrypted locally using the same XChaCha20 key. Decrypted data only exists in the extension's memory and chrome.storage.local.

4. **Autofill**: When the user clicks a password entry, the extension sends the decrypted username and password to the active tab's content script via chrome.tabs.sendMessage. The content script (which verifies sender.id matches the extension) fills in the appropriate form fields.

5. **Website Icons** (opt-in): If enabled, website domains from stored passwords are sent to Google's favicon service. The extension explicitly warns users that this may reduce privacy.

6. **Session Management**: Authentication tokens and encrypted password data are stored in chrome.storage.local with a configurable session timeout (default 20 minutes). Session data is cleared on timeout or logout.

7. **No third-party analytics, telemetry, or tracking**: The extension does not include any analytics SDKs, telemetry endpoints, or tracking mechanisms. All network communication is exclusively with user-configured Passky servers and the optional Google favicon service.

## Overall Risk: CLEAN

Passky is a well-structured, open-source password manager that follows security best practices. It uses minimal permissions (clipboardWrite, activeTab, storage), implements strong client-side encryption (XChaCha20 + Argon2id + Blake2b), has a strict Content Security Policy, and communicates only with its own servers. The content script is properly secured with a sender.id check and only performs autofill operations. The only finding is a low-severity self-XSS pattern in the popup UI where decrypted password data is inserted via innerHTML, but this is mitigated by the strict CSP and the self-XSS nature of the issue. The extension is open source (GitHub: Rabbit-Company), uses no obfuscation, and contains no signs of malicious behavior, data exfiltration, or tracking.
