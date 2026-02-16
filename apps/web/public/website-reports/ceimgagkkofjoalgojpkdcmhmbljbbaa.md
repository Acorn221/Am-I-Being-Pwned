# Vulnerability Report: Affixa - Gmail (TM) Draft Display

## Metadata
- **Extension ID**: ceimgagkkofjoalgojpkdcmhmbljbbaa
- **Extension Name**: Affixa - Gmail (TM) Draft Display
- **Version**: 5.0.3
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Affixa is a Gmail utility extension designed to help users open Gmail drafts directly from external applications. While its core functionality appears legitimate, the extension implements undisclosed data collection practices that raise privacy concerns. The extension automatically queries Google's account enumeration endpoint (`accounts.google.com/ListAccounts`) to retrieve all Gmail accounts associated with the user's browser session, processes their email addresses, generates CRC32 hashes, and stores this information locally. This behavior occurs without explicit user consent or transparency in the extension's description. The lack of disclosure around account enumeration and the potential for this data to be leveraged for user tracking or profiling elevates the risk level to MEDIUM.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Gmail Account Enumeration and Hash Storage

**Severity**: MEDIUM
**Files**: `GmailAccountsManager.js`, `service_worker.js`
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension queries Google's internal `ListAccounts` API endpoint without user notification and stores hashed representations of all associated Gmail accounts.

**Evidence**:

```javascript
// GmailAccountsManager.js, lines 7-49
getAccounts = async () => {
    const response = await fetch('https://accounts.google.com/ListAccounts?listPages=0&origin=https%3A%2F%2Fwww.google.com');

    if (!response.ok) {
        throw new Error(`Response status: ${response.status}`);
    }

    let raw = await response.text();
    const acc = new Array();

    if (raw.indexOf('<head>') == -1) {
        // Remove hex encoding
        const r = /\\x([\d\w]{2})/gi;
        raw = raw.replace(r, function (match, grp) {
            return String.fromCharCode(parseInt(grp, 16));
        });
        raw = decodeURI(raw);

        // Extract email addresses using regex
        const reg = new RegExp('[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}', 'ig');
        const res = raw.match(reg);

        if (res != null) {
            for (let i = 0; i < res.length; i++) {
                let e = res[i];
                e = e.replace('googlemail.com', 'gmail.com');
                const c = this._crc32(e);  // Generate hash
                logd(levels.info, `GmailAccountsManager: -- Account ${(i + 1)}/${res.length}, Index ${i} --`);
                logd(levels.info, `GmailAccountsManager: ${e}`);  // Logs email to console
                logd(levels.info, `GmailAccountsManager: ${c}`);   // Logs hash to console

                acc.push(c);
            }
        }

        this._accounts = acc;
        this._firstCheck = true;
    }
};
```

The extension then stores account-specific preferences using these hashes:

```javascript
// GmailAccountsManager.js, lines 55-70
setAccountComposeLength = async (accountIndex, long) => {
    const val = {};
    const key = `_${this._accounts[accountIndex]}_long`;
    val[key] = long;

    const existing = await this.composeLengthIsLong(accountIndex);

    if (existing)
        return;

    await chrome.storage.local.set(val);
}
```

This data collection is triggered:
1. On extension startup (`service_worker.js`, line 69)
2. Every 15 minutes via alarm (`service_worker.js`, lines 54-67)
3. When authentication events are detected via `webRequest.onResponseStarted` listener (`service_worker.js`, lines 37-47)

**Verdict**: While the extension appears to use this information solely for mapping Gmail drafts to the correct account context, the undisclosed nature of the account enumeration and hashing behavior constitutes a privacy issue. Users are not informed that the extension collects information about all their Gmail accounts. CRC32 hashes, while not reversible, can still serve as persistent identifiers for tracking purposes. The extension description makes no mention of this data collection practice.

## False Positives Analysis

1. **URL Redirection with declarativeNetRequest**: The extension uses `declarativeNetRequest` to intercept and redirect URLs matching the pattern `https://mail.google.com/mail/?affixa=*` to an internal redirect page. This is legitimate functionality for handling external draft links and is not suspicious.

2. **Service Worker Heartbeat**: The extension implements a heartbeat mechanism to keep the service worker alive (lines 9-30 in `service_worker.js`). This is a common and necessary pattern for MV3 extensions that need to maintain state, not malicious behavior.

3. **Tab Management**: The extension queries and manipulates tabs to find existing Gmail tabs and load drafts into them. This is expected behavior for a draft management utility and aligns with its stated purpose.

4. **Google Domain Access**: The extension's access to `accounts.google.com` and `mail.google.com` is necessary for its functionality. However, the specific use of the `ListAccounts` endpoint goes beyond what is disclosed to users.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| accounts.google.com/ListAccounts | Enumerate all Gmail accounts logged into browser | HTTP GET with query params | MEDIUM - Undisclosed data collection |
| mail.google.com | Access Gmail interface and load drafts | Standard Gmail navigation | LOW - Expected functionality |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The extension's core functionality is legitimate and useful - it allows users to open specific Gmail drafts from external applications. However, the undisclosed collection and processing of Gmail account information elevates the risk to MEDIUM for the following reasons:

1. **Privacy Concern**: The extension silently enumerates all Gmail accounts associated with the user's browser session without disclosure in the extension description or requesting explicit consent.

2. **Data Processing**: Email addresses are extracted, normalized, hashed using CRC32, and stored locally. While CRC32 is not cryptographically secure, it still creates persistent identifiers that could theoretically be used for tracking.

3. **Lack of Transparency**: The Chrome Web Store listing does not mention account enumeration or data collection, violating user expectations around informed consent.

4. **Persistent Collection**: The 15-minute alarm ensures continuous refresh of account data, suggesting ongoing monitoring rather than one-time setup.

5. **No Evidence of Exfiltration**: Importantly, there is no evidence of network transmission of the collected data beyond Google's own endpoints. The data appears to remain local to the extension.

The extension would be rated CLEAN if it either:
- Explicitly disclosed the account enumeration behavior in its description
- Used a more privacy-preserving method that didn't require enumerating all accounts
- Only collected account data with explicit user opt-in

**Recommendation**: Users should be aware that this extension collects information about all Gmail accounts in their browser. While there's no evidence of malicious intent, the lack of transparency is concerning for a utility extension with 200,000+ users.
