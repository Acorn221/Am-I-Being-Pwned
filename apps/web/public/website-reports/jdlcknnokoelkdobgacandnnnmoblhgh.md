# Vulnerability Analysis Report: Gmail Unsubscribe Tool by Trimbox

## Extension Metadata

- **Extension Name**: Gmail Unsubscribe Tool by Trimbox
- **Extension ID**: jdlcknnokoelkdobgacandnnnmoblhgh
- **Version**: 3.0.6
- **User Count**: ~90,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Gmail Unsubscribe Tool by Trimbox is a legitimate extension that helps users unsubscribe from email lists and manage Gmail filters. The extension uses OAuth 2.0 to access Gmail APIs with broad permissions (`gmail.modify`, `gmail.settings.basic`). While no malicious code was detected, the extension presents **MEDIUM risk** due to hardcoded API credentials, analytics tracking with personally identifiable information (PII), and powerful Gmail manipulation capabilities that could be abused if the extension infrastructure were compromised.

**Overall Risk Level**: **MEDIUM**

## Vulnerability Details

### 1. MEDIUM - Hardcoded API Credentials and Secrets

**Severity**: MEDIUM
**File**: `app/background/main.mjs` (lines 4533-4720)
**Category**: Credential Exposure

**Details**:
The extension hardcodes sensitive credentials for multiple third-party services directly in client-side code:

```javascript
// OAuth Client Secrets (lines 4533, 4582, 4630, 4678)
clientSecret: "7d3u2hCnqMU3H40IswkPrpzE"
clientSecret: "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"
clientSecret: "jrfKZRNeuiT0U2SBWeZE0bcG"

// Mixpanel Service Account Password (line 4572, 4620, 4668, 4716)
password: "Sp6wP9AWUqhTw4YAF9sE2zpM0iV9nd42"

// Server API Keys (lines 4559, 4607, 4655, 4703)
apiKey: "64ZFxkyB1tN2KIHuOqkAZWhyqsKewY03"

// RevenueCat API Key (lines 4566, 4614, 4662, 4710)
apiKey: "appl_INwPSmPuclqEogxFBKVutCqLhSZ"

// FingerprintJS Tokens (lines 4545, 4593, 4641, 4689)
fingerprintJsToken: "wtsyZxlTKYj10xhcMZwF"
fingerprintJsToken: "0jfSuHTgPbyKc61fDagw"
```

**Verdict**: **VULNERABLE**
These credentials are extractable by anyone who downloads the extension. While this is common practice for client-side OAuth flows, it creates risk if the secrets are reused or if rate limits/quotas are shared across all users.

---

### 2. MEDIUM - Extensive Analytics Tracking with PII

**Severity**: MEDIUM
**Files**: `app/background/main.mjs` (lines 5048-5353)
**Category**: Privacy / Data Collection

**Details**:
The extension sends detailed analytics to Mixpanel (https://api.mixpanel.com) including:

- User email addresses as distinct_id (line 5187)
- Gmail thread counts (line 6300)
- Unsubscribe/trash operations with mailing list IDs (lines 4536-4540)
- Device fingerprints via FingerprintJS tokens (lines 4545, 4689)
- OAuth credential refresh events (lines 5562-5568)

Example tracking code:
```javascript
async trackEventAsync({ event, userId, properties }) {
  const deviceId = await this.config.getOrCreateDeviceId();
  const token = await this.config.getProjectToken();
  let e = {
    event,
    properties: {
      ...properties,
      ...(await this.config.getSuperProperties(userId)),
      distinct_id: userId, // User email
      $device_id: deviceId,
      time: Date.now(),
      token,
    }
  };
}
```

**Verdict**: **PRIVACY_CONCERN**
While analytics are disclosed in general terms, the granular tracking of email operations and use of email addresses as identifiers may exceed user expectations for a Gmail utility.

---

### 3. MEDIUM - Powerful Gmail Manipulation Permissions

**Severity**: MEDIUM
**Files**: `app/background/main.mjs` (lines 42246, 42322-42323, 23789-23813, 42824-42838)
**Category**: Excessive Permissions / Abuse Potential

**Details**:
The extension requests broad Gmail permissions during OAuth flow:

```javascript
// Required scopes (lines 42246, 42322-42323)
"https://www.googleapis.com/auth/gmail.modify"
"https://www.googleapis.com/auth/gmail.settings.basic"
"https://www.googleapis.com/auth/userinfo.email"
```

These permissions allow the extension to:

1. **Modify/Delete Messages** (lines 23796-23813):
```javascript
async _modifyMessages({ userId, body }, authToken) {
  const response = await fetch(
    `https://gmail.googleapis.com/gmail/v1/users/${userId}/messages/batchModify`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${authToken}` },
      body: JSON.stringify(body), // addLabelIds: ["TRASH"]
    }
  );
}
```

2. **Create/Delete Gmail Filters** (lines 41949, 42031, 42042):
```javascript
await this.gmail.createFilter({ userId, filter });
await this.gmail.deleteFilter({ userId, filterId: filter.id });
```

3. **Batch Trash Threads** (lines 42824-42838):
```javascript
await this.gmail.modifyMessages({
  userId,
  body: {
    ids: batch.map((m) => m.id),
    addLabelIds: ["TRASH"],
    removeLabelIds: ["INBOX"],
  },
});
```

**Verdict**: **NECESSARY_BUT_RISKY**
These permissions are required for the extension's core functionality but could be abused to delete important emails, create malicious filters, or exfiltrate email content if the backend infrastructure (trimbox.io, Firebase) were compromised.

---

### 4. LOW - Third-Party Service Dependencies

**Severity**: LOW
**Files**: `app/background/main.mjs` (lines 4547-4704, 5700-5862)
**Category**: Supply Chain Risk

**Details**:
The extension relies on multiple third-party services:

- **Firebase Realtime Database**: `trimbox-production-default-rtdb.firebaseio.com` (line 4694)
- **Trimbox Backend API**: `https://app.trimbox.io` (line 4704)
- **RevenueCat Subscriptions**: `https://api.revenuecat.com` (line 4778)
- **Mixpanel Analytics**: `https://api.mixpanel.com` (line 5050)
- **Stripe Payments**: `${this.origin}/v1/stripe/checkouts` (line 5825)

Backend API calls with JWT auth (lines 5715-5747):
```javascript
async findUser(email) {
  let req = new Request(`${this.origin}/v1/users?email=${email}`, {
    headers: {
      Authorization: `Bearer ${await CredentialService.getIdToken(email)}`,
    },
  });
  const res = await fetch(req);
}
```

**Verdict**: **ACCEPTABLE**
Standard SaaS architecture, but creates multiple points of potential compromise.

---

### 5. LOW - Debug Logging Sends Sensitive Data

**Severity**: LOW
**Files**: `app/background/main.mjs` (lines 42936-42946)
**Category**: Information Disclosure

**Details**:
Debug functionality sends filter configurations and mailing list statuses to developer emails:

```javascript
async _sendLog(userId, log) {
  const messageBuilder = new MessageBuilder();
  messageBuilder.withRecipient("jordan@trimbox.io");
  messageBuilder.withRecipient("dave@trimbox.io");
  messageBuilder.withSubject(`DEBUG_LOG ${UUID.create()}`);
  messageBuilder.withBody(log); // Contains mailingListStatuses, filters
  return await this.gmail.sendMessage({ userId, message: messageBuilder.build() });
}
```

**Verdict**: **MINOR_CONCERN**
Requires explicit user action (`sendDebugLog` call), but could leak filter patterns and email metadata.

---

## False Positives Table

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| `Function('return this')()` | line 6889 | Lodash library detecting global scope | False Positive |
| `new Function()` | line 21395 | Lodash template compilation (standard library) | False Positive |
| `isFunction()` checks | lines 109-18168 | Bacon.js and Lodash type checking utilities | False Positive |
| `firebase` references | lines 4547-4704 | Firebase SDK configuration (public API keys) | False Positive |
| `.filter()` calls | multiple | Array/stream filtering operations, not Gmail filters | False Positive |
| jQuery `innerHTML` | N/A | Not present (uses React/modern DOM APIs) | N/A |
| `eval()` or dynamic imports | N/A | Not present | N/A |

---

## API Endpoints and Data Flow

### External API Calls

| Endpoint | Purpose | Data Sent | Auth Method |
|----------|---------|-----------|-------------|
| `https://oauth2.googleapis.com/token` | Refresh OAuth tokens | refresh_token, client_id, client_secret | Client credentials |
| `https://gmail.googleapis.com/gmail/v1/users/{userId}/messages/batchModify` | Trash emails | Message IDs, label modifications | Bearer token (OAuth) |
| `https://gmail.googleapis.com/gmail/v1/users/{userId}/settings/filters` | Manage filters | Filter criteria (sender emails, queries) | Bearer token (OAuth) |
| `https://app.trimbox.io/v1/users` | User account sync | Email, last seen timestamp, unsubscribe counts | Bearer token (ID token) |
| `https://app.trimbox.io/v1/stripe/checkouts` | Billing sessions | Email, subscription details | Bearer token (ID token) |
| `https://api.revenuecat.com/v1/subscribers/{email}` | Subscription status | Email (in URL path) | API key header |
| `https://api.mixpanel.com/track` | Event analytics | Email, event type, properties, device ID | Project token (in body) |

### Data Flow Summary

1. **Content Script** (`app/content/main.js`) extracts user email from Gmail DOM → Sends to background via `chrome.runtime.sendMessage`
2. **Background Script** initiates OAuth flow via `chrome.identity.launchWebAuthFlow` → Stores tokens in `chrome.storage.sync`
3. **Gmail API calls** use stored OAuth tokens to list/modify messages and create filters
4. **Backend sync** sends operation counts (unsubscribes, trashed threads) to Trimbox servers
5. **Analytics** track user actions with email as identifier to Mixpanel

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:
- ✅ **No malware detected**: No obfuscation, XHR hooking, extension enumeration, or remote code execution
- ✅ **Legitimate functionality**: Core features (unsubscribe, filter management) align with stated purpose
- ✅ **Standard OAuth flow**: Uses Google's identity APIs properly with appropriate scopes
- ⚠️ **Hardcoded credentials**: Client secrets and API keys exposed in bundled code
- ⚠️ **Privacy concerns**: Granular analytics tracking with email addresses and operation metadata
- ⚠️ **Broad permissions**: `gmail.modify` allows arbitrary email manipulation
- ⚠️ **Supply chain risk**: Depends on Trimbox infrastructure (Firebase, backend API) for core functionality

### Threat Model
**Primary Risk**: Compromise of Trimbox backend infrastructure or Firebase credentials could enable:
- Mass email deletion/exfiltration via stored OAuth tokens
- Injection of malicious Gmail filters to forward emails to attacker addresses
- Unauthorized access to 90k users' email metadata (senders, thread counts)

**Secondary Risk**: Hardcoded credentials could be extracted and abused for:
- Quota exhaustion attacks against Trimbox APIs
- Unauthorized Mixpanel/RevenueCat API calls
- Impersonation of extension in OAuth flows

### Recommendations
1. Move OAuth client secrets to backend server-side flow (PKCE for public clients)
2. Implement stricter scopes (use `gmail.readonly` where possible)
3. Add user consent UI before sending PII to analytics
4. Rotate exposed API keys (Mixpanel service account, RevenueCat, server API key)
5. Implement certificate pinning for Trimbox backend API calls

---

## Code Quality Notes
- Uses modern MV3 manifest with service worker architecture
- Properly structured with Bacon.js reactive streams and Lodash utilities
- No minification/obfuscation (deobfuscated output is readable)
- Includes comprehensive error handling and retry logic
- CSP properly configured: `script-src 'self'; object-src 'self'`

---

## Conclusion

Trimbox is a professionally developed extension with no evidence of malicious intent. The **MEDIUM** risk classification reflects legitimate but powerful Gmail access combined with credential exposure and privacy tracking practices that exceed typical user expectations. The extension is safe for informed users who understand the permissions granted, but poses supply chain risks if Trimbox infrastructure were compromised.
