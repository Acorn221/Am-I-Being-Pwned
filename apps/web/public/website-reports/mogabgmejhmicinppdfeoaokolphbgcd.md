# Security Analysis Report: Gmail Mass Unsubscribe & Delete Emails

**Extension ID:** mogabgmejhmicinppdfeoaokolphbgcd
**Extension Name:** Gmail Mass Unsubscribe & Delete Emails (InboxPurge)
**Version:** 1.8.2
**User Count:** ~30,000
**Analysis Date:** 2026-02-08

---

## Executive Summary

Gmail Mass Unsubscribe & Delete Emails is a productivity extension that helps users unsubscribe from mailing lists and bulk delete promotional emails. The extension uses OAuth to access Gmail data through Google APIs and communicates with a backend service at `api.inboxpurge.com` for unsubscribe automation and user analytics.

The extension properly implements OAuth flows, uses legitimate Gmail API scopes for its intended functionality, and does not exhibit malicious behavior. However, it transmits extensive Gmail metadata to a third-party backend service, which raises privacy considerations. The extension serves its stated purpose without key security vulnerabilities.

**Overall Risk Level:** CLEAN

---

## Metadata

| Field | Value |
|-------|-------|
| Extension ID | mogabgmejhmicinppdfeoaokolphbgcd |
| Name | Gmail Mass Unsubscribe & Delete Emails |
| Version | 1.8.2 |
| Manifest Version | 3 |
| User Count | ~30,000 |
| Permissions | `tabs`, `storage` |
| Host Permissions | `https://www.googleapis.com/*`, `https://api.inboxpurge.com/*`, `https://logo.clearbit.com/*`, `https://gmail.googleapis.com/*` |
| OAuth Scopes | `gmail.modify`, `gmail.settings.basic`, `userinfo.email` |

---

## Vulnerability Analysis

### 1. Data Exfiltration to Third-Party Backend

**Severity:** LOW (Privacy Concern, Not Malicious)
**Files:**
- `background/service/subscription.service.js`
- `background/service/user.service.js`
- `background/service/auth.service.js`

**Description:**

The extension sends Gmail metadata to `api.inboxpurge.com` including:
- User email addresses
- Unsubscribe links extracted from promotional emails
- Email sender information
- Usage statistics (unsubscription counts, deletion counts)

**Code Evidence:**

```javascript
// subscription.service.js:215
static async unsubscribeAll(email, unsubscribeLinks) {
    const response = await fetch(`${Config.INBOX_PURGE_URL}/unsubscribe?_=`, {
      method: "POST",
      body: JSON.stringify({ email, unsubscribeLinks }),
      headers,
    });
}

// user.service.js:18
const response = await fetch(
  `${Config.INBOX_PURGE_URL}/user/${this.uniqueId}?_=`,
  { headers }
);
```

**Verdict:** This data transmission is part of the extension's core functionality - the backend performs automated unsubscribe requests on behalf of users. While this involves sharing email metadata with a third party, it's clearly necessary for the advertised feature and not malicious exfiltration.

---

### 2. OAuth Token Handling

**Severity:** LOW
**Files:** `background/service/auth.service.js`

**Description:**

The extension stores OAuth tokens and refresh tokens in chrome.storage.sync, which syncs across devices. Tokens are properly validated and refreshed when expired.

**Code Evidence:**

```javascript
// auth.service.js:408
static async _updateCredentials(credentials) {
  await StorageService.saveWithPrefix(
    prefixTag.CREDENTIALS,
    credentials.uniqueId,
    credentials
  );
}

// auth.service.js:164
async _refreshAuth() {
  const response = await fetch(
    `${Config.INBOX_PURGE_URL}/refresh/token?_=`,
    { headers }
  );
  // Updates provider_token, expires_in, expiry_time
}
```

**Verdict:** Token handling follows standard OAuth patterns. Tokens are stored locally (not transmitted to backend except for refresh operations), properly validated for required scopes, and refreshed when expired. No security issues identified.

---

### 3. Sentry Error Tracking

**Severity:** NEGLIGIBLE
**Files:**
- `background/background.js`
- `scripts/app.js`
- `scripts/libs/sentry.js`

**Description:**

The extension includes Sentry SDK v6.3.5 for error tracking with DSN: `https://11d4af1f68a1421bbe3d830b980176c6@o4504521903046656.ingest.sentry.io/4505525505425408`

**Code Evidence:**

```javascript
// background.js:12
Sentry.init({
  dsn: Config.SENTRY_DSN,
  tracesSampleRate: 1.0,
  release: "inboxpurge@1.8.2",
  beforeSend(event, hint) {
    const errorOrigin = hint?.originalException?.filename || "";
    if (errorOrigin.startsWith(Utils.getBaseUrl())) {
      return event;
    }
    return null;
  },
});
```

**Verdict:** Standard error tracking implementation. The `beforeSend` hook filters errors to only send those originating from the extension itself, which is good practice. This is a known FP pattern.

---

### 4. External Messaging Validation

**Severity:** NEGLIGIBLE
**Files:** `background/background.js`

**Description:**

The extension accepts external messages from `inboxpurge.com` domains for manual sign-in functionality.

**Code Evidence:**

```javascript
// background.js:164
chrome.runtime.onMessageExternal.addListener(
  async (message, sender, sendResponse) => {
    const senderURL = new URL(sender.url);
    const allowedHostnames = ["www.inboxpurge.com", "inboxpurge.com"];

    if (!allowedHostnames.includes(senderURL.hostname)) {
      console.error("Unauthorized sender:", sender.url);
      sendResponse({ status: "Unauthorized sender" });
      return;
    }

    if (message.action === "manual-sign-in") {
      AuthService.handleManualSignIn(sender.url);
      // Close popup window after sign-in
    }
  }
);
```

**Verdict:** Properly validates sender hostname against whitelist. Only allows `manual-sign-in` action from authorized domains. This is secure.

---

## False Positive Analysis

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| Sentry SDK | `scripts/libs/sentry.js`, `background/sentry.js` | Standard error tracking with origin filtering | FP - Safe |
| Fetch to third-party API | Multiple files | Backend communication for core functionality (unsubscribe automation) | FP - Legitimate |
| OAuth token storage | `background/service/auth.service.js` | Standard OAuth implementation | FP - Safe |
| Email extraction from DOM | `scripts/services/user.service.js` | Extracts user's own email from Gmail UI | FP - Safe |
| External messaging | `background/background.js` | Properly validated with hostname whitelist | FP - Safe |

---

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `api.inboxpurge.com/auth/v1/authorize` | OAuth authorization | User email | LOW |
| `api.inboxpurge.com/refresh/token` | Token refresh | Refresh token | LOW |
| `api.inboxpurge.com/unsubscribe` | Automated unsubscribe | Email, unsubscribe links | LOW |
| `api.inboxpurge.com/user/{email}` | User profile/stats | User ID | LOW |
| `api.inboxpurge.com/user/{email}/count` | Usage tracking | Unsubscribe/deletion counts | LOW |
| `api.inboxpurge.com/license/validate` | License validation | License key | LOW |
| `gmail.googleapis.com/gmail/v1/*` | Gmail API operations | Gmail data via OAuth | LOW |
| `logo.clearbit.com/{domain}` | Sender logos | Email domains | NEGLIGIBLE |

---

## Data Flow Summary

1. **User Authentication:**
   - User initiates sign-in within Gmail interface
   - Extension opens popup to `api.inboxpurge.com/auth/v1/authorize`
   - Backend redirects to Google OAuth with required scopes
   - OAuth tokens returned via URL fragment, validated for scopes
   - Tokens stored in chrome.storage.sync

2. **Mailing List Discovery:**
   - Extension queries Gmail API for CATEGORY_PROMOTIONS emails
   - Extracts sender info and unsubscribe links from headers/body
   - Fetches logos from Clearbit API (external, public service)
   - Caches mailing list locally in chrome.storage.local

3. **Unsubscribe Operation:**
   - User selects senders to unsubscribe
   - Extension sends `{email, unsubscribeLinks[]}` to backend
   - Backend performs HTTP requests to unsubscribe links
   - Optionally deletes emails via Gmail API (batch operations)
   - Updates usage statistics on backend

4. **Deletion Operations:**
   - Queries Gmail API for messages from selected senders
   - Uses Gmail batchModify API to move messages to trash
   - Implements quota management (pauses after 10k quota units)
   - Updates deletion count statistics

---

## Privacy Considerations

While not malicious, users should be aware:

1. **Third-Party Data Sharing:** Email metadata (sender addresses, unsubscribe links) is sent to InboxPurge backend servers
2. **Usage Analytics:** The service tracks unsubscribe/deletion counts tied to user emails
3. **OAuth Scope:** Requires `gmail.modify` permission (full read/write access to Gmail)
4. **External Dependencies:** Uses Sentry for error tracking, Clearbit for logos

These are all aligned with the extension's stated functionality and disclosed in the privacy policy (linked from Chrome Web Store).

---

## Overall Risk Assessment

**Risk Level:** CLEAN

**Justification:**

The extension requires extensive Gmail permissions (`gmail.modify`, `gmail.settings.basic`) and sends email metadata to a third-party backend service, which could raise red flags. However, after thorough analysis:

1. **Permissions are justified:** The extension needs full Gmail access to scan promotional emails, extract unsubscribe links, create filters, and bulk delete messages - all core features
2. **Backend communication is legitimate:** The InboxPurge API performs automated unsubscribe requests (clicking unsubscribe links on behalf of users), which requires sharing those links
3. **No malicious patterns:** No evidence of credential theft, hidden data exfiltration, ad injection, proxy networks, or other malicious behavior
4. **Proper security practices:** OAuth validation, hostname whitelisting, token refresh handling, error filtering
5. **Transparent functionality:** The extension does exactly what it advertises - helps users unsubscribe and delete bulk emails

While the extension is invasive by nature (requires broad Gmail access and shares data with backend), this is clearly part of its intended purpose. Users who install this extension understand they're granting significant access in exchange for automation of tedious unsubscribe/delete tasks.

---

## Recommendations

1. **For Users:** Review the privacy policy to understand what data is shared with InboxPurge servers
2. **For Developers:** Consider adding more granular user controls over what data is sent to backend (e.g., local-only mode)
3. **For Reviewers:** Monitor for changes to backend endpoints or addition of new data collection

---

**Analysis completed:** 2026-02-08
**Analyst:** Claude Sonnet 4.5
