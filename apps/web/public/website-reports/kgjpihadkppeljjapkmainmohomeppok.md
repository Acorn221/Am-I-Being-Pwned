# Vulnerability Report: Universal Ad Blocker

## Metadata
- **Extension ID**: kgjpihadkppeljjapkmainmohomeppok
- **Extension Name**: Universal Ad Blocker
- **Version**: 1.1.1.2
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Universal Ad Blocker is an ad blocking extension that uses Chrome's declarative net request API along with custom content scripts for cosmetic filtering. The extension downloads blocking rulesets and cosmetic filter rules from a remote server (adsquasher.com) and periodically updates them. While the core functionality appears legitimate for an ad blocker, the extension presents medium security risks due to its remote configuration capabilities, instance tracking, and broad permissions that could be exploited if the remote infrastructure is compromised.

The extension assigns each installation a unique instance ID that is sent to the remote server, tracks uninstalls, and downloads JavaScript-based filter rules that execute in web page contexts. The combination of `<all_urls>` permissions, remote configuration, and dynamic content script registration creates a significant attack surface if the remote server is compromised.

## Vulnerability Details

### 1. MEDIUM: Remote Configuration with Instance Tracking
**Severity**: MEDIUM
**Files**: service_worker.js
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Description**: The extension downloads blocking rulesets and cosmetic filter rules from adsquasher.com on installation and every 24 hours. Each installation is assigned a unique instance ID that is sent with all requests to the remote server.

**Evidence**:
```javascript
// Instance ID assignment on install
let a = "default";
try {
    a = (await fetchJSON(config.baseUrl + "/ld/")).ld_id
} finally {
    await chrome.storage.local.set({instanceId: a}),
    chrome.runtime.setUninstallURL(config.baseUrl + "/uninstall/?ld_id=" + a)
}

// Periodic updates with instance ID
const t = await fetchJSON(config.baseUrl + "/data/?ld_id=" + a)
```

**Verdict**: While remote filter updates are common for ad blockers (e.g., uBlock Origin, AdBlock Plus), the instance tracking raises privacy concerns. If the remote server is compromised, an attacker could push malicious rulesets or track installations. The 24-hour update interval means malicious payloads could be distributed within a day.

### 2. MEDIUM: Dynamic Content Script Registration
**Severity**: MEDIUM
**Files**: service_worker.js
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Description**: The extension dynamically registers content scripts that run on `<all_urls>` with `document_start` timing in both MAIN and ISOLATED worlds.

**Evidence**:
```javascript
await chrome.scripting.registerContentScripts([{
    id: a,
    js: ["content-scripts/main.js"],
    world: "MAIN", ...e  // MAIN world has page-level access
}, {
    id: t,
    js: ["content-scripts/isolated.js"],
    world: "ISOLATED", ...e
}])
// where e = {allFrames: true, matches: ["<all_urls>"], runAt: "document_start"}
```

**Verdict**: The MAIN world content script (main.js, 11,129 lines) executes in the page's JavaScript context with full access to page variables and functions. Combined with remote configuration, this could be weaponized to inject malicious scripts if the server is compromised. The extension currently uses this for cosmetic filtering (DOM manipulation), which is legitimate.

### 3. LOW: Broad Host Permissions
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `<all_urls>` host permissions, which grants access to all websites.

**Evidence**:
```json
"host_permissions": ["<all_urls>"],
"permissions": ["declarativeNetRequest", "scripting", "storage", "unlimitedStorage", "alarms"]
```

**Verdict**: While `<all_urls>` is necessary for a comprehensive ad blocker to work on all sites, it does create a large attack surface. The extension needs these permissions for its stated purpose, so this is EXPECTED, not malicious. However, it increases the blast radius if the extension is compromised.

## False Positives Analysis

**uBlock Origin-Style Scriptlets**: The content-scripts/main.js file contains scriptlet code very similar to uBlock Origin's scriptlet library (abort-current-script, trusted scriptlets, procedural cosmetic filters). This is NOT malicious - it's a standard technique for advanced ad blocking that interferes with anti-adblock scripts.

**Cosmetic Filtering**: The extension downloads and applies CSS rules to hide elements based on class/id hashes and procedural selectors. This is standard for modern ad blockers and not a security concern.

**Message Handler**: The isolated content script sends a `setIcon` message to update the toolbar icon based on whether ad blocking is enabled for the current site. This is benign functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| adsquasher.com/ld/ | Get instance ID on install | None | MEDIUM - Tracks installations |
| adsquasher.com/data/?ld_id={id} | Fetch ruleset metadata | Instance ID | MEDIUM - Could fingerprint users |
| adsquasher.com/uninstall/?ld_id={id} | Uninstall tracking | Instance ID | LOW - Privacy concern only |
| Dynamic URLs from metadata | Download rulesets | None | MEDIUM - No integrity checks |

**Key Concerns**:
1. No TLS certificate pinning or integrity verification (e.g., signatures) on downloaded rulesets
2. Instance ID could theoretically be used to correlate browsing patterns if combined with other data
3. Uninstall URL reveals when users remove the extension

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a functional ad blocker that uses legitimate techniques (declarative net request, cosmetic filtering, scriptlets) similar to established extensions like uBlock Origin. However, it presents medium security risks due to:

1. **Remote Configuration Risk**: The extension downloads filter rules from a single server without cryptographic verification. If adsquasher.com is compromised, attackers could push malicious rules or scripts to 100,000+ users within 24 hours.

2. **Instance Tracking**: Unlike privacy-focused ad blockers (uBlock Origin doesn't track installations), this extension assigns and transmits a unique identifier, creating a privacy concern.

3. **Large Attack Surface**: The combination of `<all_urls>` permissions, MAIN world content scripts, and remote updates creates significant risk if the remote infrastructure is compromised.

**Compared to Trusted Ad Blockers**: Established ad blockers like uBlock Origin use community-maintained filter lists (often with cryptographic signatures), don't track instances, and have extensive security audits. This extension lacks these safeguards.

**Recommendation**: Users concerned about privacy or security should use established ad blockers with open-source, signed filter lists. The instance tracking and lack of integrity verification on remote updates are concerning for a security-sensitive extension category.
