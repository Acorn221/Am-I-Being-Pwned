# Vulnerability Report: UT Registration Plus

## Metadata
- **Extension ID**: hboadpjkoaieogjimneceaahlppnipaa
- **Extension Name**: UT Registration Plus
- **Version**: 2.3.0.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

UT Registration Plus is a legitimate Chrome extension designed to assist University of Texas at Austin students with course registration. The extension enhances the UT Direct registration interface with improved scheduling capabilities, conflict detection, and calendar integration features. It is developed by the Longhorn Developers student organization as an open-source project.

The ext-analyzer flagged a HIGH finding for "document.getElementById → fetch(github.com)" which initially appeared to be data exfiltration. However, detailed code analysis reveals this is a false positive: the extension legitimately fetches public GitHub contributor statistics from the Longhorn-Developers/UT-Registration-Plus repository to display developer credits in the options page. No user data, browsing history, or sensitive information is sent to any external endpoints.

## Vulnerability Details

### False Positive Analysis: GitHub API Access

**Severity**: FALSE POSITIVE (originally flagged as HIGH)
**Files**: assets/getGitHubStats-qNqAWN7_.js, assets/options-BB-mHgcy.js
**CWE**: N/A
**Description**: The ext-analyzer detected data flow from `document.getElementById` to `fetch(github.com)`. Investigation reveals this is the Octokit (official GitHub API client) library bundled in the extension.

**Evidence**:
```javascript
// Line 2600-2602 in getGitHubStats-qNqAWN7_.js
Y = "Longhorn-Developers",
qe = "UT-Registration-Plus",
Rt = `/repos/${Y}/${qe}/stats/contributors`,

// Lines 2691-2698
async fetchGitHub(r) {
  try {
    const t = new URL(r, "https://github.cachedapi.com");
    return await (await fetch(t)).json()
  } catch {
    const s = new URL(r, "https://api.github.com");
    return await (await fetch(s)).json()
  }
}

// Lines 2700-2709
async fetchContributorStats() {
  const r = `contributor_stats_${Y}_${qe}`,
    t = await this.getCachedData(r);
  if (t) return { /* cached data */ };
  const s = await this.fetchWithRetry(() => this.fetchGitHub(Rt));
  // Fetches from /repos/Longhorn-Developers/UT-Registration-Plus/stats/contributors
}
```

The extension fetches:
1. Public contributor statistics from the extension's own GitHub repository
2. User profile information for displaying contributor names/photos
3. Merged PR counts for individual contributors

This is used solely for the "About" section in the options page to credit developers. No user data is transmitted.

**Verdict**: NOT A VULNERABILITY. This is legitimate use of the GitHub API to display open-source project credits.

## False Positives Analysis

### WASM Flag
The extension includes two WASM modules:
1. **sql-wasm-Bku9E_kW.wasm** (652KB): SQLite compiled to WASM for local grade distribution database queries
2. **kc_dabr_wasm_bg-DOBW_M2a.wasm** (27KB): Rust-based Base64 encoding/decoding library

Both are used for local data processing, not for obfuscation or malicious purposes. The CSP includes `wasm-unsafe-eval` which is necessary and appropriate for WASM execution.

### "Obfuscated" Flag
The ext-analyzer flagged code as obfuscated. However, this is standard webpack/vite bundling with minified variable names (e.g., `Y`, `qe`, `Rt`). Examining the deobfuscated source shows clear, readable logic with proper imports and function names. This is NOT intentionally obfuscated malware.

### Exfiltration Flow
The single exfiltration flow detected (document → fetch) is explained above as legitimate GitHub API usage for developer credits.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.github.com | Fetch public contributor stats | API paths only (no user data) | NONE |
| github.cachedapi.com | Cached GitHub API (fallback) | API paths only (no user data) | NONE |
| utexas.bluera.com | UT course evaluation system | Opens in new tab (no fetch) | NONE |

## Privacy & Data Handling

**Local Storage Only**: The extension stores all user data (schedules, courses, preferences) in `chrome.storage.local`. No data is sent to external servers.

**Host Permissions**: All host permissions are scoped to UT Austin domains:
- `*.utdirect.utexas.edu/*` - Course registration system
- `*.utexas.collegescheduler.com/*` - Official UT schedule builder
- `*.catalog.utexas.edu/*` - Course catalog
- `*.registrar.utexas.edu/*` - Registrar schedules
- `my.utexas.edu/*` - Student portal

These are legitimate and necessary for the extension's stated purpose.

## Code Quality & Security Practices

**Positive Indicators**:
- Open-source project (Longhorn-Developers GitHub organization)
- Manifest V3 (modern security model)
- No externally_connectable declarations
- No eval() or Function() constructor usage
- Sentry error tracking for debugging (common in legitimate extensions)
- Proper message passing between content scripts and background worker
- CSP restricts to 'self' with necessary WASM exception

**Background Script Analysis**: The service worker (`background.ts-GkJuE7K2.js`) handles:
- Schedule management (add/delete/rename)
- Tab management for UT websites
- Badge count updates
- Storage synchronization

No suspicious network activity or data exfiltration logic detected.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: UT Registration Plus is a legitimate, open-source student utility extension with no security or privacy concerns. The GitHub API access flagged by static analysis is a false positive—it fetches public contributor statistics for display purposes only, with no user data involved. All extension functionality operates locally or within UT Austin's official domains. The extension follows modern security best practices with Manifest V3, proper CSP policies, and scoped permissions. Students can safely use this tool to manage their course schedules.

**Recommendation**: No action required. This extension is safe for use by UT Austin students.
