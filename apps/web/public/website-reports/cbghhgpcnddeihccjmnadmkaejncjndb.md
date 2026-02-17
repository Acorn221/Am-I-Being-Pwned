# Vulnerability Report: Vencord Web

## Metadata
- **Extension ID**: cbghhgpcnddeihccjmnadmkaejncjndb
- **Extension Name**: Vencord Web
- **Version**: 1.14.2
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Vencord Web is a legitimate Discord client modification extension that adds custom features, plugins, and themes to the Discord web application. The extension is open-source (GitHub: Vendicated/Vencord) and transparently documents its functionality. While the static analyzer flagged some potentially concerning patterns (eval usage, postMessage without origin checks, data flows to external servers), upon manual review these are all legitimate and necessary for the extension's disclosed purpose of modifying Discord's client-side behavior.

The extension removes Discord's Content Security Policy headers to allow custom code injection, uses eval for its plugin system, and syncs user settings to an opt-in cloud service. All external network requests serve documented features (badge system, SponsorBlock integration, Last.fm scrobbling, theme downloads). The code is well-structured, not obfuscated, and matches what would be expected from a reputable open-source Discord mod.

## Vulnerability Details

### 1. LOW: Use of eval() for Remote Code Execution
**Severity**: LOW
**Files**: dist/Vencord.js (line 19444)
**CWE**: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)
**Description**: The extension downloads and executes JavaScript code from GitHub using eval() for the "oneko" plugin (cat animation that follows cursor).

**Evidence**:
```javascript
fetch("https://raw.githubusercontent.com/adryd325/oneko.js/c4ee66353b11a44e4a5b7e914a81f8d33111555e/oneko.js")
  .then(e => e.text())
  .then(e => e.replace("./oneko.gif", "https://raw.githubusercontent.com/adryd325/oneko.js/14bab15a755d0e35cd4ae19c931d96d306f99f42/oneko.gif").replace("(isReducedMotion)", "(false)"))
  .then(eval)
```

**Verdict**: While technically a security risk, this is a legitimate feature of a plugin-based Discord mod. The code is fetched from a pinned commit hash (c4ee66353b11a44e4a5b7e914a81f8d33111555e), not a mutable branch, reducing supply chain risk. The plugin system is core to Vencord's documented functionality. Users installing a Discord mod expect it to modify Discord's behavior.

### 2. LOW: postMessage Event Handlers Without Origin Validation
**Severity**: LOW
**Files**: dist/Vencord.js (lines 3882, 29725)
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension listens for window.postMessage events without explicitly checking the origin property.

**Evidence**:
```javascript
window.addEventListener("message", e => {
  t.data?.type === "vencord:meta" && ({
    EXTENSION_BASE_URL: Pg,
    EXTENSION_VERSION: T3,
    RENDERER_CSS_URL: Mg
  } = t.data.meta, window.removeEventListener("message", e), kv())
})
```

**Verdict**: The message handlers check for specific message types ("vencord:meta", "discordPopoutEvent") and only extract metadata (extension version, CSS URLs). The messages are sent from the extension's own content script (content.js) to the main world script. While origin validation would be a defense-in-depth improvement, the risk is minimal because the handlers only accept internal configuration data and don't trigger privileged operations based on external input.

## False Positives Analysis

The static analyzer flagged multiple "HIGH" severity exfiltration flows:
- `document.querySelectorAll → fetch(vencord.dev)`
- `document.getElementById → fetch(vencord.dev)`
- `message data → fetch(vencord.dev)`

**Analysis**: These are false positives. The flows relate to:
1. **Settings sync**: Users can opt-in to sync their Vencord settings to `api.vencord.dev`. The code explicitly checks `if (await Ks())` (authenticated check) before syncing. Settings are compressed and uploaded to `/v1/settings` with Authorization headers.
2. **Badge system**: Fetches user badge metadata from `badges.vencord.dev/badges.json` (static JSON, not exfiltration).
3. **Theme system**: Downloads custom CSS themes from user-configured URLs.

None of these represent hidden exfiltration. The extension's purpose is to enhance Discord with custom features, which necessarily requires storing user preferences and downloading resources.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.vencord.dev | Settings cloud sync (opt-in) | Compressed user settings, OAuth tokens | Low - documented feature, requires authentication |
| badges.vencord.dev | Badge metadata | None (GET request) | None - static data fetch |
| raw.githubusercontent.com | Theme/resource downloads | None | None - read-only resource fetching |
| sponsor.ajay.app | SponsorBlock API | Video IDs for sponsor segment lookup | None - legitimate SponsorBlock integration |
| ws.audioscrobbler.com | Last.fm scrobbling | Song metadata (if plugin enabled) | Low - disclosed Last.fm integration |
| cdn.discordapp.com | Discord CDN | None (avatar downloads) | None - accessing Discord's own CDN |

## CSP Modification Analysis

The extension uses declarativeNetRequest to remove Discord's Content-Security-Policy headers:
```json
{
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [
      {"header": "content-security-policy", "operation": "remove"},
      {"header": "content-security-policy-report-only", "operation": "remove"}
    ]
  },
  "condition": {
    "resourceTypes": ["main_frame", "sub_frame"],
    "urlFilter": "||discord.com^"
  }
}
```

**Verdict**: This is necessary for the extension's core functionality. Discord client mods require injecting custom JavaScript into the page, which CSP would block. While this technically weakens Discord's security posture, it's an explicit trade-off users make when installing client modifications. The extension is transparent about being a Discord mod.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
Vencord Web is a legitimate, open-source Discord modification with 200,000+ users and active development. While it uses potentially dangerous APIs (eval, CSP removal, postMessage), these are all necessary for its disclosed purpose and implemented responsibly. The codebase is well-structured, not obfuscated, and matches the open-source repository. External API calls serve documented features (settings sync, badges, theme downloads, SponsorBlock, Last.fm).

The "LOW" rating reflects that:
1. Users installing a Discord mod expect it to modify Discord's client behavior
2. All network requests serve disclosed, legitimate features
3. The code is open-source and auditable
4. Security-sensitive features (cloud sync) are opt-in and authenticated
5. No evidence of hidden data collection, credential theft, or malicious behavior

The main risks are inherent to any client modification tool: if a user's Vencord cloud account were compromised, an attacker could inject malicious settings; if GitHub or the Vencord API were compromised, supply chain attacks are possible. However, these are platform/infrastructure risks, not issues with the extension's design.

**Recommendation**: Safe for users who understand they are installing a Discord client modification. The extension delivers what it advertises without hidden malicious behavior.
