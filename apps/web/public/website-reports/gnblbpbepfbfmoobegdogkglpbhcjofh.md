# Vulnerability Report: Beyond 20

## Metadata
- **Extension ID**: gnblbpbepfbfmoobegdogkglpbhcjofh
- **Extension Name**: Beyond 20
- **Version**: 2.17.1
- **Users**: ~500,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Beyond 20 is a legitimate browser extension that integrates D&D Beyond character sheets with Virtual Tabletop (VTT) platforms like Roll20 and Foundry VTT. The extension facilitates dice rolling and character data synchronization between D&D Beyond and various VTT platforms. After comprehensive code review and static analysis, no security or privacy vulnerabilities were identified.

The extension uses appropriate permissions for its stated functionality, operates transparently, and does not collect or exfiltrate user data. All network communications are limited to the declared VTT platforms and the extension's own update/Discord bot API endpoints. The code is well-structured, properly obfuscated only through standard webpack bundling, and follows secure coding practices.

## Vulnerability Details

No vulnerabilities were identified during analysis.

## False Positives Analysis

### Script Injection via chrome.scripting API
The extension uses `chrome.scripting.executeScript()` to inject content scripts into VTT tabs (Roll20, Foundry VTT, and custom domains). This is the **intended and legitimate functionality** of the extension - it needs to inject scripts to enable communication between D&D Beyond and VTT platforms.

**Evidence from background.js (lines 2939-2954):**
```javascript
async function executeScripts(tabs, js_files, callback, frame_id = 0) {
    for (let tab of tabs) {
        if (manifest.manifest_version >= 3) {
            chrome.scripting.executeScript( {
                target: { tabId: tab.id, frameIds: [frame_id] },
                files: js_files
            }, callback);
        }
    }
}
```

**Verdict:** Not a vulnerability. Script injection is limited to:
- Roll20 (`app.roll20.net/editor/*`)
- Foundry VTT (user-configured)
- D&D Beyond (`*.dndbeyond.com/*`)
- Discord Activity domains (with explicit permission request)
- User-configured custom VTT domains (requires user consent)

All injected scripts are bundled with the extension (not remotely loaded).

### Optional Permission for All URLs
The manifest declares `"*://*/*"` as an optional permission. This appears broad but is **necessary and user-consented**.

**Context:** The extension allows users to add custom VTT domains to support self-hosted or alternative tabletop platforms. The permission is only requested when users explicitly configure custom domains in settings.

**Evidence from background.js (lines 493):**
```javascript
"description": "Enter a list of custom domain URLs to load Beyond20 into.\n
One domain per line, you must include the http:// or https:// protocol and
you can use wildcards for subdomains and path.\n
This can be used to send Beyond20 requests to sites that may independently
support Beyond20."
```

**Verdict:** Not a vulnerability. Permission is optional, user-configured, and transparently documented.

### Web Accessible Resources
The extension exposes numerous resources (122 files) including JavaScript files, images, and HTML pages through web_accessible_resources with `"matches": ["*://*/*"]`.

**Assessment:** This is standard practice for extensions that need to inject UI elements into web pages. The exposed resources are:
- Static images (dice icons, badges)
- jQuery library (v3.4.1)
- Alertify notification library
- Extension-specific scripts for VTT integration
- UI pages (popup.html, options.html)

**Verdict:** Not a vulnerability. No sensitive data or dangerous functionality exposed. All resources are static or designed for page interaction.

### External Domains Contacted
The extension communicates with several external domains:
- `beyond20.kicks-ass.org` - Discord bot API for sending dice rolls to Discord
- `beyond20.here-for-more.info` - Update/changelog information
- `app.roll20.net` - Roll20 VTT platform
- `dndbeyond.com` - D&D Beyond (source of character data)
- `forge-vtt.com` - Foundry VTT hosting service
- Discord and other supported VTT platforms

**Verdict:** All domains are legitimate, documented, and directly related to the extension's stated functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| beyond20.kicks-ass.org/roll | Discord bot API for dice rolls | Dice roll data, character info | LOW - Disclosed functionality |
| beyond20.here-for-more.info/update | Changelog/update info | None (read-only) | NONE |
| app.roll20.net/editor/ | Roll20 VTT integration | Dice rolls, character stats | NONE - Core functionality |
| *.dndbeyond.com/* | Character data extraction | None (read-only) | NONE - Source platform |
| *.forge-vtt.com/game | Foundry VTT integration | Dice rolls, character stats | NONE - Core functionality |
| discord.com | Discord Activity integration | Roll data (optional feature) | NONE - User-enabled |

## Code Quality Assessment

**Positive Security Indicators:**
- Uses Manifest V3 (modern security model)
- Proper use of chrome.storage.local for settings (no sync to avoid data leaks)
- Migration from chrome.storage.sync to local storage (line 1460) shows privacy awareness
- No use of eval(), Function(), or dangerous dynamic code execution
- No cookie harvesting or credential theft
- No browser history or tab URL collection
- Service worker implements keep-alive pattern (line 3072-3074) which is standard MV3 practice
- Message passing uses proper chrome.runtime.sendMessage API with structured messages

**Code Structure:**
- Well-organized with clear separation between background, content scripts, and page scripts
- Extensive configuration system for D&D character features (classes, abilities, etc.)
- Proper error handling and user feedback via alertify notifications

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification:**
Beyond 20 is a legitimate, well-designed extension with no security or privacy concerns. The extension:

1. **Operates transparently** - All functionality matches the stated purpose of integrating D&D Beyond with VTT platforms
2. **Respects user privacy** - No data collection, tracking, or analytics
3. **Uses appropriate permissions** - All permissions are necessary and properly scoped
4. **Follows secure coding practices** - No dangerous patterns like eval(), remote code loading, or credential harvesting
5. **Has strong user trust** - 500,000 users with 4.8/5 rating indicates community validation
6. **Is actively maintained** - Version 2.17.1 with ongoing updates

The extension serves a specific niche (D&D players using Virtual Tabletops) and executes that purpose without overreach or hidden behavior. The optional `*://*/*` permission is properly gated behind user configuration for custom VTT domains, and all script injections are limited to relevant gaming platforms.

**Recommendation:** Safe for continued use. No remediation required.
