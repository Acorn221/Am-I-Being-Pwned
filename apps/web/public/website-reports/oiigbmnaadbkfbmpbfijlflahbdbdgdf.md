# Vulnerability Report: ScriptSafe

## Metadata
- **Extension ID**: oiigbmnaadbkfbmpbfijlflahbdbdgdf
- **Extension Name**: ScriptSafe
- **Version**: 1.0.9.3
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

ScriptSafe is a comprehensive security and privacy extension designed to block scripts, plugins, and other potentially harmful web content. It provides features including script blocking, anti-fingerprinting protections, user-agent spoofing, referrer control, and ad/tracker blocking. The extension is open-source, licensed under GPL, and includes extensive privacy protection mechanisms.

After thorough analysis of the codebase, no malicious behavior, data exfiltration, or security vulnerabilities were identified. The extension operates entirely locally and does not communicate with any external servers. All functionality is consistent with its stated purpose as a security tool similar to NoScript.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

Several patterns that might initially appear concerning are actually legitimate security features:

1. **User-Agent Spoofing**: The extension allows users to spoof their browser's user-agent string (lines 104-200 in scriptsafe.js). This is an intentional privacy feature to prevent fingerprinting, not malicious behavior.

2. **Referrer Manipulation**: The extension can modify or remove HTTP referrer headers (lines 94-102 in scriptsafe.js). This is a privacy protection feature to prevent tracking across sites.

3. **Cookie Stripping**: The extension can strip cookies from requests to third-party trackers (line 91 in scriptsafe.js). This is anti-tracking functionality.

4. **WebRequest Blocking**: The extension uses webRequest and webRequestBlocking permissions to intercept and block scripts, images, iframes, and other content. This is the core functionality of a script blocker.

5. **Fingerprint Protection**: The content script (ss.js) hooks various browser APIs to prevent fingerprinting:
   - Canvas fingerprinting protection (lines 161-236)
   - Audio fingerprinting protection (lines 237-284)
   - WebGL, Battery API, Gamepad API blocking (lines 297+)
   - These are legitimate anti-fingerprinting defenses, not malicious hooking.

6. **Large Blocklist File**: The yoyo.js file (55,914 lines, 1.6MB) contains antisocial widget blocklists and ad/tracker domain lists. This is a standard blocklist similar to those used by privacy extensions.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | N/A | None |

**Finding**: This extension does not contact any external endpoints. All functionality is local. The only URLs referenced in the code are:
- `https://chrome.google.com/webstore` (whitelisted, not blocked)
- `http://www.gnu.org/licenses/` (GPL license reference in comments)

## Permission Analysis

The extension requests broad permissions, but all are justified by its functionality:

- **http://*/*, https://*/***: Required to inject content scripts for blocking and anti-fingerprinting
- **webRequest, webRequestBlocking**: Core functionality for intercepting and blocking network requests
- **tabs**: Required to track which tabs have blocked content
- **storage, unlimitedStorage**: For storing user whitelist/blacklist preferences and settings
- **privacy**: Used to control WebRTC IP handling policy (privacy feature)
- **notifications**: To notify users of blocking events
- **contextMenus**: Provides right-click menu options for quick allow/block

## Code Quality & Transparency

**Positive indicators**:
- GPL-licensed open source code
- Clear copyright headers identifying author ("andryou")
- Well-structured code with descriptive function names
- Credits given to inspiration sources (NotScripts, AdBlock Plus, Ghostery)
- No obfuscation (ext-analyzer flagged as obfuscated, but this is likely due to the large blocklist data structure in yoyo.js, not malicious obfuscation)

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: ScriptSafe is a legitimate, open-source security extension that operates transparently and entirely locally. All functionality matches its stated purpose as a script blocker and privacy protector. The extension does not collect, transmit, or exfiltrate any user data. The broad permissions are necessary for its core blocking and anti-fingerprinting features. No malicious code, hidden functionality, or security vulnerabilities were detected.

The extension provides genuine security value by:
1. Blocking potentially malicious scripts and plugins
2. Preventing browser fingerprinting through multiple techniques
3. Blocking tracking cookies and social widgets
4. Stripping tracking parameters from URLs
5. Allowing user control over WebRTC IP handling

This is a well-designed privacy tool with no security concerns.
