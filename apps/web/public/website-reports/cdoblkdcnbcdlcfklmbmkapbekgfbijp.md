# Vulnerability Report: Happy dog - virtual pet for you and friends

## Metadata
- **Extension ID**: cdoblkdcnbcdlcfklmbmkapbekgfbijp
- **Extension Name**: Happy dog - virtual pet for you and friends
- **Version**: 2.36.7
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Happy dog" is a virtual pet extension that allows users to adopt, care for, and interact with an AI-powered virtual dog. The extension provides social features for co-parenting pets with friends, AI chat functionality, personality customization, and diary/memory features. The extension collects user interaction data, personality profiles, and chat conversations to power its AI features, which are disclosed as part of the core functionality. While the data collection aligns with the extension's stated purpose, it requests broad host permissions (`http://*/*`, `https://*/*`) that are overly permissive for a virtual pet game.

Static analysis flagged one exfiltration flow where stored user session data is sent to external APIs. However, this is expected behavior for a social gaming extension that synchronizes pet state across devices and users. The extension does not exhibit malicious characteristics, hidden data collection, or credential theft.

## Vulnerability Details

### 1. LOW: Overly Broad Host Permissions

**Severity**: LOW
**Files**: manifest.json, background.js, main.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**: The extension requests host permissions for all HTTP/HTTPS URLs (`http://*/*`, `https://*/*`), which is excessive for a virtual pet extension. The extension uses these permissions to inject a content script (`main.js`) that displays the virtual pet overlay on web pages and synchronizes pet state. While the scripting permission is used for legitimate UI injection, the broad scope creates unnecessary attack surface.

**Evidence**:
```json
"host_permissions": [
    "http://*/*",
    "https://*/*"
],
"permissions": [
    "tabs",
    "storage",
    "scripting"
]
```

```javascript
// background.js - Injects content script into all tabs
chrome.scripting.executeScript({
    target: { tabId: t.id },
    files: ["main.js"]
}, () => {});
```

**Verdict**: This is a common pattern for overlay/companion extensions. While the permissions are broader than necessary, they are used solely for displaying the virtual pet UI across web pages. No sensitive data collection from page content was observed. The extension could limit injection to specific domains if it wanted to reduce scope, but this is not a critical security issue given the benign use case.

## False Positives Analysis

**1. Data Exfiltration Flag**
The static analyzer correctly identified data flows where `chrome.storage.local` data is sent to remote endpoints. However, this is expected and disclosed behavior for a social virtual pet game:
- User session data (space name, pet name, user name) is sent to Firebase Cloud Functions to synchronize pet state
- Cached user actions (feeding, playing, etc.) are batched and sent when the popup closes
- Personality profiles and chat messages are sent to AI endpoints for generating personalized responses

All endpoints are first-party domains owned by the extension developer (gethappydog.com, office-pets cloud functions).

**2. Remote Config Flag**
The extension fetches pet state, goodies inventory, and AI-generated content from remote servers. This is fundamental to the multi-user, cloud-synced nature of the application and is not malicious remote code execution.

**3. OAuth2 Scope**
The extension requests `userinfo.email` via Google OAuth2. This is used for user account management and is appropriately scoped (email only, no broader Google account access).

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.gethappydog.com/referral | Referral tracking on install | Browser cookies | Low - Marketing attribution |
| us-central1-office-pets.cloudfunctions.net/batch_action_update | Sync pet actions | Pet name, space, user, action list, client_id | Low - Core functionality |
| us-central1-office-pets.cloudfunctions.net/createPet-3 | Create new pet | Pet name, breed, client_id | Low - Core functionality |
| us-central1-office-pets.cloudfunctions.net/getGoodies | Fetch cosmetic items | Pet info | Low - Game state |
| update-personality-profile-551090273917.us-central1.run.app | Update AI personality | Pet ID, personality traits | Low - Disclosed AI feature |
| diary-551090273917.us-central1.run.app | Generate pet memories | Pet ID, timestamp | Low - AI content generation |
| adventure-chat-551090273917.us-central1.run.app | AI chat conversations | Pet ID, chat messages | Low - Core AI chat feature |
| storage.googleapis.com/office-pets/* | Static assets | None (CDN requests) | None - Image hosting |
| gethappydog.com/* | Website links | None (opens external pages) | None - Navigation |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate virtual pet social gaming extension with AI-powered features. The data collection patterns align with its disclosed functionality:
- Pet state synchronization for multi-user spaces
- Personality profiling for AI chat customization
- User action tracking for game mechanics (mood, hunger, energy)
- Chat message processing for AI conversation features

**Why not CLEAN:**
- Requests overly broad host permissions that exceed what's necessary for a pet overlay
- Collects user interaction patterns and personality data, though disclosed

**Why not MEDIUM or higher:**
- No undisclosed data collection
- No sensitive credential access (OAuth limited to email)
- No ad injection, affiliate manipulation, or monetization beyond disclosed in-app purchases
- No evidence of third-party data sharing
- No access to browsing history, passwords, or financial data
- Clean code with readable deobfuscated output (not heavily obfuscated)

**Recommendation**: The extension is safe to use for users who accept the disclosed data collection for AI pet features. Users concerned about privacy should note that pet interactions, chat messages, and personality profiles are stored on the developer's servers to enable the social and AI features.
