# Vulnerability Report: SingleFile

## Metadata
- **Extension ID**: mpiodijhokgodhhofbcjdecpffjipkle
- **Extension Name**: SingleFile
- **Version**: 1.22.97
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

SingleFile is a legitimate browser extension that allows users to save complete web pages as single HTML files. The extension is open-source (GNU AGPL v3) and developed by Gildas Lormeau. It provides optional cloud storage integration with Google Drive, Dropbox, and Woleet (blockchain timestamping service). The extension requires broad permissions including `<all_urls>` host access to capture and process any web page, `scripting` to inject content scripts, and `downloads` to save files locally.

The analysis identified one minor security concern related to postMessage usage without strict origin validation in the editor component. However, this is limited to internal communication between the extension's UI components and does not expose sensitive data or create significant security risks. The extension operates as expected for its stated purpose of archiving web pages.

## Vulnerability Details

### 1. LOW: postMessage Without Origin Validation

**Severity**: LOW
**Files**: src/ui/bg/ui-editor.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The editor component uses `postMessage` with wildcard origin (`"*"`) to communicate between the toolbar and editor iframe.

**Evidence**:
```javascript
// src/ui/bg/ui-editor.js:90-93
addYellowNoteButton.onmouseup = () => editorElement.contentWindow.postMessage(JSON.stringify({ method: "addNote", color: "note-yellow" }), "*");
addPinkNoteButton.onmouseup = () => editorElement.contentWindow.postMessage(JSON.stringify({ method: "addNote", color: "note-pink" }), "*");
addBlueNoteButton.onmouseup = () => editorElement.contentWindow.postMessage(JSON.stringify({ method: "addNote", color: "note-blue" }), "*");
addGreenNoteButton.onmouseup = () => editorElement.contentWindow.postMessage(JSON.stringify({ method: "addNote", color: "note-green" }), "*");
```

**Verdict**: This is a minor issue as the messages are limited to editor commands (adding notes, highlighting, etc.) within the extension's own pages. The messages don't contain sensitive data and can only trigger UI actions. The impact is minimal since the editor operates on already-captured page content within the extension context.

## False Positives Analysis

The static analyzer flagged this extension as "obfuscated," but examination reveals this is due to webpack bundling (e.g., `single-file-bootstrap.bundle.js`, `single-file-frames.bundle.js`). The deobfuscated source shows clean, readable code with proper copyright headers and AGPL licensing. This is standard build tooling, not malicious obfuscation.

The extension requests extensive permissions including:
- `<all_urls>` - Required to capture any web page the user wants to archive
- `scripting` - Required to inject capture scripts into pages
- `downloads` - Required to save archived pages
- `storage` - Required to save user preferences
- `tabs` - Required to identify and process tabs

All permissions are justified by the extension's core functionality of saving complete web pages.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.woleet.io | Blockchain timestamping (optional) | SHA-256 hash of saved page | Low - Only hash, not content |
| www.googleapis.com | Google Drive upload (optional) | Saved page file (user-initiated) | Low - OAuth flow, user consent |
| api.dropboxapi.com | Dropbox upload (optional) | Saved page file (user-initiated) | Low - OAuth flow, user consent |
| content.dropboxapi.com | Dropbox upload (optional) | Saved page file (user-initiated) | Low - OAuth flow, user consent |
| accounts.google.com | OAuth authentication | OAuth tokens | Low - Standard OAuth |

All cloud storage integrations are:
1. **Optional** - Require explicit user configuration
2. **User-initiated** - Only activate when user chooses to upload
3. **Transparent** - Use standard OAuth flows with clear permission prompts
4. **Documented** - Help files explain each service integration

The Woleet service includes a hardcoded demo API key in the source (`woleet.js:25`), but this appears to be a fallback for users testing the feature without their own account.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

SingleFile is a well-designed, legitimate browser extension with a clear and useful purpose. The extension is:

1. **Open Source** - Published under GNU AGPL v3 license with full source available
2. **Transparent** - All functionality matches the stated purpose of archiving web pages
3. **Non-Malicious** - No evidence of data exfiltration, tracking, or deceptive behavior
4. **Popular & Trusted** - 400,000+ users with 4.4 rating
5. **Well-Maintained** - Active development with recent updates

The single vulnerability (postMessage without origin check) is minor and limited to internal UI communication. The extension's broad permissions are necessary for its core functionality and properly justified. Cloud storage integrations are optional, user-controlled, and use standard OAuth authentication.

**Recommendation**: This extension is safe for general use. Users should be aware that optional cloud storage features will upload saved pages to third-party services, but this is clearly disclosed and user-controlled.
