# Vulnerability Report: PhishWall

## Metadata
- **Extension ID**: alohbabbpkchbmiihojaffcfnbkmgpdo
- **Extension Name**: PhishWall
- **Version**: 6.4.2.1
- **Users**: ~600,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

PhishWall is a legitimate anti-phishing browser extension developed by Hitachi Systems, Ltd. for the Japanese market. It works in conjunction with a local desktop client (PhishWall) installed on the user's machine to provide real-time phishing protection for banking and financial institution websites. The extension monitors web navigation, sends visited URLs to a local security service running on localhost:8888, and displays visual indicators (colored icons) to signal the safety status of websites. The extension also modifies User-Agent headers for specific Japanese banking sites to ensure compatibility with their online banking systems.

While the extension has legitimate security purposes and only communicates with a local desktop application (not external servers), it uses overly broad permissions (`<all_urls>`) that could be scoped more narrowly for its specific purpose. The code is clean, well-documented, and shows no signs of malicious behavior.

## Vulnerability Details

### 1. LOW: Overly Broad Host Permissions
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `<all_urls>` host permission, which grants it access to all websites the user visits. While this is used for the legitimate purpose of monitoring navigation and checking URLs against the PhishWall service, it represents a broader permission set than strictly necessary. The extension primarily targets Japanese banking sites and could potentially use a more restricted permission model with optional host permissions.

**Evidence**:
```json
"host_permissions": ["<all_urls>", "http://127.0.0.1/"]
```

**Verdict**: This is a minor issue. The permission is used for the extension's core anti-phishing functionality (monitoring all navigations to detect phishing sites). The extension only sends URL information to a local service (127.0.0.1:8888), not to external servers. For an anti-phishing tool, this level of access is reasonable, though overly permissive from a least-privilege perspective.

## False Positives Analysis

Several patterns in the code might initially appear suspicious but are legitimate for this extension type:

1. **Base64 Encoding**: The extension base64-encodes data before sending to localhost. This is not obfuscation but rather data formatting for the local PhishWall client API.

2. **User-Agent Modification**: The extension modifies User-Agent strings for specific Japanese banking websites (adding "SBPW/1.0" or "SE04" markers). This is legitimate functionality required by Japanese banks to identify browsers with PhishWall protection enabled.

3. **Localhost Communication**: All network requests go to `http://127.0.0.1:8888`, which is the local PhishWall desktop client, not a remote server. This is the expected architecture for this security tool.

4. **URL Monitoring**: The extension monitors all page navigations via webRequest API and tabs API. This is the core functionality of an anti-phishing tool - it needs to check every URL the user visits.

5. **Storage of Site Lists**: The extension maintains lists of "known sites", "suspicious sites", and "white sites" in local storage. This is user preference data for customizing phishing protection.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://127.0.0.1:8888/pw/PluginInfo/browser-{version} | Get PhishWall client version | Extension version | None - localhost only |
| http://127.0.0.1:8888/pw/pwapa/browser-{version} | Get protected site list | Extension version | None - localhost only |
| http://127.0.0.1:8888/pw/auth/browser-{version} | Check URL safety | URL, tab ID, extension version (base64-encoded JSON) | None - localhost only |
| http://127.0.0.1:8888/pw/signal/browser-{version} | Send site classification signal | Site status, URL, tab ID, extension version | None - localhost only |

All endpoints are local (127.0.0.1) and communicate with the PhishWall desktop client. No external data exfiltration occurs.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: PhishWall is a legitimate security extension from a reputable Japanese corporation (Hitachi Systems) that provides anti-phishing protection for banking websites. The extension operates as designed and does not exhibit any malicious behavior. All network communication is with a local desktop application, not external servers. The only concern is the use of `<all_urls>` permission, which while overly broad, is reasonably justified for an anti-phishing monitoring tool. The extension is appropriately scoped for its purpose in the Japanese banking security ecosystem.

The extension's behavior is transparent: it monitors page navigations, checks URLs against a local security service, displays visual indicators of site safety, and allows users to manually classify sites. This is standard functionality for enterprise anti-phishing tools and poses minimal risk to users who have intentionally installed both the browser extension and desktop client.
