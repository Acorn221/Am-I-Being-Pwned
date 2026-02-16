# Vulnerability Report: Mimecast Incydr

## Metadata
- **Extension ID**: hamlakigaoomkpddnpnbjkhdfppbnjjh
- **Extension Name**: Mimecast Incydr
- **Version**: 1.47.0
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Mimecast Incydr (formerly Code42 Incydr) is a legitimate enterprise Data Loss Prevention (DLP) solution designed for insider risk management and data exfiltration detection. The extension monitors file uploads, clipboard operations, downloads, and user activity across all websites to detect and prevent unauthorized data transfer. This is an enterprise security tool that implements highly invasive monitoring and control mechanisms that are expected and disclosed as part of its core functionality.

While the extension's capabilities would be considered severe privacy violations in a consumer context, they are appropriate and necessary for its stated purpose as an enterprise DLP solution deployed by organizations to protect sensitive data. The extension operates with full transparency to IT administrators and is installed via enterprise policies rather than individual user choice.

## Vulnerability Details

### 1. EXPECTED: Comprehensive Data Exfiltration Monitoring
**Severity**: N/A (Expected Behavior)
**Files**: background.js, contentscript.js, mainworld.js
**CWE**: N/A
**Description**: The extension implements extensive monitoring of potential data exfiltration vectors including file uploads (FileReader, Blob, FormData, File API), clipboard copy/paste operations, downloads, and web requests. This monitoring occurs on all websites via `<all_urls>` permissions and content scripts running at `document_start`.

**Evidence**:
- Content script injected into all frames on all websites: `"matches": ["http://*/*", "https://*/*", "*://*/*", "<all_urls>"]`
- Main-world script injection for FileReader, Blob API interception: `mainworld.js` hooks Blob.text, FileReader.readAsArrayBuffer, etc.
- Clipboard monitoring via offscreen document: clipboard read/write tracking in `background.js`
- Native messaging permission for communication with local agent: `"nativeMessaging"`

**Verdict**: Expected and disclosed behavior for an enterprise DLP solution. The extension's stated purpose is data loss prevention, which requires monitoring file access and clipboard operations.

### 2. EXPECTED: CSP Header Manipulation
**Severity**: N/A (Expected Behavior)
**Files**: rules/csp_rule.json, background.js
**CWE**: N/A
**Description**: The extension removes Content-Security-Policy headers on specific domains (chatgpt.com, idrive.com) using declarativeNetRequest and injects custom CSP meta tags. This allows the extension to maintain connectivity to localhost (127.0.0.1) for communication with the local agent even on sites with restrictive CSP.

**Evidence**:
```json
{
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [{"header": "content-security-policy", "operation": "remove"}]
  },
  "condition": {
    "resourceTypes": ["main_frame", "sub_frame"],
    "requestDomains": ["chatgpt.com", "idrive.com"]
  }
}
```

Code in background.js: `this.cspRuleDomains=["chatgpt.com","idrive.com","itsy.dev.code42.com"]`

**Verdict**: Expected behavior. Enterprise DLP requires maintaining connectivity to local enforcement agents. The CSP modification is limited to specific domains and documented in the code.

### 3. EXPECTED: Clipboard Access and Control
**Severity**: N/A (Expected Behavior)
**Files**: background.js, contentscript.js, offscreen.js
**CWE**: N/A
**Description**: The extension monitors all clipboard copy and paste events, reads clipboard contents via offscreen document (MV3 approach), and can block paste operations based on policy. It tracks paste source (trusted vs untrusted domains) and implements granular controls including blocking paste to password fields.

**Evidence**:
- Clipboard read permission: `"clipboardRead"`
- Offscreen document for clipboard access: `"offscreen"` permission
- Copy/paste event handlers in `handleCopyEvent`, `handlePasteEvent`
- Policy enforcement: `BlockType.Confirm`, `BlockType.Block`, `BlockType.None`

**Verdict**: Expected DLP functionality. Clipboard monitoring is a standard feature of insider risk management tools to detect sensitive data transfers.

### 4. EXPECTED: Block-by-Source Agent Integration
**Severity**: N/A (Expected Behavior)
**Files**: mainworld.js (BlockBySourceClient class)
**CWE**: N/A
**Description**: The extension communicates with a local agent via synchronous XMLHttpRequest to localhost (127.0.0.1) to determine whether file uploads should be blocked. This "block-by-source" mechanism allows real-time policy enforcement based on file content analysis performed by the local agent.

**Evidence**:
```javascript
doRequest=(e,t)=>{
  const r={type:"BlockBySourceRequestV1",files:t.map(this.toFile)};
  l.open("POST",e,!1); // synchronous POST to localhost
  l.send(JSON.stringify(r));
  // ... parse response for Block/Confirm/None
}
```

**Verdict**: Expected architecture for enterprise DLP. Communication with local agents for content inspection is standard practice and documented in Mimecast Incydr's deployment guides.

### 5. EXPECTED: Native Messaging for Agent Communication
**Severity**: N/A (Expected Behavior)
**Files**: manifest.json, background.js
**CWE**: N/A
**Description**: The extension uses native messaging (`"nativeMessaging"` permission) to communicate with the locally installed Mimecast Incydr agent (formerly Code42). This enables coordination between the browser extension and the OS-level monitoring agent.

**Evidence**:
- Native messaging permission in manifest.json
- Evidence in code referencing "com.code42.incydr.extension"

**Verdict**: Expected. Enterprise DLP solutions typically use native messaging to coordinate between browser and OS-level enforcement agents.

### 6. LOW: Broad Permission Scope
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests very broad permissions including `<all_urls>`, `tabs`, `webRequest`, `downloads`, `scripting`, `identity.email`, and `clipboardRead`. While justified by its DLP purpose, this represents significant attack surface if the extension were compromised.

**Evidence**:
- Host permissions: `"<all_urls>", "*://*/*"`
- Wide array of sensitive permissions
- Content scripts on all sites at document_start

**Verdict**: Permissions are justified for the stated DLP purpose, but represent elevated risk if vulnerabilities exist in the extension code or if credentials for the Mimecast backend are compromised.

## False Positives Analysis

None. All monitoring and control behaviors are expected and necessary for the extension's stated purpose as an enterprise Data Loss Prevention solution. Behaviors that would be flagged as malicious in consumer extensions (file upload blocking, clipboard monitoring, comprehensive page access) are core features of DLP tools and are deployed with organizational consent.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| 127.0.0.1:* | Local agent communication | File metadata, upload events | Low (localhost only) |
| Mimecast Incydr backend | DLP event reporting | User activity, file transfers, clipboard data | Expected (encrypted, disclosed) |

Note: The actual backend endpoints are not visible in the static code as they are likely configured by the local agent. The extension communicates primarily via native messaging rather than direct HTTP requests.

## Attack Surface Considerations

While not vulnerabilities in the traditional sense, the following represent potential security considerations:

1. **Extension Compromise Risk**: If an attacker gains control of the extension (via XSS in the extension context or supply chain compromise), they would have access to all monitored data including clipboard contents, file uploads, and browsing activity.

2. **Local Agent Trust**: The extension trusts the local agent running on 127.0.0.1. If the agent is compromised, malicious policies could be enforced.

3. **CSP Weakening**: Removing CSP headers on specific domains reduces those sites' built-in protections, though this is limited to documented domains.

4. **Synchronous XHR**: The use of synchronous XMLHttpRequest for block-by-source checks can cause page freezes if the local agent is unresponsive.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: Mimecast Incydr is a legitimate, widely-deployed enterprise DLP solution with 300,000+ users. All invasive monitoring behaviors (file upload tracking, clipboard monitoring, CSP modification) are expected and disclosed features of insider risk management tools. The extension is properly scoped to enterprise deployments via policy-based installation rather than individual user opt-in.

The MEDIUM risk rating reflects the inherent security considerations of any DLP tool with such broad access, rather than vulnerabilities in implementation. Organizations deploying this extension should:
- Ensure proper endpoint protection to prevent extension compromise
- Monitor the native messaging host for integrity
- Review the excluded domains list for business justification
- Maintain updated versions to receive security patches
- Educate users that their activity is monitored per corporate policy

For its intended use case (enterprise insider risk management), this extension operates appropriately. For consumer users accidentally installing this extension, it would represent severe privacy violations, but the extension is clearly labeled and targeted at enterprise deployments.
