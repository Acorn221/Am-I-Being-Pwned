# Vulnerability Report: Equatio - Math made digital

## Extension Metadata
- **Extension ID**: hjngolefdpdnooamgdldlkjgmdcmcjnc
- **Extension Name**: Equatio - Math made digital
- **Version**: 67.0.0
- **User Count**: ~5,000,000
- **Developer**: Texthelp Ltd.
- **Manifest Version**: 3

## Executive Summary

Equatio is a legitimate educational extension developed by Texthelp Ltd. for creating and editing mathematical equations in Google Docs, Microsoft Office Online, and other web platforms. The extension provides math input through multiple modalities (equation editor, LaTeX, handwriting, speech, screenshots) and integrates deeply with Google Workspace applications.

**Overall Risk Assessment: CLEAN**

The extension requires extensive permissions and has significant access to web content, but all functionality serves its stated educational purpose. No malicious behavior, suspicious data exfiltration, ad injection, or security vulnerabilities were identified. The extension uses appropriate security measures including CSP, OAuth2 for authentication, and legitimate API endpoints.

## Permissions Analysis

### Declared Permissions
- `activeTab` - Access to current tab for math insertion
- `tabs` - Tab management for multi-platform support
- `alarms` - Background task scheduling
- `storage` - User settings and favorites persistence
- `identity` - Google account authentication
- `identity.email` - User email for licensing
- `gcm` - Google Cloud Messaging (deprecated, likely legacy)
- `scripting` - Dynamic content script injection

### Host Permissions
- `<all_urls>` - Required for universal math editor support across educational platforms

**Assessment**: Permissions are invasive but justified for an educational tool that must work across diverse platforms (Google Docs, Microsoft Office Online, Coursera, institutional LMS systems, etc.). The `<all_urls>` permission is necessary to inject the math toolbar into arbitrary web pages.

## Content Security Policy

```json
"extension_pages": "script-src 'self'; object-src 'self'"
"sandbox": "sandbox allow-scripts; script-src 'self' 'unsafe-eval'; worker-src blob:"
```

**Assessment**: Appropriate CSP with sandboxed pages for math rendering (MathJax, Desmos calculator). The `unsafe-eval` is limited to sandboxed contexts for mathematical expression evaluation.

## Code Analysis

### Background Scripts
**File**: `background.js` (962KB, 2996 lines)

**Key Findings**:
- Contains Google Firebase SDK (Apache 2.0 licensed) for user data sync
- Uses Google Cloud Workstations integration for institutional deployments
- No dynamic code execution outside sandboxed math rendering contexts
- No evidence of XHR/fetch hooking or network interception
- Clean message passing architecture via `chrome.runtime.sendMessage`

**Network Endpoints**: No hardcoded API endpoints found in background script. Uses Firebase SDK for backend communication.

### Content Scripts

**Primary Bundles**:
1. `chromeBundle.js` - Google Docs integration
2. `officeBundle.js` - Microsoft Office Online integration
3. `formBundle.js` - Google Forms integration
4. `htmlEditorApiInjector.js` - Generic HTML editor support
5. `equatioApi.js` - Third-party API for partner sites (Coursera, Orbit)
6. `docsMessagingApi.js` - Keyboard simulation for equation insertion

**Key Observations**:
- **No keylogging**: Keyboard event handlers are solely for simulating keypresses to insert equations into Google Docs (using zero-width characters and keyboard shortcuts like `ctrl+alt+y`)
- **No ad injection**: No DOM manipulation for advertising or coupon insertion
- **No SDK injection**: No evidence of market intelligence SDKs (Sensor Tower, Pathmatics, etc.)
- **Legitimate postMessage usage**: Inter-frame communication for toolbar visibility and equation data transfer

**Example from docsMessagingApi.js**:
```javascript
// Simulates keyboard shortcuts to trigger Google Docs equation insertion
const ShowAltTextDialog = () => {
    simulateKeyPress("ctrl+alt+y");
    simulateKeyPress("cmd+alt+y");
};
```

### Third-Party Integrations

**Partner Platforms** (from manifest content_scripts):
- Google Workspace: docs.google.com, forms, slides, sheets
- Microsoft: sharepoint.com, onedrive.live.com, officeapps.live.com
- Coursera: coursera.org, dev-coursera.org
- Texthelp Orbit: orbit.texthelp.com (companion note-taking platform)

**OAuth2 Configuration**:
```json
"client_id": "1012020947112-ej46u2phchai2guaj81fk9lb7pp2mm3q.apps.googleusercontent.com"
"scopes": ["email", "profile"]
```

**Assessment**: Minimal OAuth scopes for user identification and licensing verification. No access to Drive files, Gmail, or other sensitive data.

### Web Accessible Resources

The extension exposes resources to `<all_urls>`:
- `content/*` - Toolbar UI and math rendering components
- `mathjaxFrame/*` - MathJax equation rendering
- `desmos/*` - Graphing calculator integration
- `triangle-calculator/*` - Geometry tool
- `*.woff2` - Web fonts for math symbols

**Risk**: Standard practice for extensions that inject UI elements. Resources are properly scoped and sandboxed where necessary.

## Managed Enterprise Schema

**File**: `schema.json`

Provides IT administrators with 14+ policy controls to disable features:
- Prediction (autocomplete)
- Individual drawers (equation, LaTeX, graph, handwriting, speech)
- Screenshot reader
- Forms creator
- Math mentor
- Triangle calculator

**Assessment**: Excellent enterprise deployment support with granular feature controls for educational institutions.

## Vulnerability Assessment

### No Critical or High-Severity Issues Found

| Category | Finding | Verdict |
|----------|---------|---------|
| Remote Code Execution | None | ✓ CLEAN |
| XSS Vulnerabilities | None | ✓ CLEAN |
| Credential Theft | None | ✓ CLEAN |
| Keylogging | None (keyboard simulation only) | ✓ CLEAN |
| Ad Injection | None | ✓ CLEAN |
| Cookie Harvesting | None | ✓ CLEAN |
| Extension Enumeration | None | ✓ CLEAN |
| Residential Proxy | None | ✓ CLEAN |
| Market Intelligence SDKs | None | ✓ CLEAN |
| AI Conversation Scraping | None | ✓ CLEAN |

## False Positive Analysis

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `postMessage` | All content scripts | Legitimate inter-frame communication for toolbar-page data transfer |
| `insertAdjacentHTML` (grep false positive) | N/A - Not found in codebase | No dynamic HTML injection detected |
| Firebase SDK | background.js | Apache 2.0 licensed Google library for user data sync (favorites, settings) |
| OAuth2 tokens | manifest.json | Standard Google identity integration with minimal scopes |
| Keyboard event handlers | docsMessagingApi.js | Simulates keypresses to insert equations into Google Docs canvas |
| `unsafe-eval` CSP | Sandboxed pages only | Limited to math expression evaluation in isolated contexts |

## API Endpoints and Data Flows

### Identified Domains

| Domain | Purpose | Data Transmitted |
|--------|---------|------------------|
| equatio.texthelp.com | Extension homepage/settings | None identified |
| equatio-assets.texthelp.com | CDN for fonts/assets | Asset requests only |
| orbit.texthelp.com | Companion note-taking app | postMessage coordination |
| *.coursera.org | Partner integration | Equation data via API |
| firebase.google.com | User data sync | User favorites, settings, licensing |
| googleapis.com | OAuth/identity | Email, profile (OAuth scopes) |

### Data Flow Summary

1. **User Authentication**: Google OAuth2 → Email + profile for license verification
2. **Feature Usage**: Equations/favorites stored in Firebase (user's Google account)
3. **Asset Loading**: Fonts/resources from Texthelp CDN
4. **Partner Integration**: Math data sent to Coursera/Orbit when extension invoked on those platforms

**Privacy Assessment**: Data collection is minimal and transparent. User-generated math content is stored in the user's own Google account via Firebase. No evidence of third-party analytics beyond standard Google Analytics GA4 events.

## Overall Risk: CLEAN

**Justification**:

Equatio is a professionally developed educational extension by Texthelp Ltd., a reputable assistive technology company. While the extension requires extensive permissions (`<all_urls>`, identity, scripting), all functionality directly serves its legitimate purpose of enabling math input across diverse educational platforms.

**Key factors supporting CLEAN verdict**:

1. **Established vendor**: Texthelp Ltd. is a well-known educational software company with 25+ years in assistive technology
2. **Large user base**: 5 million users indicates institutional trust from schools/universities
3. **Transparent functionality**: All code behaviors match the extension's stated math editing purpose
4. **No malicious patterns**: Zero evidence of ad injection, data theft, keylogging, or SDK injection
5. **Security best practices**: Proper CSP, OAuth2 with minimal scopes, sandboxed evaluation contexts
6. **Enterprise support**: Managed policy schema for IT administrators demonstrates enterprise-grade development
7. **Clean codebase**: No obfuscation beyond standard webpack bundling; includes open-source license attributions

**Note on invasiveness**: While the extension is highly invasive (all_urls, tabs, scripting, identity), this is inherent to providing a universal math editor across Google Docs, Microsoft Office Online, Coursera, and institutional learning platforms. The permissions are used appropriately without evidence of misuse.

## Recommendations

For IT administrators deploying Equatio in educational environments:

1. **Use managed policies** (schema.json) to disable unnecessary features for your use case
2. **Review OAuth consent**: Users grant email/profile access - ensure privacy policies are communicated
3. **Monitor network traffic**: Extension communicates with texthelp.com and firebase.google.com - add to allowlists
4. **Verify licensing**: Premium features require valid licenses - expired licenses may trigger upgrade prompts

## Conclusion

**CLEAN** - Equatio is a legitimate, professionally developed educational extension with appropriate security measures. No vulnerabilities or malicious behavior identified. The extensive permissions are justified by the product's multi-platform math editing functionality and are used transparently for their stated purpose.

---

**Report Generated**: 2026-02-08
**Analysis Version**: v1.0
**Analyst**: Security Research Agent
