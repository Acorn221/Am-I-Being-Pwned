# Vulnerability Report: FEPWeb CMS Digital Signature Extension

## Metadata
- **Extension ID**: bcellnicpceplkigjnldelfglfmomhon
- **Extension Name**: FEPWeb CMS Digital Signature Extension
- **Version**: 1.3.7
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

FEPWeb CMS Digital Signature Extension is a legitimate Brazilian digital signature tool that enables users to sign documents using digital certificates stored on their local machine or hardware tokens (e.g., A3 certificates). The extension communicates with a native host application (`br.com.fepweb.digitalsignature.extension.host`) to access local certificate stores and perform cryptographic signing operations.

While the extension serves a legitimate purpose in the Brazilian e-government and corporate document signing ecosystem, it contains a medium-severity vulnerability: the content script accepts `postMessage` events from web pages without validating the origin. This could allow malicious websites to send commands to the extension and potentially trigger certificate operations or gather information about installed certificates.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: content-script.js:80, firefox/content-script.js:10
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The content script registers a `window.addEventListener("message")` handler that processes messages from web pages without validating `event.origin`. While the handler checks that `event.data.from == "PAGE"`, it does not verify which origin sent the message. This means any website can send messages to the extension and trigger operations.

**Evidence**:
```javascript
// content-script.js, line 80
window.addEventListener("message", function(event) {
    if (event.data.from && event.data.correlationID && (event.data.from == "PAGE")) {
        console.log("Dados recebidos operacao " + event.data.correlationID + " chave : " +
                    (event.data.requestData.id_operation ? event.data.requestData.id_operation : 'sem chave'));

        if (event.data.requestData.id_operation) {
            // Forwards to background script via port
            if (port == null) {
                port = chrome.runtime.connect({name: "fepweb-sign-interchange"});
                // ...
            }
            port.postMessage(event.data.requestData);
        } else {
            // Forwards to background script via sendMessage
            chrome.runtime.sendMessage(event.data.requestData, function(response) {
                // Posts response back to web page
                window.postMessage({ from: "CONTENT_SCRIPT", correlationID: event.data.correlationID,
                                   responseData: response }, "*");
            });
        }
    }
}, false);
```

The handler accepts messages with `from: "PAGE"` from any origin and forwards the `requestData` to the background script, which then communicates with the native host application. Operations supported include:
- `listcerts` - List installed digital certificates
- `sign` - Sign content with a certificate
- `getCertBySerial` - Retrieve certificate by serial number
- `getCertByCPF` - Retrieve certificate by CPF (Brazilian tax ID)
- `version` - Get native host version

**Verdict**: While the native host application likely has its own security controls and user consent mechanisms (e.g., PIN prompts for certificate access), the lack of origin validation creates an unnecessary attack surface. A malicious website could:
1. Enumerate installed certificates by calling `listcerts`
2. Attempt to trigger signing operations (though these likely require user interaction at the OS level)
3. Fingerprint users based on certificate presence

The severity is MEDIUM rather than HIGH because:
- The extension is designed for a specific use case (Brazilian document signing platforms)
- The native host application likely requires user authentication (PIN, password)
- The real-world attack surface is limited to users who have this extension installed AND are visiting a malicious site
- There is no evidence of credential theft or automatic data exfiltration

However, this is still a real vulnerability that violates the principle of least privilege.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated," but upon inspection, this appears to be a false positive. The code includes:
- Standard jQuery library (minified, not obfuscated)
- jQuery SimpleModal plugin (minified)
- Clear, readable application code in content-script.js, service_worker.js, and popup.js

The "obfuscated" flag was likely triggered by the minified jQuery libraries, which use variable name compression and code mangling for size reduction - a standard practice, not evidence of malicious intent.

The extension also includes a `test/` directory with test code that demonstrates the postMessage API for integration testing purposes. This is not malicious, though it does illustrate how the vulnerable API can be invoked.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Host: `br.com.fepweb.digitalsignature.extension.host` | Local certificate access and signing | Certificate operations, content to sign, certificate identifiers | LOW - Local only, requires user consent |
| `https://cloud-app.fepweb.com.br/chrome-extension/FEPWebDigitalSignatureHost.pkg` | Native host installer (Mac) | None (download only) | CLEAN - Legitimate installer |
| `https://cloud-app.fepweb.com.br/chrome-extension/FEPWebHostExtensionSetup.msi` | Native host installer (Windows) | None (download only) | CLEAN - Legitimate installer |

The extension does not make any HTTP/HTTPS network requests itself. All communication is:
1. Web page → Content script (via postMessage)
2. Content script → Background script (via chrome.runtime)
3. Background script → Native host application (via chrome.runtime.connectNative)
4. Native host → Background script → Content script → Web page (responses)

The native host application handles all actual certificate operations at the OS level.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise/government tool for Brazilian digital signature workflows with a single exploitable vulnerability. The postMessage origin validation issue is a real security flaw that could allow certificate enumeration and potentially unwanted signing attempts from malicious websites. However, the practical exploitability is limited by:

1. **User base**: Only ~200,000 users, primarily in Brazil using specific document signing platforms
2. **Native host protection**: The native application likely enforces its own authentication (PIN, password, biometric)
3. **No automatic exfiltration**: The extension does not send data to remote servers
4. **Legitimate purpose**: The extension performs its stated function without deception

**Recommendation**: The developers should add origin validation to the postMessage handler, restricting it to known trusted domains (e.g., FEPWeb CMS domains). Example fix:

```javascript
const ALLOWED_ORIGINS = [
    'https://fepweb.com.br',
    'https://cloud-app.fepweb.com.br',
    // Add other legitimate origins
];

window.addEventListener("message", function(event) {
    // Validate origin
    if (!ALLOWED_ORIGINS.some(origin => event.origin.startsWith(origin))) {
        console.warn('Rejected message from untrusted origin:', event.origin);
        return;
    }

    if (event.data.from && event.data.correlationID && (event.data.from == "PAGE")) {
        // ... existing logic
    }
}, false);
```

This would maintain the extension's functionality for legitimate use cases while preventing abuse from malicious websites.
