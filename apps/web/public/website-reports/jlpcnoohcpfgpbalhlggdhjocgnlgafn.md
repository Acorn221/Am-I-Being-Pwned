# Vulnerability Report: 有道灵动翻译

## Metadata
- **Extension ID**: jlpcnoohcpfgpbalhlggdhjocgnlgafn
- **Extension Name**: 有道灵动翻译 (Youdao Smart Translation)
- **Version**: 1.0.16
- **Users**: ~90,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Youdao Smart Translation is a legitimate translation extension from Youdao (NetEase) that provides webpage translation, image OCR, and input box translation features. The extension uses Youdao's AI services (luna-ai.youdao.com) and includes WASM-based ONNX machine learning models for local text processing capabilities including tokenization and NLP tasks.

The extension has one medium-severity vulnerability related to postMessage handlers that do not validate message origins, but the overall risk is low given the extension's legitimate purpose and the limited exploitability of this issue. The extension properly communicates with its own backend services using encrypted API communication.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: assets/workload-b73c1978.js (line 33749), assets/offscreen-94fa1ab0.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension's sandboxed page and offscreen document implement `window.addEventListener("message")` handlers without validating the origin of incoming messages. This could potentially allow malicious web pages to send crafted messages to these contexts.

**Evidence**:
```javascript
// workload-b73c1978.js:33749
window.addEventListener("message", function(event) {
  console.log("message received in sandbox", event);
  const message = event.data;
  try {
    switch (message.type) {
      case "ocr":
        handOcr(message, event);
        break;
      case "asr":
        handleAsr(message, event);
    }
  } catch (e) {
    event.ports[0].postMessage({
      error: e
    });
  }
});
```

The handler processes messages of type "ocr" (OCR processing) and "asr" (speech recognition) without checking `event.origin`.

**Verdict**:
This is a legitimate security concern but has limited exploitability because:
1. The sandboxed page runs in a restricted CSP context (`sandbox allow-scripts; script-src 'self' 'unsafe-eval'`)
2. The handlers are designed for internal extension communication via MessageChannel
3. The WASM models perform tokenization/NLP tasks, not arbitrary code execution
4. The extension uses proper content security policies to mitigate risks

## False Positives Analysis

**WASM Modules**: The extension contains 5 WASM files totaling ~59MB. These are legitimate ONNX Runtime WASM binaries for machine learning inference, specifically for BERT tokenization. The strings analysis confirms these are standard ML model files (HfBertTokenizer, SentencepieceTokenizer, WordpieceTokenizer).

**Obfuscation**: While ext-analyzer flagged the code as "obfuscated", this is standard webpack/build tool bundling, not malicious obfuscation. The deobfuscated code is readable and shows normal extension patterns.

**Crypto Usage**: The extension uses AES-128-CBC encryption for API communication with its backend (`decodeData` function). This is legitimate protection for API responses, not credential theft. The encryption keys are stored as prefixed strings ("secret:/key/...") which is an internal key management approach.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| luna-ai.youdao.com/extension/trans/secret | Fetch secret key for API signing | Extension UUID, config | Low - Standard API auth |
| luna-ai.youdao.com/extension/trans/yd | Translation API (Youdao standard) | Text to translate, target language, domain | Low - Disclosed translation feature |
| luna-ai.youdao.com/extension/trans/llm | Translation API (LLM-powered) | Text to translate | Low - Disclosed AI translation |

All API calls:
- Use proper HTTPS endpoints
- Include signature-based authentication (genParamV3)
- Return encrypted responses that are decrypted locally
- Match the extension's stated purpose (translation services)

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate translation extension from a reputable Chinese tech company (NetEase/Youdao). The postMessage vulnerability is a coding oversight rather than malicious behavior. The extension:

1. **Legitimate Purpose**: Provides real webpage translation, OCR, and input translation features
2. **Proper Permissions**: Uses permissions appropriately for its functionality (tabs, scripting for page translation; offscreen for ML processing)
3. **Disclosed Data Collection**: Sends user text to Youdao translation APIs, which is the core feature
4. **Local ML Processing**: Uses WASM-based ONNX models for tokenization/preprocessing locally before API calls
5. **Secure Communication**: Encrypts API responses and uses signed requests
6. **No Hidden Malware**: No credential harvesting, hidden proxies, or data exfiltration beyond translation services

The postMessage vulnerability should be fixed by the developer to validate origins, but does not represent a critical security threat to users given the sandboxed execution context and the benign nature of the message handlers.
