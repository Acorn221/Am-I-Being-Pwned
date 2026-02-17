# Vulnerability Report: SAML-tracer

## Metadata
- **Extension ID**: mpdajninpobndbfcldcmbpnnbhibjmch
- **Extension Name**: SAML-tracer
- **Version**: 1.9.2
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

SAML-tracer is a legitimate developer tool designed for debugging SAML (Security Assertion Markup Language) and WS-Federation authentication flows. The extension intercepts HTTP requests containing SAML messages and displays them in a user-friendly interface for analysis.

After comprehensive analysis of the codebase, including static analysis and manual code review, no security or privacy concerns were identified. The extension operates entirely locally, storing all intercepted data in memory within the extension's popup window without any external transmission. The broad permissions (`webRequest` and `<all_urls>`) are appropriate for its stated purpose as a network debugging tool.

## Vulnerability Details

No vulnerabilities were identified.

## False Positives Analysis

**Broad Permissions (`webRequest` + `<all_urls>`)**: While these permissions allow the extension to intercept all HTTP traffic, this is the core functionality of a SAML debugging tool. The extension:
- Only activates when the user clicks the extension icon and opens the tracer window
- Stores all intercepted data locally in the popup window's memory
- Provides import/export functionality for saving traces locally as JSON files
- Does not transmit any data to external servers
- Is open source (GitHub: SimpleSAMLphp/SAML-tracer)

**Request/Response Interception**: The extension intercepts HTTP headers and request bodies to parse SAML tokens. This is expected behavior for a SAML debugging tool and matches its description: "A debugger for viewing SAML messages."

**Base64 Decoding and Decompression**: The extension decodes and decompresses SAML messages (which are typically base64-encoded and deflated). This is legitimate functionality for displaying SAML tokens in readable XML format.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| N/A | No external endpoints | None | None |

The extension does not contact any external servers. All functionality is local:
- HTTP interception via `webRequest` API
- Local storage in popup window memory
- Import/export to local filesystem only

## Code Analysis

### Key Files Reviewed

**bootstrap.js**: Simple background service worker that opens the tracer popup window when the extension icon is clicked.

**src/SAMLTrace.js**: Core functionality implementing:
- HTTP request/response interception via `webRequest` API
- SAML message parsing (base64 decoding, deflate decompression, XML parsing)
- WS-Federation protocol support
- In-memory storage of intercepted requests
- UI rendering for displaying HTTP traffic and parsed SAML tokens

**src/SAMLTraceIO.js**: Import/export functionality allowing users to:
- Export traced sessions to local JSON files
- Import previously saved sessions
- Apply privacy filters (hash/obfuscate cookies and POST data) during export

### Security Controls

1. **Strong CSP**: `default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; frame-src data:;` prevents XSS attacks
2. **No external network calls**: All code operates locally
3. **Privacy-conscious export**: Offers options to hash or obfuscate sensitive data (cookies, POST parameters) when exporting traces
4. **Open source**: Code is publicly auditable on GitHub
5. **Reputable authors**: Developed by SimpleSAMLphp project contributors

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

SAML-tracer is a legitimate, well-maintained developer tool that performs exactly as described. While it has broad permissions to intercept all HTTP traffic, this is necessary and appropriate for its functionality as a SAML debugging tool. The extension:

1. Only operates when explicitly activated by the user
2. Stores all data locally without any external transmission
3. Implements strong security controls (CSP)
4. Is open source and maintained by reputable developers
5. Provides privacy-conscious export options
6. Has no indicators of malicious behavior

The extension serves a legitimate purpose for developers and security professionals working with SAML authentication flows and poses no security or privacy risks to users who understand its purpose.
