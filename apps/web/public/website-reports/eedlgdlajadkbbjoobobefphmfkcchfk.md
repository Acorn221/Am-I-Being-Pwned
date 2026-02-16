# Vulnerability Report: Ecosia - The search engine that plants trees

## Metadata
- **Extension ID**: eedlgdlajadkbbjoobobefphmfkcchfk
- **Extension Name**: Ecosia - The search engine that plants trees
- **Version**: 7.5.0
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Ecosia is a legitimate and well-known search engine extension that sets Ecosia as the user's default search provider. The extension has minimal permissions (cookies on ecosia.org domain only) and implements standard functionality for a search engine extension: setting the default search provider, opening a first-run page on installation, handling browser action clicks, and setting an uninstall feedback URL. The code is clean, minimal, and does not exhibit any malicious behavior.

All network communication is limited to ecosia.org domains (www.ecosia.org and ac.ecosia.org for search suggestions), which is entirely expected and disclosed in the extension's purpose. The extension uses externally_connectable to allow ecosia.org pages to communicate with it, which is a standard pattern for search engine extensions.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

**externally_connectable Configuration**: The extension has `externally_connectable` set to `*://*.ecosia.org/*`, which allows Ecosia web pages to communicate with the extension. This is flagged by the static analyzer as MEDIUM attack surface, but it is:
- Limited to the Ecosia domain only (not wildcard domains)
- Standard behavior for search engine extensions that need to coordinate between web pages and extension
- Protected by the message handler that validates the source URL before taking action

**Cookie Usage**: The extension sets a cookie (ECEA) with the extension version on the .ecosia.org domain. This is used to track extension installation and version for legitimate analytics purposes, not for data exfiltration.

**postMessage in funnel.js**: The content script on ecosia.org pages uses `window.postMessage` to send extension version information. While this posts to "*" (any origin), it only sends benign metadata (addon type and version) that is already publicly available through the Chrome extension API.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.ecosia.org | Search engine, first-run page, uninstall feedback | URL parameters: addon type, version, search terms, feedback flag | CLEAN - Expected functionality |
| ac.ecosia.org | Search suggestions (autocomplete) | Search query, locale | CLEAN - Standard search suggestion service |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This is a legitimate, professionally developed search engine extension from a reputable company. The extension:
- Uses minimal permissions appropriate to its stated purpose
- Only communicates with its own domain (ecosia.org)
- Implements standard search engine extension patterns (default search provider override, first-run page, icon click handler)
- Has clean, readable code with no obfuscation
- Does not collect, exfiltrate, or misuse user data beyond what is necessary for search functionality
- Has 1M+ users and a 4.7 rating, consistent with a legitimate extension
- Is Manifest V3 compliant

The extension sets cookies on its own domain for installation tracking, which is disclosed behavior and does not constitute a privacy violation. All functionality aligns with the extension's stated purpose of providing Ecosia search with tree-planting features.
