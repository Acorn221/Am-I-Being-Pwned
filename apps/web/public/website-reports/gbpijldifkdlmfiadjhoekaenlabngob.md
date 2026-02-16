# Vulnerability Report: SYSTRAN Translator

## Metadata
- **Extension ID**: gbpijldifkdlmfiadjhoekaenlabngob
- **Extension Name**: SYSTRAN Translator
- **Version**: 2.7.1
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

SYSTRAN Translator is a legitimate translation extension developed by SYSTRAN, a professional translation services company. The extension provides webpage translation functionality and integrates with SYSTRAN's translation API services. The extension uses webpack bundling (not obfuscation) and follows standard Manifest V3 practices.

After thorough analysis including static analysis with ext-analyzer and manual code review, no security vulnerabilities or privacy concerns were identified. The extension operates as expected for a translation tool, communicating only with SYSTRAN's translation API endpoints configured by the user. All code patterns detected (such as Function constructor usage) are part of legitimate polyfills and library code, not malicious functionality.

## Vulnerability Details

### No Vulnerabilities Found

The analysis found no exploitable vulnerabilities or privacy violations. The extension:

1. **Does not collect or exfiltrate user data** - No data collection mechanisms beyond what's necessary for translation functionality
2. **Does not use eval or dynamic code execution maliciously** - The Function constructor usage detected is part of standard polyfills (function-bind, get-intrinsic libraries)
3. **Does not inject ads or modify content maliciously** - Only modifies pages to show translations when requested by user
4. **Uses standard Chrome APIs appropriately** - Permissions are justified for translation functionality
5. **Communicates only with configured translation endpoints** - No hardcoded third-party domains for data exfiltration

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated" because it uses webpack bundling. This is a **false positive** - webpack is a standard JavaScript module bundler used by millions of legitimate extensions. The code is minified but not obfuscated to hide malicious intent.

The analyzer found benign flows involving:
- `chrome.storage` API - Used to store user preferences and translation settings
- `chrome.tabs` API - Used to inject translation widget into pages
- `chrome.runtime.sendMessage` - Used for communication between content scripts and background page
- `Function()` constructor - Part of standard polyfills for older browser compatibility

All of these patterns are expected and legitimate for a translation extension.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| User-configured SYSTRAN API | Translation requests | Text to be translated, source/target languages | Low - User controls endpoint |

The extension uses a configurable API endpoint model where enterprise users can specify their own SYSTRAN translation server. The schema.json shows support for:
- **spnsOAuthPkce** - SYSTRAN Pure Neural Server with OAuth login
- **spnsApikey** - SYSTRAN Server with API Key
- **spnsPro** - SYSTRAN Translate PRO

No hardcoded external endpoints were found that would allow unauthorized data collection.

## Permissions Analysis

The extension requests the following permissions, all justified:

- **scripting** - Required to inject translation widget into webpages
- **contextMenus** - Provides right-click "Translate selection with SYSTRAN" option
- **tabs** - Required to identify which tab to translate
- **activeTab** - Required to access current page content for translation
- **storage** - Stores user preferences and translation settings
- **notifications** - Shows translation status notifications
- **alarms** - Potentially for periodic sync or cleanup tasks

**Content scripts on `<all_urls>`** - Necessary for translating any webpage the user visits. This is standard for translation extensions.

## Code Quality Observations

1. **Professional development** - Uses React, Material-UI, modern JavaScript tooling
2. **Managed schema support** - Supports enterprise deployment via Chrome's managed storage
3. **Multi-browser support** - Detects and supports both Chrome and Firefox APIs
4. **Proper error handling** - Includes try-catch blocks and error callbacks
5. **No minified variable name obfuscation** - Variables like `translatePageMessageValue`, `REQUEST_TRANSLATE_PAGE` are readable

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

SYSTRAN Translator is a professionally developed, legitimate translation extension with no security vulnerabilities or privacy concerns identified. The extension:

1. Is published by SYSTRAN, a well-established translation technology company
2. Has 300,000+ users with a 3.7 star rating, indicating stable, expected behavior
3. Uses Manifest V3 with appropriate permissions for its functionality
4. Contains no data exfiltration mechanisms, malware, or hidden functionality
5. All API communications are user-controlled through configurable endpoints
6. Static analysis findings were benign (webpack bundling, standard polyfills)
7. No hardcoded third-party tracking or analytics endpoints

The extension operates transparently as a translation tool and poses no security or privacy risk to users. The "obfuscated" flag from static analysis is a false positive due to webpack bundling, which is industry-standard practice.

**Recommendation**: Safe for use. No remediation needed.
