# Vulnerability Report: AI Google Form Builder

## Extension Metadata
- **Extension Name**: AI Google Form Builder
- **Extension ID**: kjglafdhoohlhlicoklkgjffiedneeem
- **User Count**: ~30,000
- **Version**: 1.6
- **Manifest Version**: 3

## Executive Summary

AI Google Form Builder is a legitimate extension that allows users to generate Google Forms from various input sources (text, images, PDFs, videos, web pages). The extension operates by collecting user input through the popup interface, uploading files to Alibaba Cloud OSS storage, and redirecting users to an external web application (livepolls.app) for form generation.

**Overall Risk Level: CLEAN**

The extension serves its intended purpose without engaging in malicious behavior. While it does transmit user data to external servers and performs file uploads to cloud storage, these activities are directly related to its core functionality of AI-powered form generation. The extension uses minimal permissions and does not engage in surveillance, data harvesting, or other suspicious activities.

## Manifest Analysis

### Permissions
- **contextMenus**: Used to add right-click menu options for generating forms from selected text or images
- **No host permissions**: Extension does not request access to any websites
- **No sensitive permissions**: No access to cookies, browsing history, downloads, or web requests

### Content Security Policy
- Default CSP for Manifest V3 applies
- No custom CSP defined

### Assessment
The permission model is minimal and appropriate for the extension's functionality. The use of only `contextMenus` permission is a positive security indicator.

## Background Script Analysis

**File**: `background.js` (2.2KB)

### Key Functionality

1. **Uninstall URL Tracking**
   - Sets uninstall URL to `livepolls.app` with tracking parameters
   - Distinguishes between Chrome and Edge browsers
   - Benign marketing practice

2. **Context Menu Creation**
   - Creates two context menu items:
     - "Generate Google form from Selected Content" (for text selection)
     - "GenerateGoogle form from image" (for images)

3. **Data Transmission Flow**
   ```javascript
   // Lines 43-56: Saves user selection to temporary storage
   fetch('https://www.imgkits.com/site/save', {
     method: 'POST',
     body: JSON.stringify({
       key: randomKey,
       value: JSON.stringify(selectionData),
       time: 100
     })
   })
   ```

4. **Redirect to Web App**
   - Opens new tab to `livepolls.app/gpt_form_builder/form-builder` with generated key
   - Key allows web app to retrieve the saved data

### Security Assessment
- Uses HTTPS for all network requests
- No XHR/fetch hooking detected
- No chrome.* API abuse
- No dynamic code execution
- No extension enumeration or killing behaviors
- Selected text/images are sent to external server (expected behavior for AI processing)

## Popup Script Analysis

**File**: `popup.js` (11KB)

### Key Functionality

1. **Cross-App Promotion**
   - Fetches app recommendations from `imgkits.com/site/recommend`
   - Creates dropdown with links to other extensions
   - Not malicious, standard cross-promotion

2. **File Upload to Alibaba Cloud OSS**
   ```javascript
   // Lines 124-155: Gets presigned URL and uploads file
   async function putObjectAli(file, fileName, app_name, prefix, bucketName) {
     let presignedUrlRes = await getPresignedUrl(up_key, bucketName, file.type);
     let result = await fetch(presignedUrlRes.url, { method: 'PUT', body: file });
     return { url: custom_domain + '/' + up_key, key: up_key };
   }
   ```

3. **File Type Validation**
   - Restricts uploads to: mp4, PDF, DOC, DOCX, TXT, PNG, JPG, JPEG
   - Size limits: 100MB for video, 40MB for other files
   - Good security practice

4. **Data Flow**
   - Text input → imgkits.com/site/save → livepolls.app
   - File upload → Alibaba OSS → livepolls.app
   - Web URL → imgkits.com/site/save → livepolls.app

### Security Assessment
- All uploads use presigned URLs (secure pattern)
- File type and size validation implemented
- No credential harvesting
- No DOM manipulation of visited pages
- No postMessage vulnerabilities
- No SDK injection or tracking pixels

## Third-Party Library Analysis

**File**: `ali_oss.js` (1.2MB)

- Official Alibaba Cloud OSS SDK v6.16.0
- Legitimate library for cloud storage operations
- No evidence of tampering or malicious modifications
- Contains standard eval/atob usage for SDK functionality (false positive)

## API Endpoints Summary

| Endpoint | Purpose | Data Transmitted | Assessment |
|----------|---------|------------------|------------|
| `livepolls.app/chrome_addons` | Uninstall tracking, cross-promotion | Browser type, source extension | Benign marketing |
| `imgkits.com/site/save` | Temporary data storage | User input (text/URL), random key | Required for functionality |
| `imgkits.com/site/recommend` | Cross-app recommendations | Extension identifier | Cross-promotion |
| `usa.imgkits.com/node-api/api/generate-ali-presigned-url` | Generate upload URL | File name, bucket, file type | Standard cloud upload |
| `californian.oss-us-west-1.aliyuncs.com` | File storage | User files (PDF, images, video) | Required for functionality |
| `livepolls.app/gpt_form_builder/form-builder` | Form generation UI | Retrieval key | Required for functionality |

## Data Flow Summary

1. **User Action**: Selects text, right-clicks image, or uses popup to input data/files
2. **Extension Processing**:
   - For text/images: Sends to imgkits.com temporary storage
   - For files: Uploads to Alibaba Cloud OSS
3. **Web App Redirect**: Opens livepolls.app with retrieval key
4. **AI Processing**: Web application retrieves data and generates Google Form

All data transmission is explicitly initiated by user action and serves the extension's stated purpose.

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `eval`, `Function()`, `atob`, `fromCharCode` | ali_oss.js | Official Alibaba OSS SDK - standard library operations |
| `fetch` to external domains | background.js, popup.js | Required for AI form generation service |
| Cross-app recommendations | popup.js | Standard cross-promotion, not malicious |

## Privacy Considerations

### Data Collection
- User-selected text and images (when using context menu)
- User-uploaded files (PDF, DOC, images, videos)
- Web URLs entered by users
- Browser type (Chrome vs Edge) for tracking

### Data Storage
- Files stored temporarily on Alibaba Cloud OSS (californian bucket, us-west-1 region)
- Text/URL data stored temporarily via imgkits.com/site/save (100 second TTL)
- Extension states in popup: "All data you upload are automatically deleted every day"

### Privacy Assessment
The extension is transparent about its data handling. All data transmission is:
1. User-initiated (no background surveillance)
2. Necessary for the stated functionality (AI form generation)
3. Sent over HTTPS
4. Claimed to be automatically deleted

## Vulnerability Details

### No Critical or High Severity Vulnerabilities Found

The extension does not exhibit any of the following concerning behaviors:
- Extension enumeration or killing
- XHR/fetch hooking or interception
- Residential proxy infrastructure
- Remote configuration or kill switches
- Market intelligence SDK integration
- AI conversation scraping
- Ad or coupon injection
- Credential harvesting
- Keylogging
- Unauthorized DOM manipulation
- Cookie or session theft

## Recommendations

While the extension is clean, users should be aware:
1. User-provided content is sent to third-party servers (livepolls.app, imgkits.com)
2. Files are uploaded to Alibaba Cloud storage
3. The extension relies on external web services for functionality
4. Cross-promotion of other extensions may be considered intrusive by some users

For maximum privacy, users should:
- Avoid uploading sensitive documents
- Review the privacy policy of livepolls.app
- Be aware that input data is processed by AI services

## Overall Risk Assessment

**Risk Level: CLEAN**

**Justification:**
- Minimal permission model (only contextMenus)
- No content scripts or host permissions
- No surveillance or data harvesting beyond stated functionality
- Transparent data handling (user-initiated only)
- No obfuscation or suspicious patterns
- Uses legitimate cloud infrastructure (Alibaba OSS)
- Standard cross-promotion practices
- All network requests directly support the AI form generation feature

The extension is invasive in the sense that it transmits user data to external servers, but this is clearly part of its intended functionality (AI-powered form generation). There is no evidence of malicious behavior, hidden tracking, or data exfiltration beyond what is necessary for the extension to work.

**Verdict: Safe for use** - This extension operates as advertised and does not pose a security threat to users.
