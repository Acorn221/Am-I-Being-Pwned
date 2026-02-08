# Security Analysis Report: Excel Editor Online

## Extension Metadata
- **Extension Name**: Excel Editor Online
- **Extension ID**: ahibepkhmaepihjpbddebpdhfoecghfd
- **Version**: 3.2.0
- **User Count**: ~20,000
- **Homepage**: https://www.qwerpdf.com/
- **Author**: qwerpdf.com

## Executive Summary

Excel Editor Online is a legitimate document conversion extension that provides file conversion services between PDF and Office formats (Word, Excel, PowerPoint) as well as image formats. The extension functions as a client-side interface to the qwerpdf.com web service, uploading user files to remote servers for conversion processing.

**Overall Risk Assessment: LOW**

The extension demonstrates a focused, benign functionality with minimal permissions and no significant security vulnerabilities or malicious behavior. While it does upload user files to third-party servers (which is core to its stated functionality), it does not engage in data harvesting, tracking, or other privacy-invasive behaviors beyond what is necessary for its document conversion service.

## Manifest Analysis

### Permissions
```json
"permissions": [
    "notifications",
    "storage"
]
```

**Assessment**: Minimal and appropriate permissions for the stated functionality.
- `notifications` - Used to notify users of conversion status
- `storage` - Used to store conversion history and user login state

### Host Permissions
```json
"host_permissions": [
    "https://*.qwerpdf.com/"
]
```

**Assessment**: Appropriately scoped to the extension's domain only.

### Content Security Policy
No custom CSP defined - uses Manifest V3 defaults.

### Content Scripts
Two content scripts injected only on qwerpdf.com domains:
1. `content_script.js` - Message relay (document_start)
2. `content_script_installed.js` - Version detection flag (document_end)

**Assessment**: Content scripts are minimal, non-invasive, and only active on the extension's own domain.

## Background Script Analysis

**File**: `js/background.js` (258 lines)

### Key Functionality

1. **File Upload Handling**
   - Receives files via `chrome.runtime.onMessage` with type `ADD_FILE`
   - Converts DataURL to Blob/File objects
   - Uploads to either `PDF_UPLOAD_API` or `OFFICE_UPLOAD_API` depending on conversion type
   - No evidence of file content inspection or exfiltration beyond stated functionality

2. **API Endpoints**
   ```javascript
   const PDF_UPLOAD_API = 'https://p1.qwerpdf.com/api/upload1';
   const OFFICE_UPLOAD_API = 'https://up1.qwerpdf.com/extupload';
   const QUEUE_API = 'https://qwerpdf.com/queue/v2';
   const TASK_PROCESS_API = "https://qwerpdf.com/user/taskProcess";
   ```

3. **Task Management**
   - Creates conversion tasks via `taskCreate()` function
   - Polls task status via `TASK_PROCESS_API` every 1 second
   - Stores converted files in chrome.storage.local with 30-minute expiration

4. **Post-Install Behavior**
   - Opens install page on first install: `https://qwerpdf.com/ext.html?utm_source=E-EEOC&utm_medium=EXT`
   - Sets uninstall URL: `https://qwerpdf.com/uninstall.html?utm_source=E-EEOC&utm_medium=EXT`

**Assessment**: Standard web service integration pattern. No malicious behavior detected.

## Content Script Analysis

### content_script.js (21 lines)
```javascript
window.addEventListener('message', function (e) {
    if (e.origin != 'https://qwerpdf.com' && e.origin != 'https://www.qwerpdf.com') {
        return false;
    }
    chrome.runtime.sendMessage(e.data, (res) => {
        // Message relay to background
    });
});
```

**Assessment**: Simple message relay with proper origin validation. No security concerns.

### content_script_installed.js (9 lines)
```javascript
function addExtFlagToSite(){
    let div = document.createElement('div');
    div.setAttribute('id', 'qwerpdf-extension-installed');
    div.setAttribute('version',chrome.runtime.getManifest().version);
    document.body.appendChild(div);
}
```

**Assessment**: Benign version detection mechanism for the website to detect extension presence.

## Vulnerability Assessment

### Critical Vulnerabilities
**None identified.**

### High Severity Issues
**None identified.**

### Medium Severity Issues
**None identified.**

### Low Severity Issues

#### 1. Third-Party File Upload
- **Severity**: LOW
- **Location**: `background.js` lines 38-42, 93-105
- **Description**: User files are uploaded to third-party servers (qwerpdf.com) for processing. While this is the core functionality, users should be aware their files leave the local machine.
- **Code**:
  ```javascript
  fetch(f == 'pdf' ? PDF_UPLOAD_API : OFFICE_UPLOAD_API, {
      method: 'POST',
      body: formData
  })
  ```
- **Verdict**: NOT A VULNERABILITY - This is the intended and clearly stated functionality of a document conversion service.

#### 2. File Retention Tracking
- **Severity**: LOW
- **Location**: `background.js` line 154
- **Description**: Files stored with 30-minute expiration timestamp
- **Code**:
  ```javascript
  converted_file.expired = converted_file.addTime + 1800 * 1000;
  ```
- **Verdict**: ACCEPTABLE - Temporary file retention is standard for conversion services.

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|--------------------------|
| `fetch()` API calls | Multiple locations | Legitimate API communication with service backend |
| `postMessage` relay | content_script.js | Properly validated origin check before relay |
| `chrome.storage.local` | misc.js, background.js | Legitimate storage of conversion history |
| `chrome.notifications` | background.js | User-facing conversion status notifications |
| Third-party library | dropzone.min.js | Standard file upload library (Dropzone.js) |

## API Endpoints Table

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `https://p1.qwerpdf.com/api/upload1` | PDF file upload | File content (multipart/form-data) | LOW |
| `https://up1.qwerpdf.com/extupload` | Office file upload | File content (multipart/form-data) | LOW |
| `https://qwerpdf.com/queue/v2` | Queue conversion task | file, from, to, task, user, password, fun, server | LOW |
| `https://qwerpdf.com/user/taskProcess` | Check task status | id, user | LOW |
| `https://qwerpdf.com/user/taskCreate` | Create task record | type, name, size, user_id, server | LOW |
| `https://qwerpdf.com/user/taskuid` | Update task UID | task_id, uid | LOW |
| `https://qwerpdf.com/ext/checkUser` | Verify user login | None (credentials in cookies) | LOW |
| `https://qwerpdf.com/user/allowofficeview` | Check view permissions | taskid, type | LOW |
| `https://qwerpdf.com/pdf/extdownload/...` | Download converted file | Encoded in URL path | LOW |
| `https://qwerpdf.com/pdf/extfileedit/...` | Edit/view converted file | Encoded in URL path | LOW |

## Data Flow Summary

1. **User Interaction Flow**:
   - User selects file via Dropzone UI in popup
   - File read as DataURL in popup (upload.js)
   - Message sent to background script with file data
   - Background converts DataURL to Blob and uploads to qwerpdf.com
   - Task created and polled until completion
   - Converted file URL stored in chrome.storage.local
   - User downloads converted file from qwerpdf.com

2. **Data Collection**:
   - File content (for conversion)
   - File metadata (name, size, type)
   - Task IDs (server-generated)
   - User ID (if logged in)
   - UTM tracking parameters (utm_source=E-EEOC, utm_medium=EXT)

3. **Data Storage**:
   - `chrome.storage.local.files` - Array of converted file metadata
   - `chrome.storage.local.user` - User login state (user_id, is_subscription)

4. **Third-Party Communication**:
   - All communication limited to qwerpdf.com domain and subdomains
   - No external analytics, tracking, or advertising networks detected

## Security Features

✅ **Proper origin validation** in content script message handler
✅ **Scoped host permissions** to extension's own domain only
✅ **Minimal permissions** requested
✅ **No dynamic code execution** (eval, Function, etc.)
✅ **No sensitive API access** (cookies, webRequest, tabs enumeration, etc.)
✅ **No obfuscation** beyond minified Dropzone library
✅ **File expiration** implemented (30 minutes)

## Privacy Considerations

- **File Upload**: User files are uploaded to qwerpdf.com servers for conversion. This is clearly the stated purpose of the extension.
- **User Tracking**: Minimal tracking via UTM parameters for install/uninstall attribution.
- **No Cross-Site Data Access**: Content scripts only run on qwerpdf.com, preventing access to user data on other sites.
- **No Persistent Identifiers**: No device fingerprinting or persistent tracking beyond optional user login.

## Recommendations

1. ✅ **No security fixes required** - Extension follows security best practices
2. ℹ️ Users should be aware that files are uploaded to third-party servers (though this is inherent to the service)
3. ℹ️ Sensitive/confidential documents should not be processed through any third-party conversion service

## Overall Risk Assessment

**Risk Level: LOW**

**Justification**:
- Extension performs exactly as advertised (document conversion service)
- Minimal permissions with appropriate scope
- No data exfiltration beyond stated functionality
- No malicious code patterns detected
- No suspicious obfuscation or anti-analysis techniques
- No injection of ads, tracking scripts, or third-party SDKs
- Proper security practices (origin validation, scoped permissions)
- No evidence of extension enumeration, proxy infrastructure, or malware characteristics

**Verdict**: CLEAN

This is a legitimate productivity extension that provides document conversion services via a web-based API. While it does upload user files to remote servers (qwerpdf.com), this is the core and clearly stated functionality. The extension demonstrates responsible security practices and does not exhibit any malicious behavior patterns.
