# DHIS2 Core - Path Traversal in /api/apps Resources

**Submitter:** s1ain  
**Discovery Date:** 2025-11-04  
**Tested Version:** dhis2-core commit 5a9b5335e29947ecad6b9f74ef69b073f727a730  
**Impact:** Arbitrary file read (Information Disclosure)  
**Severity:** High

## Summary
The DHIS2 Web API exposes static resources for installed DHIS2 apps via `/api/apps/{appKey}/**`. When the file store provider is configured as `filesystem` (the documented default for on-prem deployments), the request path is not normalized or bounds-checked. An authenticated user can supply path segments containing `..` to traverse out of the app directory and read arbitrary files on the host, including `dhis.conf` or `/etc/passwd`.

## Vulnerability Details
1. `AppController#getResourcePath` (dhis-web-api/src/main/java/org/hisp/dhis/webapi/controller/AppController.java:185-315) strips protocol prefixes but never rejects `..` or absolute path elements. The untrusted `resourcePath` is propagated unchanged.
2. `DefaultAppManager#getAppResource` concatenates the attacker-controlled path with the app folder and forwards it to `JCloudsAppStorageService#getResource` without any canonical-path validation.
3. In filesystem mode, `JCloudsAppStorageService#getResource` calls `LocationManager.getFileForReading(cleanedFilepath)`. `DefaultLocationManager#getFileForReading` simply constructs `new File(directory, fileName)` and verifies existence/readability (dhis-support-external/.../DefaultLocationManager.java:200-206). Thus `..` sequences escape the app directory, and there is no check that the resolved file remains under `<DHIS2_HOME>/files`.

Because the servlet ultimately streams whatever file was opened, an attacker can retrieve arbitrary readable files from the operating system.

## Proof of Concept
1. Install or identify any DHIS2 app with key `myapp`.
2. Send an authenticated request (any user who can load app resources):
   ```bash
   curl -k -u user:pass \
     "https://dhis.example.com/api/apps/myapp/../../../../etc/passwd"
   ```
3. The response body contains `/etc/passwd`. Other sensitive files such as `DHIS2_HOME/dhis.conf` can be exfiltrated the same way.

## Impact
Attackers can read secrets stored on the DHIS2 host (database credentials, TLS keys, OS user data). This facilitates privilege escalation, lateral movement, and complete compromise of the deployment.

## Mitigation
- Normalize and validate `resourcePath` in `AppController` (e.g., `Paths.get(...).normalize()`), reject requests containing `..`, absolute paths, or null bytes.
- In `JCloudsAppStorageService#getResource`, compute the canonical path and ensure it starts with the expected app directory before reading the file.
- Add canonical-path enforcement inside `LocationManager#getFileForReading`/`getFileForWriting` to prevent future regressions.

## Timeline
- **2025-11-04:** Vulnerability discovered during code audit.

## Credits
Discovered by s1ain.
