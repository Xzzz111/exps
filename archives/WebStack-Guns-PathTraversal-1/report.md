# WebStack-Guns Path Traversal (CWE-22)

- **Submitter**: sh7err@vEcho
- **Target Product**: WebStack-Guns (open-source navigation CMS)
- **Affected Version**: 1.0 (current master)
- **Tested Environment**: commit `HEAD` of https://github.com/jsnjfz/WebStack-Guns on Java 8 / Spring Boot 2.0.1
- **Vulnerability Type**: Path Traversal leading to arbitrary file read
- **CVSS v3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (Base 7.5)

## Summary
The public `/kaptcha/{pictureId}` endpoint fails to sanitize the attacker-controlled `pictureId` parameter before concatenating it with the configured upload path. Because the route is explicitly exposed as an anonymous resource in `ShiroConfig`, any remote user can perform directory traversal and force the server to return arbitrary files readable by the application user.

## Component Overview
- `com.jsnjfz.manage.modular.system.controller.KaptchaController#renderPicture` (src/main/java/com/jsnjfz/manage/modular/system/controller/KaptchaController.java:114-127)
- `com.jsnjfz.manage.config.web.ShiroConfig#shiroFilter` (src/main/java/com/jsnjfz/manage/config/web/ShiroConfig.java:140-189)
- `com.jsnjfz.manage.config.properties.GunsProperties#getFileUploadPath` (src/main/java/com/jsnjfz/manage/config/properties/GunsProperties.java:58-78)

The design intent of `renderPicture` is to return uploaded thumbnails or captcha images by filename. The handler trusts the path variable on the assumption that only legitimate filenames will be requested from the admin UI. No validation or canonicalization is performed.

## Proof of Concept
1. Deploy WebStack-Guns with the default configuration where `guns.file-upload-path` points to a writable directory (e.g., `/tmp/`).
2. Send the following HTTP request without authenticating:

```
GET /kaptcha/..%2f..%2f..%2f..%2fetc%2fpasswd HTTP/1.1
Host: victim
```

3. The controller builds `path = <upload_path> + "../../../../etc/passwd"`, resolves it via `FileUtil.toByteArray`, and streams the bytes back in the HTTP response. Any file readable by the JVM process, including `application.yml` (contains DB credentials) or SSH keys, can be exfiltrated the same way.

## Root Cause Analysis
- `pictureId` is directly concatenated to the upload directory without normalization. No checks exist for `..`, path separators, or absolute paths.
- The application exposes `/kaptcha/**` to unauthenticated users via Shiro's filter chain, so there is no authentication or authorization barrier that could mitigate the issue.
- `GunsProperties#getFileUploadPath` may automatically create directories and append a trailing slash, but it performs no sanitization and therefore does not prevent traversal.

## Impact
This flaw allows any remote network attacker to read arbitrary files accessible to the application service account. Attackers can obtain database passwords from `application.yml`, dump user data, or chain with other vulnerabilities that require configuration disclosure. The weakness therefore constitutes a high-severity information disclosure.

## Recommended Remediation
1. Treat `pictureId` as untrusted input. Reject any value containing directory traversal characters (`/`, `\\`, `..`, `%2f`, etc.) or enforce a strict whitelist for allowed filenames.
2. Construct filesystem paths using `Paths.get(uploadDir, pictureId).normalize()` and ensure that the normalized path still starts with the intended upload base directory before reading the file.
3. Consider serving uploaded thumbnails through a dedicated controller that looks up filenames from the database rather than accepting raw user input. At minimum, change the Shiro filter chain so that `/kaptcha/**` is protected if the endpoint is not needed publicly.

## References
- Source: https://github.com/jsnjfz/WebStack-Guns/blob/master/src/main/java/com/jsnjfz/manage/modular/system/controller/KaptchaController.java#L114-L127

