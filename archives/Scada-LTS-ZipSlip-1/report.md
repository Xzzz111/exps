# Security Vulnerability Report: Scada-LTS Zip Slip Arbitrary File Write

**Submitter:** sh7err@vEcho  
**Tested revision:** commit 1cfaed4b35117e4871bc3dfeae073f61d8e3bb3d (branch: develop)

## Summary

Scada-LTS is vulnerable to a Zip Slip style path traversal in its project import functionality. By providing a crafted ZIP archive, an authenticated administrator can coerce the server into writing attacker-controlled files outside of the intended `uploads/` and `graphics/` directories. The issue stems from insufficient normalization and validation in `ZIPProjectManager.restoreFiles` combined with permissive path checks in `PathSecureUtils` and `SafeZipFileUtils`.

Successful exploitation enables arbitrary file overwrite anywhere beneath `Common.getHomeDir()` (typically the Tomcat base directory). An attacker can deface the user interface, plant malicious SVGs for stored XSS, or otherwise persistently modify resources that are delivered to other users.

## Product & Versions

- **Product:** Scada-LTS (https://github.com/SCADA-LTS/Scada-LTS)  
- **Affected versions:** all releases prior to and including commit 1cfaed4b35117e4871bc3dfeae073f61d8e3bb3d  
- **Fixed version:** _Not yet fixed_

## Vulnerability Details

### Root Cause Analysis

1. `br/org/scadabr/vo/exporter/ZIPProjectManager.java:125-205` iterates over each ZIP entry during import and delegates filtering to `UploadFileUtils.filteringUploadFiles`/`filteringGraphicsFiles` before calling `restoreFiles`.
2. `restoreFiles` (line 179) ultimately resolves the destination with `PathSecureUtils.toSecurePath(Paths.get(appPath + File.separator + entryName))` and writes the file without further checks if the optional result is present.
3. `PathSecureUtils.toSecurePath` (`src/org/scada_lts/utils/PathSecureUtils.java:45-95` and `186-193`) constructs an absolute path via `getAbsoluteResourcePath`. When the provided path contains traversal segments (e.g., `uploads/../../../../webapps/Scada-LTS/assets/logo.png`), the function simply concatenates the input to `Common.getHomeDir()` before returning, allowing traversal to any location under that base directory.
4. The preventative checks in `SafeZipFileUtils.valid` (`src/org/scada_lts/utils/security/SafeZipFileUtils.java:11-22`) rely on `ValidationPaths.validatePath(..., a -> true)`, which always reports success and therefore fails to block `..` sequences.
5. `UploadFileUtils.isToUploads` (`src/org/scada_lts/utils/UploadFileUtils.java:215-276`) confirms only MIME type/format (e.g., PNG, SVG, `info.txt`) and does not mitigate directory traversal.

### Proof of Concept

1. Authenticate to Scada-LTS as an administrator.
2. Create a ZIP archive with a payload file beyond the intended directory:

   ```bash
   mkdir -p exploit/uploads/../../../../webapps/Scada-LTS/assets/
   cp legit.png exploit/uploads/../../../../webapps/Scada-LTS/assets/logo.png
   (cd exploit && zip -r malicious.zip uploads)
   ```

   (Any valid PNG/SVG will satisfy `ImageIO.read`.)

3. In the web UI, navigate to **System → Import** and upload `malicious.zip`.
4. After import, inspect `${SCADA_HOME}/webapps/Scada-LTS/assets/logo.png`. The original file is overwritten with the attacker-controlled image, demonstrating arbitrary file write under `Common.getHomeDir()`.

### Impact

- Persistent defacement or phishing by replacing UI assets.
- Potential stored XSS if a malicious SVG or other interpreted resource is placed in a web-accessible path.
- Facilitates additional exploitation by overwriting configuration, templated files, or other static resources delivered to operators.

## Remediation Guidance

1. Treat all ZIP entry names as untrusted input. After resolving the canonical path (`File#getCanonicalPath()`), ensure it starts with the intended `uploads`/`graphics` base directory before writing.
2. Harden `SafeZipFileUtils`/`ValidationPaths` to reject traversal tokens (`..`, absolute paths, drive letters) rather than blindly accepting `normalize()` results.
3. Optionally maintain an explicit whitelist of permissible subdirectories and file types.


## Credits

Discovered by sh7err@vEcho.

