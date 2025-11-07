# Jakarta RESTful Web Services `MultipartResource` Directory Traversal

## Submitter
- sh7err@vEcho

## Affected Product(s)
- **Vendor:** Eclipse Foundation / Jakarta EE
- **Product:** Jakarta RESTful Web Services (REST) Examples module
- **Affected Component:** `examples/src/main/java/jaxrs/examples/multipart/MultipartResource.java`
- **Version:** 5.0.0-SNAPSHOT (commit `1c637a0a971ad3f9c5ac8a07ee88793c5fa2b17e`)
- **Configuration:** Default `pdf.root.dir` (`/myPDFs`) or any custom path

## Vulnerability Type
- Directory Traversal / Arbitrary File Read & Write

## CVSS (preliminary)
- Base Score: 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Overview
The sample REST endpoint `MultipartResource` exposes `/multipart` APIs for handling PDF uploads. Two independent directory traversal bugs allow remote, unauthenticated attackers to read arbitrary files and write attacker-controlled files outside the intended storage root. The flaws stem from the absence of canonical-path validation for both the `dirName` query parameter and each uploaded part's file name.

## Technical Details
### 1. `dirName` traversal enables arbitrary directory read/write
*Method(s):* `getAllPdfFilesInDirectory`, `postNewPdfFiles`
*Code:* `new File(PDF_ROOT_DIR, dirName)` → `dir.listFiles()` / `Files.copy(...)`

`dirName` is taken directly from the HTTP query string and appended to `PDF_ROOT_DIR`. If an attacker sends `dirName=../../../../etc`, `java.io.File` resolves it outside `/myPDFs`. Because the only validation is `dir.exists()`, any existing directory (including absolute paths such as `/etc`) can be targeted. `GET /multipart?dirName=/etc` returns every file under `/etc` as multipart parts. The corresponding `POST` stores uploaded files into the same arbitrary directory. No authentication, normalization, or allow‑listing mitigations are present, so impact is equivalent to full arbitrary file read/write (subject to OS permissions).

### 2. File name traversal reintroduces arbitrary file write
*Method:* `postNewPdfFiles`
*Code:* `File f = new File(dir, p.getFileName().orElseThrow(...));`

Each uploaded `EntityPart` may supply a `Content-Disposition` filename, which is concatenated as the second argument of `new File`. Java treats absolute paths or names with `../` as escape sequences; therefore an attacker can set `filename=../../../../tmp/shell.jsp` and force writes outside the supposedly safe directory even if `dirName` were sanitized. The only subsequent check is `f.exists()`, which merely prevents overwriting existing files, not path traversal.

### Proof of Concept
```
# Arbitrary read
curl -k "https://target.example.com/api/multipart?dirName=/etc" -H 'Accept: multipart/form-data'

# Arbitrary write via dirName
curl -k -X POST "https://target.example.com/api/multipart?dirName=/tmp" \
     -F 'file=@payload.pdf;type=application/pdf'

# Arbitrary write via filename
curl -k -X POST "https://target.example.com/api/multipart?dirName=safe" \
     -F 'file=@payload.pdf;type=application/pdf;filename=../../../../tmp/evil.jsp'
```

## Impact
A remote attacker can download any readable file from the server (secrets, configuration, keys) and plant arbitrary files in writable locations, possibly escalating to code execution depending on the environment (e.g., planting web shells or tampering with configuration). No authentication is required.

## Root Cause
- Lack of canonical-path validation and allow-listing for user-controlled directory names.
- Lack of filename normalization before using user-supplied `EntityPart` metadata as filesystem paths.

## Remediation
1. Normalize (`Path.normalize().toRealPath()`) both the requested directory and each target file, and verify they remain within the configured `pdf.root.dir` before any file system action.
2. Reject absolute paths and names containing `..`, path separators, or drive specifiers; alternatively, use `Paths.get(name).getFileName()` to strip user-supplied directories.
3. Consider running the example service under a low-privilege account and storing uploads on isolated storage.

## References
- https://github.com/jakartaee/rest (source repository)
- https://jakarta.ee/specifications/restful-ws/
