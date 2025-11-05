# Vulnerability Report: Directory Traversal in org.takes:takes

- **Submitter:** sh7err
- **Date:** 2025-11-05
- **Affected Product:** takes (org.takes)
- **Affected Component:** `TkFiles` (src/main/java/org/takes/tk/TkFiles.java)
- **Vulnerability Type:** Directory Traversal / Arbitrary File Read
- **Impact:** High – unauthenticated disclosure of arbitrary files from the server filesystem
- **Status:** Unfixed as of commit 5e1ef1e0343dcb25ac050ce74dd68b65bae3f96a (2.0-SNAPSHOT)

## Summary
`TkFiles`, the static file serving take in the Takes web framework, concatenates the HTTP request path directly onto the configured base directory without canonicalization or traversal checks. An attacker can supply path segments such as `../` to escape the base directory and read arbitrary files on the host. This contradicts the documented intent that “Directory traversal attempts (../) are handled safely.”

## Technical Details
1. `TkFiles` resolves the target file with `new File(base, new RqHref.Base(request).href().path())` (src/main/java/org/takes/tk/TkFiles.java:88-100).
2. `RqHref.Base` and `Href#path()` preserve traversal sequences like `../`.
3. `java.io.File` keeps the provided base directory even when the second argument starts with `/`. The resulting canonical path is calculated lazily. Example from JShell:
   ```java
   File base = new File("/tmp/base");
   File target = new File(base, "/../../etc/passwd");
   target.getCanonicalPath(); // => /etc/passwd
   target.exists();           // true (once base exists)
   ```
4. `TkFiles` checks only `file.exists()` before streaming the file back through `new RsWithBody(new InputOf(file).stream())`.
5. Consequently, any readable file on the filesystem becomes accessible to a remote unauthenticated attacker.

## Proof of Concept
1. Ensure the service exposes a `TkFiles` instance, e.g.:
   ```java
   new FtBasic(new TkFiles("/var/www/static"), 8080).start(Exit.NEVER);
   ```
2. Create the base directory (`/var/www/static`) so the file existence check succeeds.
3. Issue the following HTTP request:
   ```bash
   curl http://localhost:8080/../../etc/passwd
   ```
4. The response body contains the contents of `/etc/passwd`, demonstrating arbitrary file disclosure outside the configured document root.

The same behaviour is reproducible in automated tests:
```java
new TkFiles(tempDir.toFile()).act(new RqFake("GET", "/../../etc/passwd HTTP/1.1"));
```
which streams the system `/etc/passwd` file when the environment permits read access.

## Impact Assessment
- **Attack Surface:** Remote, unauthenticated HTTP clients
- **Confidentiality:** Full compromise of any readable file, including application configuration, credentials, and source code
- **Integrity:** Not directly affected, but disclosed secrets may enable follow-on attacks
- **Availability:** Not impacted

## Root Cause
Lack of canonicalization or traversal validation in `TkFiles` when translating request paths to filesystem paths.

## Suggested Mitigations
- Normalize/canonicalize the resolved file path (`getCanonicalPath()`) and ensure it remains within the configured base directory before serving it.
- Alternatively, reject any request path containing `..`, backslashes, or absolute path prefixes.
- Add regression tests covering traversal attempts to prevent future regressions.

## Timeline
- 2025-11-05 – Vulnerability identified and reproduced by sh7err.
- 2025-11-05 – CVE request package prepared.

## References
- Project repository: https://github.com/yegor256/takes
- Vulnerable file: `src/main/java/org/takes/tk/TkFiles.java`

## Credits
- Discovery and report prepared by **sh7err**.
