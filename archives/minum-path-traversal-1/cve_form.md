## CVE Submission Form

**Vulnerability type info**  
Directory Traversal / Arbitrary File Read via Symbolic Link Bypass

**Vendor of the product(s) info**  
Renomad (Minum project)

**Affected product(s)/code base info**  
- Minum Web Framework 8.3.0 (latest) and earlier versions; no patched release available yet.

**Has vendor confirmed or acknowledged the vulnerability**  
No

**Attack type info**  
Remote

**Impact info**  
Information Disclosure

**Affected component(s)**  
`src/main/java/com/renomad/minum/utils/FileUtils.java` (`checkFileIsWithinDirectory`), `src/main/java/com/renomad/minum/web/WebFramework.java` (`readStaticFile` static handler)

**Attack vector(s)**  
An unauthenticated attacker who can place or control symbolic links under the configured static directory (common in shared deployments or repos) can request `/symlink/target` over HTTP; Minum fails to resolve symlinks during validation but follows them when opening the file, so the response contains arbitrary files outside the static tree (e.g., `/etc/passwd`).

**Suggested description of the vulnerability for use in the CVE info**  
Minum Web Framework before a forthcoming fix validates static file paths using `checkFileIsWithinDirectory`, which resolves paths with `toRealPath(LinkOption.NOFOLLOW_LINKS)` and therefore does not follow symbolic links. When the file is later opened, the runtime follows the symlink, allowing attackers to traverse out of the static directory and read any file accessible to the server process via crafted requests such as `/symlink/secret`. This results in unauthenticated arbitrary file read.

**Discoverer(s)/Credits info**  
sh7err@vEcho

**Reference(s) info**  
https://github.com/byronka/minum

**Additional information**  
Proof-of-concept: create `ln -s /etc static/leak` and request `GET /leak/passwd HTTP/1.1`; the server returns `/etc/passwd` with `200 OK`.
