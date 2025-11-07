# Vulnerability Report – Directory Traversal in OWASP Benchmark for Java

## Submitter
- sh7err@vEcho

## Summary
An unauthenticated POST request to `/pathtraver-00/BenchmarkTest00001` accepts an attacker-controlled cookie value and uses it directly as part of a filesystem path. Because the application never normalizes or restricts the supplied value, an attacker can supply sequences such as `../../` to traverse outside of the intended `testfiles/` sandbox and read arbitrary files that the Java process can access.

## Product Information
- **Vendor:** OWASP Foundation
- **Product:** OWASP Benchmark for Java
- **Version:** 1.2 (latest master)
- **Environment:** Default configuration shipped with the project, running on any servlet container

## Vulnerability Details
- **Vulnerability Type:** Directory Traversal (CWE-22)
- **Attack Surface:** HTTP POST endpoint `/pathtraver-00/BenchmarkTest00001`
- **Affected Component:** `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java` (`doPost` method)

### Technical Description
`BenchmarkTest00001#doPost` pulls the value of the cookie named `BenchmarkTest00001`, URL-decodes it, concatenates it with `org.owasp.benchmark.helpers.Utils.TESTFILES_DIR`, and instantiates a `FileInputStream` on the resulting path. The method never validates or normalizes the user-supplied value, so relative path tokens such as `../` traverse out of the testfiles directory. Whatever file is opened is dumped back to the HTTP response, which allows arbitrary file disclosure under the servlet container's privileges.

Relevant excerpt:
```java
String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
FileInputStream fis = new FileInputStream(new File(fileName));
byte[] b = new byte[1000];
int size = fis.read(b);
response.getWriter().println("The beginning of file: '" + ESAPI.encoder().encodeForHTML(fileName) + "' is:\n\n" + ESAPI.encoder().encodeForHTML(new String(b, 0, size)));
```

### Proof of Concept
```
curl -i -X POST \
     -H "Cookie: BenchmarkTest00001=../../../../etc/passwd" \
     http://<host>:8080/benchmark/pathtraver-00/BenchmarkTest00001
```
The response begins with the contents of `/etc/passwd` (or any targeted file that the JVM can read).

### Impact
Remote attackers can read any file that the application user account can access, exposing credentials, source code, and environment secrets. This information disclosure can be chained with other weaknesses to escalate an intrusion.

### Suggested Mitigations
1. Reject any cookie value that contains path metacharacters such as `..`, `/`, `\\`, or NUL bytes.
2. Resolve the requested path via `Paths.get(baseDir, userInput).normalize()` and ensure the normalized path still resides beneath the intended directory before opening it.
3. Prefer exposing only whitelisted file identifiers instead of raw filenames supplied by users.

### Additional Notes
OWASP Benchmark intentionally ships with vulnerable test cases to evaluate security tooling. If any portion of this project is repurposed for production use, the vulnerable sample servlets must be removed or fixed before deployment.
