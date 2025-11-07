# Vulnerability Report – Command Injection in OWASP Benchmark for Java

## Submitter
- sh7err@vEcho

## Summary
`BenchmarkTest00295`, exposed at `/cmdi-00/BenchmarkTest00295`, reads an attacker-controlled HTTP header and spawns `cmd.exe /c` or `sh -c` with the header value concatenated into the command line. Because the value is evaluated by the system shell, an unauthenticated attacker can execute arbitrary OS commands with the permissions of the servlet container.

## Product Information
- **Vendor:** OWASP Foundation
- **Product:** OWASP Benchmark for Java
- **Version:** 1.2 (latest master)
- **Environment:** Any platform supported by the Benchmark (Windows, Linux, macOS)

## Vulnerability Details
- **Vulnerability Type:** OS Command Injection (CWE-78)
- **Attack Surface:** HTTP POST/GET endpoint `/cmdi-00/BenchmarkTest00295`
- **Affected Component:** `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00295.java`

### Technical Description
The servlet grabs the first value of header `BenchmarkTest00295`, decodes it, assigns it to `bar`, and then executes:
```java
String[] args = {a1, a2, "echo " + bar};
ProcessBuilder pb = new ProcessBuilder(args);
Process p = pb.start();
```
When running on Unix-like systems, `a1="sh"` and `a2="-c"`, so the third argument is interpreted by the shell. Characters such as `&&`, `;`, or backticks allow injection of additional commands that run before returning the echoed string. The helper `Utils.printOSCommandResults` streams stdout/stderr back to the HTTP response, confirming execution.

### Proof of Concept
```
curl -i -X POST \
     -H "BenchmarkTest00295=hello && id" \
     http://<host>:8080/benchmark/cmdi-00/BenchmarkTest00295
```
Response contains the output of `/usr/bin/id`, demonstrating arbitrary command execution. Equivalent payloads work on Windows with `&`.

### Impact
Remote unauthenticated attackers obtain arbitrary command execution on the underlying host, enabling full takeover, lateral movement, and data theft.

### Suggested Mitigations
1. Do not pass untrusted data to shells; build the command argument array without involving `sh -c` / `cmd /c`.
2. Apply strict whitelists for any permitted command-line arguments and escape values using platform-specific routines.
3. Consider removing the test servlet entirely or wrapping it behind strong authentication when not used for benchmarking.

### Additional Notes
The vulnerable sample is part of OWASP Benchmark's command injection test suite. It must be isolated from production environments to avoid exposing the host.
