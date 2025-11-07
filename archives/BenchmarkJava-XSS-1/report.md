# Vulnerability Report – Reflected XSS in OWASP Benchmark for Java

## Submitter
- sh7err@vEcho

## Summary
The servlet `BenchmarkTest00048`, accessible at `/xss-00/BenchmarkTest00048`, reads the raw query string parameter `BenchmarkTest00048`, URL-decodes it, disables the browser's XSS filter, and writes the value directly to the HTTP response without any encoding. This exposes a classic reflected cross-site scripting vulnerability that allows arbitrary script execution in the victim's browser.

## Product Information
- **Vendor:** OWASP Foundation
- **Product:** OWASP Benchmark for Java
- **Version:** 1.2 (latest master)
- **Environment:** Any servlet container (Tomcat/Jetty/etc.)

## Vulnerability Details
- **Vulnerability Type:** Reflected Cross-Site Scripting (CWE-79)
- **Attack Surface:** HTTP GET endpoint `/xss-00/BenchmarkTest00048`
- **Affected Component:** `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00048.java`

### Technical Description
Instead of calling `request.getParameter()`, the servlet manually parses `request.getQueryString()`, extracts the substring after `BenchmarkTest00048=`, decodes it, and returns it verbatim:
```java
response.setHeader("X-XSS-Protection", "0");
response.getWriter().print(param.toCharArray());
```
Because no HTML encoding is performed, any `<script>` or event handler supplied by the attacker executes in the victim's origin context.

### Proof of Concept
```
http://<host>:8080/benchmark/xss-00/BenchmarkTest00048?BenchmarkTest00048=%3Cscript%3Ealert(document.domain)%3C/script%3E
```
Visiting the URL shows a JavaScript alert with the site's domain, confirming XSS. The attack can be weaponized to steal session cookies or perform authenticated actions.

### Impact
An attacker can execute arbitrary JavaScript in the victim's browser within the application's origin, enabling credential theft, CSRF token exfiltration, or UI redressing attacks.

### Suggested Mitigations
1. Use standard parameter accessors such as `request.getParameter()` and encode any untrusted data before embedding it into HTML (`ESAPI.encoder().encodeForHTML`).
2. Enforce HTTP response headers such as `Content-Security-Policy` and keep browser XSS filters enabled.
3. Sanitize or reject unexpected characters in reflected parameters.

### Additional Notes
The servlet exists to test XSS detection capabilities; it should never be exposed to untrusted users outside of benchmarking exercises.
