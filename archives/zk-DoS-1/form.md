# CVE Request Form

**Vulnerability type info**  
Denial of Service (unauthenticated input validation error in multipart parser)

**Vendor of the product(s) info**  
ZKoss / Potix Corporation

**Affected product(s)/code base info**  
- Product: ZK Framework 10.0.0 – 10.3.0-SNAPSHOT (confirmed on commit f52827fab6a1e844bcb0329a5ed3f59f8fb7e690).  
- Fixed version: not yet available.

**Has vendor confirmed or acknowledged the vulnerability**  
No

**Attack type info**  
Remote

**Impact info**  
Denial of Service

**Affected component(s)**  
`org.zkoss.zk.au.http.AuMultipartUploader`, `splitQueryParameter`, `splitQuery`

**Attack vector(s)**  
An unauthenticated attacker sends a crafted `multipart/form-data` POST request to the AU endpoint (e.g., `/zkau`) where the `data` field contains a parameter without an equals sign (such as `cmd_0=foo&foo`). When the server decodes the query fragment it dereferences `null`, throws a `NullPointerException`, and kills the request-handling thread.

**Suggested description of the vulnerability for use in the CVE info**  
ZK Framework versions 10.0.0 through 10.3.0-SNAPSHOT contain an input-validation flaw in `AuMultipartUploader`. The multipart AU parser assumes every `key=value` pair contains an equals sign; a crafted request without `=` causes `URLDecoder.decode` to receive `null` and throw a `NullPointerException`, letting remote attackers crash the update servlet and deny service.

**Discoverer(s)/Credits info**  
sh7err@vEcho

**Reference(s) info**  
https://github.com/zkoss/zk (tested at commit f52827fab6a1e844bcb0329a5ed3f59f8fb7e690)

**Additional information**  
Proof-of-concept:  
```
curl -k -i -X POST http://victim.example/zkau \
  -H 'Content-Type: multipart/form-data; boundary=----v' \
  --data-binary $'------v\r\nContent-Disposition: form-data; name="data"\r\n\r\ncmd_0=foo&foo\r\n------v--\r\n'
```
