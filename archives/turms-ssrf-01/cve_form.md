# CVE Application Form - Turms SSRF in HTTP Authentication Configuration

## Vulnerability Type Info
**Server-Side Request Forgery (SSRF)**

## Vendor of the Product(s) Info
**Vendor**: Turms Project (turms-im)
**Vendor Homepage**: https://github.com/turms-im/turms

## Affected Product(s)/Code Base Info

| Product | Version |
|---------|---------|
| Turms Server | v0.10.0-SNAPSHOT and earlier |

**Fixed Version**: Not fixed yet

## Optional
**Has vendor confirmed or acknowledged the vulnerability?**
No - The vulnerability has not been publicly disclosed to the vendor yet.

## Attack Type Info
**Remote**

## Impact Info
- [x] Information Disclosure
- [ ] Code Execution
- [ ] Denial of Service
- [ ] Escalation of Privileges
- [x] Other: Network Reconnaissance, Cloud Metadata Theft

## Affected Component(s)
HTTP-based authentication service configuration, administrator configuration panel, external authentication URL validation mechanism

## Attack Vector(s)
To exploit this vulnerability:
1. Attacker gains administrator access (through compromised credentials, social engineering, or other vulnerabilities)
2. Attacker accesses the Turms admin configuration panel
3. Attacker configures the HTTP authentication service URL to point to internal network addresses:
   - Localhost: `http://127.0.0.1:PORT/`
   - Private networks: `http://192.168.x.x/`, `http://10.x.x.x/`
   - Cloud metadata: `http://169.254.169.254/latest/meta-data/` (AWS)
   - Cloud metadata: `http://metadata.google.internal/` (GCP)
   - Internal services: databases, caches, admin panels
4. When users attempt to authenticate, Turms server makes HTTP requests to the configured malicious URL
5. Attacker extracts information from:
   - Server logs containing response data
   - Timing differences in responses
   - Error messages revealing internal service details
   - Direct access to internal service responses if controllable
6. Attacker achieves:
   - Cloud instance credential theft
   - Internal network mapping and port scanning
   - Access to internal services and APIs
   - Bypass of network segmentation

## Suggested Description of the Vulnerability for Use in the CVE
Turms Server v0.10.0-SNAPSHOT and earlier contains a Server-Side Request Forgery (SSRF) vulnerability in the HTTP-based authentication service configuration. Administrators can specify arbitrary URLs for external authentication endpoints, but the system does not validate these URLs or filter internal network addresses. A malicious or compromised administrator can configure the authentication service to point to internal network addresses (127.0.0.1, 10.x.x.x, 192.168.x.x ranges), localhost, or cloud instance metadata endpoints (169.254.169.254 for AWS, metadata.google.internal for GCP). When users authenticate, the Turms server makes HTTP requests to these internal targets, enabling attackers to perform port scanning, access internal services, steal cloud credentials, and bypass network access controls. CVSS v3.1 Base Score: 4.3 (Medium) - AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N

## Discoverer(s)/Credits Info
s1ain

## Reference(s) Info
https://github.com/turms-im/turms
https://cwe.mitre.org/data/definitions/918.html
https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html

## Additional Information
- **Severity**: Medium (CVSS 4.3), but can be Critical in cloud environments
- **CWE ID**: CWE-918 (Server-Side Request Forgery)
- **Vulnerability Type**: SSRF
- **Authentication Required**: Administrator privileges required
- **Attack Complexity**: Low
- **Disclosure Date**: 2025-11-02
- **Status**: Unpatched

**Attack Scenarios**:
1. **AWS Metadata Theft**: Point to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to steal IAM credentials
2. **GCP Metadata Theft**: Point to `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` to steal service account tokens
3. **Internal Port Scanning**: Iterate through ports on internal IPs to map network infrastructure
4. **Database Access**: Point to `http://127.0.0.1:27017/` (MongoDB), `http://localhost:6379/` (Redis) to interact with internal databases
5. **Internal API Access**: Access internal admin panels, monitoring tools, or management interfaces

**Cloud Metadata Endpoints to Block**:
- AWS/Azure: `169.254.169.254`
- GCP: `metadata.google.internal`, `metadata`
- Alibaba Cloud: `100.100.100.200`
- DigitalOcean: `169.254.169.254`

**Private IP Ranges to Block**:
- `127.0.0.0/8` (loopback)
- `10.0.0.0/8` (private)
- `172.16.0.0/12` (private)
- `192.168.0.0/16` (private)
- `169.254.0.0/16` (link-local, includes cloud metadata)
- `::1` (IPv6 loopback)
- `fc00::/7` (IPv6 unique local)

**Recommended Fixes**:
1. Implement strict URL validation rejecting internal addresses
2. Use allowlist of permitted authentication service domains
3. Block cloud metadata endpoint access
4. Validate resolved IP addresses, not just hostnames (prevent DNS rebinding)
5. Use separate network namespace or proxy for outbound requests
6. Implement request timeouts and response size limits
7. Add audit logging for authentication URL configuration changes
8. Require HTTPS only for authentication endpoints

**Defense in Depth**:
- Network-level blocking of internal IP ranges from application servers
- Cloud provider IMDSv2 requirement (prevents simple HTTP SSRF)
- Principle of least privilege for administrator accounts
- Regular security audits of authentication configurations
