# CVE Application Form - Turms Admin Password Plaintext Caching

## Vulnerability Type Info
**Cleartext Storage of Sensitive Information**

## Vendor of the Product(s) Info
**Vendor**: Turms Project (turms-im)
**Vendor Homepage**: https://github.com/turms-im/turms

## Affected Product(s)/Code Base Info

| Product | Version |
|---------|---------|
| Turms Server Common | v0.10.0-SNAPSHOT and earlier |

**Fixed Version**: Not fixed yet

## Optional
**Has vendor confirmed or acknowledged the vulnerability?**
Partially - The code contains comments indicating this is a performance optimization ("If the password doesn't match, it may happen due to the outdated cache"), but the security implications have not been publicly acknowledged.

## Attack Type Info
**Local**

## Impact Info
- [x] Information Disclosure
- [ ] Code Execution
- [ ] Denial of Service
- [x] Escalation of Privileges
- [x] Other: Compliance Violation (PCI DSS, GDPR)

## Affected Component(s)
`turms-server-common/src/main/java/im/turms/server/common/domain/admin/bo/AdminInfo.java` (rawPassword field), `turms-server-common/src/main/java/im/turms/server/common/domain/admin/service/BaseAdminService.java` (authenticate method, line 237), `loginNameToAdminInfo` cache, `idToAdminInfo` cache

## Attack Vector(s)
To exploit this vulnerability:
1. Attacker gains local system access to the server running Turms (through separate vulnerability, malicious insider, or compromised system)
2. Attacker generates a Java heap dump using tools like jmap, jcmd, or VisualVM: `jmap -dump:format=b,file=heap.bin <pid>`
3. Attacker analyzes the heap dump to locate `AdminInfo` objects
4. All administrator passwords are visible in plaintext in the `rawPassword` field
5. Attacker uses extracted passwords to gain full administrative access

Alternative vectors include debugger attachment in development environments or accidental serialization to logs.

## Suggested Description of the Vulnerability for Use in the CVE
Turms Server v0.10.0-SNAPSHOT and earlier contains a plaintext password storage vulnerability in the administrator authentication system. The `BaseAdminService` class caches administrator passwords in plaintext within `AdminInfo` objects to optimize authentication performance. Upon successful login, raw passwords are stored unencrypted in memory in the `rawPassword` field. Attackers with local system access can extract these passwords through memory dumps, heap analysis, or debugger attachment, bypassing bcrypt protection. This violates security best practices and compliance standards (PCI DSS, GDPR), as all administrator credentials remain exposed in memory until server restart. CVSS v3.1 Base Score: 6.5 (Medium) - AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N

## Discoverer(s)/Credits Info
s1ain

## Reference(s) Info
https://github.com/turms-im/turms
https://github.com/turms-im/turms/blob/develop/turms-server-common/src/main/java/im/turms/server/common/domain/admin/bo/AdminInfo.java#L34
https://github.com/turms-im/turms/blob/develop/turms-server-common/src/main/java/im/turms/server/common/domain/admin/service/BaseAdminService.java#L237
https://cwe.mitre.org/data/definitions/256.html
https://cwe.mitre.org/data/definitions/532.html

## Additional Information
- **Severity**: Medium-High (CVSS 6.5), but critical impact due to admin account exposure
- **CWE ID**: CWE-256 (Plaintext Storage of a Password), CWE-532 (Insertion of Sensitive Information into Log File)
- **Vulnerability Type**: Sensitive Data Exposure
- **Authentication Required**: System-level access required for exploitation
- **Attack Complexity**: Low
- **Disclosure Date**: 2025-11-02
- **Status**: Unpatched

**Special Considerations**:
- Violates PCI DSS Requirement 8.2.1 (passwords must be rendered unreadable during transmission and storage)
- Affects all administrator accounts in the system
- Password caching is implemented as a performance optimization but creates severe security risks
- Exploitation requires local access, but the impact is complete compromise of administrative credentials
- Recommended fix: Remove password caching and implement JWT token-based session management
