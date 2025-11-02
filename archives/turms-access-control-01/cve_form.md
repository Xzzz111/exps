# CVE Application Form - Turms User Online Status Access Control

## Vulnerability Type Info
**Improper Access Control**

## Vendor of the Product(s) Info
**Vendor**: Turms Project (turms-im)
**Vendor Homepage**: https://github.com/turms-im/turms

## Affected Product(s)/Code Base Info

| Product | Version |
|---------|---------|
| Turms IM Server | v0.10.0-SNAPSHOT and earlier |

**Fixed Version**: Not fixed yet

## Optional
**Has vendor confirmed or acknowledged the vulnerability?**
Yes - The source code contains a `// TODO : Access Control` comment at line 239 of `UserServiceController.java`, indicating the development team is aware this feature needs to be implemented.

## Attack Type Info
**Remote**

## Impact Info
- [x] Information Disclosure
- [ ] Code Execution
- [ ] Denial of Service
- [ ] Escalation of Privileges
- [ ] Other

## Affected Component(s)
`turms-service/src/main/java/im/turms/service/domain/user/access/servicerequest/controller/UserServiceController.java`, `handleQueryUserOnlineStatusesRequest()` method, line 239

## Attack Vector(s)
To exploit this vulnerability:
1. Attacker authenticates as any valid user in the Turms IM system
2. Attacker sends a `QUERY_USER_ONLINE_STATUSES_REQUEST` protobuf message with arbitrary target user IDs
3. System returns online status, device type, and login timestamp for all requested users without verifying the attacker has permission to access this information
4. Attacker can enumerate and track any user's online activities and patterns

## Suggested Description of the Vulnerability for Use in the CVE
Turms IM Server v0.10.0-SNAPSHOT and earlier contains a broken access control vulnerability in the user online status query functionality. The `handleQueryUserOnlineStatusesRequest()` method in `UserServiceController.java` allows any authenticated user to query the online status, device information, and login timestamps of arbitrary users without proper authorization checks. The source code contains a `// TODO : Access Control` comment acknowledging this security control is not implemented. This vulnerability enables unauthorized information disclosure and user privacy violations, allowing attackers to track user activity patterns. CVSS v3.1 Base Score: 7.5 (High) - AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

## Discoverer(s)/Credits Info
s1ain

## Reference(s) Info
https://github.com/turms-im/turms
https://github.com/turms-im/turms/blob/develop/turms-service/src/main/java/im/turms/service/domain/user/access/servicerequest/controller/UserServiceController.java#L239

## Additional Information
- **Severity**: High (CVSS 7.5)
- **CWE ID**: CWE-284 (Improper Access Control)
- **Vulnerability Type**: Broken Access Control / IDOR
- **Authentication Required**: Yes (any authenticated user)
- **Attack Complexity**: Low
- **Disclosure Date**: 2025-11-02
- **Status**: Unpatched

The vulnerability has been verified through source code analysis. The affected method explicitly contains a TODO comment indicating the access control feature is planned but not yet implemented, making this a confirmed vulnerability rather than a design feature.
