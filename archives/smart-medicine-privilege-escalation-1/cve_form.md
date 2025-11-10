# CVE Request Form - Smart-Medicine Vertical Privilege Escalation

## Vulnerability Type Info
**Improper Access Control / Vertical Privilege Escalation**

## Vendor of the Product(s) Info
**Vendor Name**: XueWei (薛伟同学)

**Vendor Website**: http://xuewei.world

**Vendor Contact**: Available through GitHub repository

**Note**: This is an open-source educational project

## Affected Product(s)/Code Base Info

### Product: Smart-Medicine (智慧医药系统)

**Version(s) Affected**: All versions up to and including current release (commit cc3ec30)

**Version Status**: No fixed version available yet

**Source Repository**: https://github.com/xw213400/smart-medicine

**Programming Language**: Java (Spring Boot 2.6.7)

## Vendor Acknowledgment
**Has vendor confirmed or acknowledged the vulnerability?**
No (Not yet reported to vendor)

## Attack Type Info
**Remote**

## Impact Info
- [ ] Code Execution
- [x] Information Disclosure
- [x] Denial of Service
- [x] Escalation of Privileges (Primary Impact)
- [x] Other: Account Takeover, Administrative Lockout

## Affected Component(s)
```
src/main/java/world/xuewei/controller/UserController.java (lines 22-30, saveProfile method),
src/main/java/world/xuewei/service/UserService.java (lines 48-55, save method),
User entity automatic parameter binding (Spring MVC),
Role-based access control mechanism
```

## Attack Vector(s)
To exploit this vulnerability:

1. An attacker authenticates with any regular user account (roleStatus=0)
2. Attacker navigates to the profile update page or directly sends a POST request to `/user/saveProfile`
3. Attacker crafts a request with additional parameters:
   - `id=[target_user_id]` - To target any user account
   - `roleStatus=1` - To escalate privileges to administrator
4. Example exploitation: `curl -X POST "http://target/user/saveProfile" -H "Cookie: JSESSIONID=valid-session" -d "id=5&userName=attacker&roleStatus=1"`

The vulnerability exists because:
- The `saveProfile` method does not verify if the authenticated user's ID matches the submitted user ID
- Spring MVC automatically binds all HTTP parameters to the User object, including sensitive fields like `roleStatus`
- No filtering is applied to prevent modification of security-sensitive attributes

An attacker can modify any user account, escalate their own privileges to administrator, demote existing administrators, or take over accounts by changing email addresses.

## Suggested Description for CVE

**Title**: Vertical Privilege Escalation in Smart-Medicine System via Insecure Profile Update

**Description**:

Smart-Medicine (智慧医药系统) contains a critical vertical privilege escalation vulnerability in the user profile update functionality. The `saveProfile` method in `src/main/java/world/xuewei/controller/UserController.java` (lines 22-30) fails to validate whether the authenticated user is authorized to modify the target user account. The application accepts a user ID parameter without verifying it matches the current session user, and Spring MVC's automatic parameter binding allows modification of sensitive fields including `roleStatus` (privilege level). This enables any authenticated user to: (1) escalate their own privileges from regular user (roleStatus=0) to administrator (roleStatus=1), (2) modify arbitrary user accounts including administrators, (3) demote administrators to regular users causing administrative lockout, and (4) take over accounts by changing email addresses. The vulnerability is an Insecure Direct Object Reference (IDOR) combined with missing authorization checks. All versions up to and including the current release (commit cc3ec30) are affected.

**CVSS v3.1 Score**: 8.8 (High)

**CVSS v3.1 Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Discoverer(s)/Credits Info
**sh7err@vEcho**

## Reference(s) Info
https://github.com/xw213400/smart-medicine
https://github.com/xw213400/smart-medicine/blob/main/src/main/java/world/xuewei/controller/UserController.java
http://xuewei.world
https://cwe.mitre.org/data/definitions/639.html
https://cwe.mitre.org/data/definitions/862.html

## Additional Information

### Technical Background
This vulnerability represents a classic case of Broken Access Control (OWASP Top 10 2021 - A01). The application implements a role-based access control system where `roleStatus=0` indicates regular users and `roleStatus=1` indicates administrators. However, the profile update endpoint fails to enforce authorization checks, allowing privilege escalation.

### CWE Classifications
- **CWE-639**: Authorization Bypass Through User-Controlled Key
- **CWE-862**: Missing Authorization
- **CWE-284**: Improper Access Control

### Attack Complexity
- **Attack Complexity**: Low
- **Privileges Required**: Low (any authenticated user)
- **User Interaction**: None
- **Scope**: Unchanged
- **Network Access**: Required

### Real-World Impact Scenarios

1. **Privilege Escalation Chain**: Attacker gains administrative access → modifies medical data → injects malicious information → impacts patient safety

2. **Administrative Lockout**: Attacker demotes all administrators → system becomes unmanageable → requires database-level intervention to restore

3. **Account Takeover**: Attacker modifies victim's email → uses password reset → gains full account access

4. **Mass Compromise**: Automated scripts can modify all user accounts in bulk

### Verification Steps

The vulnerability was verified through:
1. Source code review identifying missing authorization checks
2. Data flow analysis confirming unrestricted parameter binding
3. Frontend code examination revealing intended user ID source
4. Proof of concept demonstrating successful privilege escalation

### Comparison with Authentication Bypass

This vulnerability is distinct from but can be combined with the authentication bypass vulnerability (separate CVE request). While the authentication bypass allows unauthenticated access to administrative functions, this vulnerability allows authenticated users to escalate their privileges within the system.

### Recommended Fix Priority
**Critical (P0)** - This vulnerability completely undermines the application's access control system and should be fixed immediately before any production deployment.

### Fix Verification
After implementing the recommended fix, verify:
1. Users can only modify their own profile (match `loginUser.getId()` with `user.getId()`)
2. Sensitive fields (`roleStatus`, `userAccount`, `id`) cannot be modified via profile update
3. Attempts to modify other users' profiles are rejected with appropriate error messages
4. Audit logs capture all profile modification attempts

---

**Submitter**: sh7err@vEcho

**Submission Date**: 2025-11-10

**Report Version**: 1.0
