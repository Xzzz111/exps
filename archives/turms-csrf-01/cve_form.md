# CVE Application Form - Turms Admin API CSRF Vulnerability

## Vulnerability Type Info
**Cross-Site Request Forgery (CSRF)**

## Vendor of the Product(s) Info
**Vendor**: Turms Project (turms-im)
**Vendor Homepage**: https://github.com/turms-im/turms

## Affected Product(s)/Code Base Info

| Product | Version |
|---------|---------|
| Turms Server (Admin API) | v0.10.0-SNAPSHOT and earlier |

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
- [x] Escalation of Privileges
- [x] Other: Unauthorized Administrative Actions

## Affected Component(s)
Admin API endpoints (entire administrative interface), specifically all state-changing operations including: admin account management (`/admin/api/admins`), user management (`/admin/api/users`), system settings (`/admin/api/settings`), plugin management (`/admin/api/plugins`)

## Attack Vector(s)
To exploit this vulnerability:
1. Attacker creates a malicious webpage containing hidden forms or JavaScript that performs administrative actions
2. Attacker tricks an authenticated Turms administrator into visiting the malicious page (via phishing email, social media link, compromised website, etc.)
3. When the admin visits the page, their browser automatically includes HTTP Basic Authentication credentials in cross-origin requests
4. The malicious page sends state-changing requests (POST/PUT/DELETE) to the Turms Admin API
5. Turms server accepts the requests because valid credentials are present and no CSRF token validation is performed
6. Unauthorized actions execute with the administrator's privileges (e.g., creating backdoor accounts, modifying users, installing plugins, changing settings)
7. Attacker gains persistent access or achieves other malicious objectives

## Suggested Description of the Vulnerability for Use in the CVE
Turms Server v0.10.0-SNAPSHOT and earlier contains a Cross-Site Request Forgery (CSRF) vulnerability in the Admin API. The administrative interface uses HTTP Basic Authentication without implementing CSRF tokens, SameSite cookie attributes, or custom header requirements. State-changing operations (POST, PUT, DELETE) on admin endpoints can be triggered by malicious websites while an administrator is authenticated. An attacker can craft a malicious webpage that, when visited by an authenticated administrator, performs unauthorized administrative actions such as creating backdoor administrator accounts, modifying or deleting user accounts, changing system configurations, or installing malicious plugins. Browser automatically includes Basic Auth credentials in cross-origin requests, and the server does not validate anti-CSRF tokens. CVSS v3.1 Base Score: 6.1 (Medium) - AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N

## Discoverer(s)/Credits Info
s1ain

## Reference(s) Info
https://github.com/turms-im/turms
https://cwe.mitre.org/data/definitions/352.html
https://owasp.org/www-community/attacks/csrf
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Additional Information
- **Severity**: Medium (CVSS 6.1), but high impact potential for administrative compromise
- **CWE ID**: CWE-352 (Cross-Site Request Forgery)
- **Vulnerability Type**: CSRF / Broken Access Control
- **Authentication Required**: Victim must be authenticated administrator; attacker needs no authentication
- **Attack Complexity**: Low (simple HTML/JavaScript)
- **Disclosure Date**: 2025-11-02
- **Status**: Unpatched

**Attack Scenarios**:
1. **Backdoor Account Creation**: Create new admin account with attacker-controlled credentials
2. **Privilege Escalation**: Elevate existing low-privilege account to administrator
3. **Mass User Deletion**: Delete user accounts causing service disruption
4. **Configuration Tampering**: Modify security settings, disable protections
5. **Malicious Plugin Installation**: Install plugins containing backdoors or malware

**Recommended Fixes**:
1. Implement CSRF token validation for all state-changing operations
2. Use SameSite=Strict or SameSite=Lax cookie attributes (if switching to cookie-based auth)
3. Require custom HTTP headers (e.g., X-Turms-Admin-API) that cannot be sent from forms
4. Implement double-submit cookie pattern
5. Consider migrating from HTTP Basic Auth to JWT tokens with proper CSRF protection
6. Add re-authentication requirement for critical operations

**Why Basic Auth is Vulnerable to CSRF**:
- Unlike session cookies, Basic Auth credentials are automatically sent by browsers on ALL requests to the domain
- No way to set SameSite attribute on Authorization header
- Cannot be protected by standard CSRF token mechanisms alone
- Credentials persist across browser tabs and windows
