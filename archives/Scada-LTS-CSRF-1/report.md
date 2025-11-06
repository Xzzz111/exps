# Security Vulnerability Report: Scada-LTS Missing CSRF Protection

**Submitter:** sh7err@vEcho  
**Tested revision:** commit 1cfaed4b35117e4871bc3dfeae073f61d8e3bb3d (branch: develop)

## Summary

Scada-LTS disables Spring Security's Cross-Site Request Forgery (CSRF) protection on every web context, leaving numerous state-changing interfaces exposed to CSRF attacks. Any attacker-controlled web page can trigger authenticated browsers to execute POST/PUT/DELETE requests against endpoints such as `/api/watch-lists` or `/api/reports/save`, causing unauthorized state modifications under the victim's account.

## Product & Versions

- **Product:** Scada-LTS (https://github.com/SCADA-LTS/Scada-LTS)  
- **Affected versions:** all releases prior to and including commit 1cfaed4b35117e4871bc3dfeae073f61d8e3bb3d  
- **Fixed version:** _Not yet fixed_

## Vulnerability Details

### Root Cause Analysis

- `WebContent/WEB-INF/spring-security.xml` configures each `<http>` block with `<csrf disabled="true"/>` (lines 18, 42, 65, 88, 111, 134).
- The same configuration grants regular authenticated users (`ROLE_USER`) the ability to POST/PUT/DELETE to REST endpoints, e.g. `/api/watch-lists` (lines 345-352) and `/api/reports/save` (line 363).
- There is no alternative CSRF mitigation (e.g., double-submit tokens, SameSite enforcement, per-request nonce) in the codebase; the REST endpoints rely solely on the existing session cookie for authentication.

### Proof of Concept

1. Victim signs in to Scada-LTS Web UI in browser A and remains logged in.
2. Victim visits attacker-controlled page in another tab. The page contains:

   ```html
   <form action="https://victim-host/api/watch-lists" method="POST">
     <input type="hidden" name="name" value="CSRF_Pwned" />
     <input type="hidden" name="xid" value="WL_PWNED" />
   </form>
   <script>document.forms[0].submit();</script>
   ```

3. Because CSRF protection is disabled, the browser automatically includes the victim's `JSESSIONID`. Scada-LTS creates a new watch list owned by the victim without their consent.

Similar payloads can manipulate reports, user settings, or any other session-authenticated REST action.

### Impact

- Unauthorized creation, modification, or deletion of watch lists, reports, system settings, etc.
- Potential privilege escalation if combined with other vulnerabilities (e.g., replacing scripts executed by admins).
- Undermines auditability and trust of operator actions.

## Remediation Guidance

1. Re-enable Spring Security CSRF protection for session-based interfaces (remove `<csrf disabled="true"/>` or set it to enabled).
2. For API clients that cannot support cookies/CSRF tokens, expose dedicated stateless endpoints (e.g., via HTTP Basic or token-based authentication) while keeping CSRF enabled for browser-based traffic.
3. Consider enforcing SameSite cookies and adding per-request nonces as defense-in-depth.

## Disclosure Timeline

- 2024-XX-XX: Vulnerability discovered during source audit.
- 2024-XX-XX: Vendor notification (_pending_).
- 2024-XX-XX: Requested CVE ID.

## Credits

Discovered by sh7err@vEcho.

