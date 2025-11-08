# Vulnerability Report – Cross-Origin Credential Theft in spring-boot-init-template

## Summary
The Spring Boot reference project `spring-boot-init-template` (version v2.2.1-jdk17-pre, latest commit at the time of testing) ships with a global CORS configuration that simultaneously allows credentials and accepts any Origin. When a victim is logged in, any third-party website can issue authenticated cross-origin requests and read the JSON responses, which results in a complete breakdown of the intended access control. The flaw is exploitable with nothing more than a crafted JavaScript snippet on an attacker-controlled web page.

- **Submitter**: sh7err@vEcho
- **CWE**: CWE-346 – Origin Validation Error
- **Severity**: High

## Product & Component
- **Product**: spring-boot-init-template
- **Version**: v2.2.1-jdk17-pre (GitHub main branch, commit `HEAD` as of audit)
- **Component**: `src/main/java/top/sharehome/springbootinittemplate/config/cors/CorsConfiguration.java`

```java
registry.addMapping("/**")
        .allowCredentials(true)
        .allowedOriginPatterns("*")
        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
        .allowedHeaders("*")
        .exposedHeaders("*");
```

No other module introduces CSRF tokens, SameSite restrictions, referer validation or Origin whitelisting, therefore this configuration governs the entire API surface.

## Technical Details
1. Any browser sends the Origin header automatically. The configuration above always reflects that Origin value and sets `Access-Control-Allow-Credentials: true`.
2. When a logged-in user visits an attacker-controlled page, the page can run the following script:

```javascript
fetch('http://<target-host>/api/auth/info', {
  method: 'GET',
  credentials: 'include'
}).then(r => r.json()).then(console.log)
```

3. The browser includes the valid Sa-Token cookie. Because the response also carries `Access-Control-Allow-Origin: <attacker>` and `Access-Control-Allow-Credentials: true`, the browser hands the JSON body back to the attacker page.
4. The attacker can call any privileged endpoint (for example `/user/update/email`, `/model/delete/{id}`, etc.), exfiltrate data, and trigger state-changing requests, all without user interaction beyond visiting the malicious site.

## Impact
- Full disclosure of authenticated API responses (user profile, system configuration, etc.).
- Cross-site request forgery against every protected endpoint, enabling account takeover, data tampering, or administrative actions.
- The issue affects default deployments because the configuration is active in the template out of the box.

## Proof of Concept
1. Start the backend with default settings and log in via `/auth/login`.
2. Host the JavaScript snippet shown above on any external domain.
3. While still logged in, visit the malicious page; observe that the browser console prints the JSON payload returned by `/auth/info`, confirming credential leakage.

## Remediation
- Replace `allowedOriginPatterns("*")` with an explicit list of trusted domains or disable global CORS entirely when not required.
- Do not combine `allowCredentials(true)` with wildcard origins; alternatively switch to token-only authentication for cross-origin clients and enforce `Allow-Credentials: false`.
- Add CSRF defenses (synchronizer tokens, SameSite cookies, strict Origin validation) for state-changing endpoints.

## References
- Project repository: https://github.com/AntonyCheng/spring-boot-init-template

