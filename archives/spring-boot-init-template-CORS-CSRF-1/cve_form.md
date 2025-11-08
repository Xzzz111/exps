# CVE Request Form – spring-boot-init-template CORS Credential Theft

**Vulnerability type info**: Improper Access Control / CORS Misconfiguration (CWE-346)

**Vendor of the product(s) info**: AntonyCheng (spring-boot-init-template project maintainer)

**Affected product(s)/code base info**:
- Product: spring-boot-init-template
- Version: v2.2.1-jdk17-pre (latest main branch). No fixed version is available.

**Has vendor confirmed or acknowledged the vulnerability**: No

**Attack type info**: Remote

**Impact info**: Information Disclosure, Other (Cross-Site Request Forgery and unauthorized state changes)

**Affected component(s)**: `src/main/java/top/sharehome/springbootinittemplate/config/cors/CorsConfiguration.java`

**Attack vector(s)**: An attacker-controlled website can issue cross-origin fetch/XHR requests while the victim is logged in. Because the server reflects any Origin and allows credentials, the browser returns the privileged JSON response to the attacker page, enabling authenticated API calls from another domain.

**Suggested description of the vulnerability for use in the CVE info**:
`spring-boot-init-template v2.2.1-jdk17-pre ships with a global CORS configuration that combines allowCredentials(true) with a wildcard Origin. Any external website can therefore send authenticated requests and read the responses of protected endpoints when a user is logged in, leading to information disclosure and cross-site request forgery.`

**Discoverer(s)/Credits info**: sh7err@vEcho

**Reference(s) info**:
https://github.com/AntonyCheng/spring-boot-init-template

**Additional information**: The issue affects default deployments; no optional modules or configuration toggles mitigate it.

