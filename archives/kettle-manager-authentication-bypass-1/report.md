# kettle-manager Default Administrative Credentials Vulnerability

- **Submitter:** sh7err@vEcho
- **Product:** kettle-manager (a.k.a. 数据大师 / sjds)
- **Affected Version:** 0.2.6-SNAPSHOT main branch (latest commit, no patch available)
- **Severity:** Critical (CVSS v3.1 Base Score 9.8 – AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

## Summary
kettle-manager ships with Spring Security enabled and hard-coded credentials (`jingma/jingma`) in `src/main/resources/application.yaml`. Because this configuration is packaged with the application and also reused verbatim in the provided Docker deployment files, every default deployment exposes an administrator-level account that is publicly documented in the source repository. Any unauthenticated user who can reach the HTTP service can log in with this account and obtain full administrative access.

## Technical Details
- **Files:** `src/main/resources/application.yaml:111-120`, `doc/docker/sjsj/conf/application-private.yaml:48-57`
- **Component:** Spring Boot default security configuration
- **Root Cause:** Hard-coded username/password inside the default configuration with no environment-specific override or randomization.

## Proof of Concept
1. Deploy kettle-manager with the provided configuration (defaults: `server.port=8090`, `server.servlet.context-path=/sjsj-ht`).
2. Send any request to a protected endpoint, e.g.:
   ```bash
   curl -i http://<host>:8090/sjsj-ht/custom/demo/select
   ```
   The server challenges with HTTP Basic authentication.
3. Re-issue the request using the documented default credentials:
   ```bash
   curl -i -u jingma:jingma http://<host>:8090/sjsj-ht/custom/demo/select
   ```
4. The request now succeeds and the attacker can invoke any administrative API, upload jobs, or operate the entire platform without further restrictions.

## Impact
Anyone on the network can trivially obtain full administrator privileges. This allows reading/modifying all managed datasets, triggering jobs, changing credentials, and potentially pivoting to connected Kettle repositories or databases. Because the credentials are public and unavoidable in a stock deployment, the vulnerability is exploitable immediately after installation.

## Mitigation
- Remove the hard-coded `spring.security.user.*` settings from all default configuration files.
- Force operators to supply strong credentials via environment variables, external secrets management, or an actual user store.
- Provide tooling to generate unique admin accounts during installation, and document the need to rotate existing deployments.

## References
- https://github.com/majinju/kettle-manager (upstream project)

