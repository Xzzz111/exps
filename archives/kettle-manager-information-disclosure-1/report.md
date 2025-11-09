# kettle-manager Druid Console Weak Credential Information Disclosure

- **Submitter:** sh7err@vEcho
- **Product:** kettle-manager (数据大师 / sjds)
- **Affected Version:** 0.2.6-SNAPSHOT main branch (no fixed release)
- **Severity:** High (CVSS v3.1 Base Score 7.5 – AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

## Summary
The default configuration enables the Alibaba Druid monitoring console at `/sjsj-ht/druid/*` and hard-codes the management credentials to `jingma/jingma`. The whitelist parameter `allow` is empty, so the console accepts requests from any IP address. Consequently, anyone who can reach the HTTP port can sign in to the Druid console and obtain sensitive information such as SQL statements, database connection strings, runtime metrics, and thread stack traces.

## Technical Details
- **Files:** `src/main/resources/application.yaml:202-212`, `doc/docker/sjsj/conf/application-private.yaml:52-57`
- **Component:** Druid StatViewServlet configuration
- **Root Cause:** Monitoring servlet is exposed publicly with static credentials and no network restrictions.

## Proof of Concept
1. Deploy kettle-manager with default settings.
2. Browse to `http://<host>:8090/sjsj-ht/druid/login.html`.
3. Log in with username `jingma` and password `jingma`.
4. The console displays:
   - Complete lists of executed SQL statements (including parameter values)
   - Active database connection details (JDBC URLs, pool stats)
   - HTTP URI metrics and session details
   - Console actions allowing reset of statistics

## Impact
An unauthenticated attacker gains visibility into every query executed by the platform, including credentials, personally identifiable information, and business logic. The exposed data is sufficient to map the schema, harvest secrets, or craft targeted injection attacks against the underlying databases.

## Mitigation
- Disable the Druid StatView servlet in production by setting `stat-view-servlet.enabled=false`.
- If monitoring is required, restrict it to trusted networks via `allow`, reverse-proxy ACLs, or VPNs.
- Enforce unique, secret credentials through environment variables or a secret manager rather than embedding them in source control.

## References
- https://github.com/majinju/kettle-manager

