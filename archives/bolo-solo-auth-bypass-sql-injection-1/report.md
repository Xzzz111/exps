# Vulnerability Report: Bolo Solo Fast Migration Authentication Bypass & SQL Injection

- **Submitter:** sh7err@vEcho
- **Product:** Bolo Solo (https://github.com/bolo-blog/bolo-solo)
- **Affected Versions:** <= 4.3.4 (latest master)
- **Vulnerability Type:** Authentication Bypass + SQL Injection
- **CWE:** CWE-306 (Missing Authentication for Critical Function), CWE-89 (SQL Injection)

## Summary
Bolo Solo exposes a "Fast Migration" HTTP endpoint intended to help administrators migrate Solo data. When the internal flag `UpgradeService.boloFastMigration` is true (which happens automatically after deployment while skins aren't fully configured), the public endpoint `/oauth/bolo/login` accepts any POST request and enters the migration path without authenticating the caller. Inside the migration routine (`OAuthProcessor.migrateLow`) the supplied `username` and `password` are directly concatenated into SQL statements executed via a plain `java.sql.Statement`. As a result, an unauthenticated remote attacker can both create or replace the administrator account and inject arbitrary SQL commands.

## Technical Details
- `UpgradeService.upgrade()` (`src/main/java/org/b3log/solo/service/UpgradeService.java:84-113`) automatically sets `UpgradeService.boloFastMigration = true` when no Bolo skin is configured yet.
- `OAuthProcessor.adminLogin()` (`src/main/java/org/b3log/solo/processor/OAuthProcessor.java:121-209`) handles `/oauth/bolo/login` POST requests. When `boloFastMigration` is true, it immediately calls `fastMigrate()` without verifying credentials or session state.
- `fastMigrate()` → `migrateLow()` executes SQL such as:
  ```java
  statement.executeUpdate("INSERT INTO `" + tablePrefix + "user` ... VALUES (..., '" + username + "', ..., '" + password + "', ...);");
  ```
  which is a textbook SQL injection sink because attacker-controlled `username` / `password` are concatenated into the query string.

Because the handler lacks any `@Before(ConsoleAuthAdvice.class)` or `Solos.isAdminLoggedIn` check, the endpoint is reachable by anyone while the flag is set.

## Impact
- Unauthenticated admin creation or takeover: attacker can set arbitrary credentials and log into `/admin-index.do`, gaining full control of the blog.
- Arbitrary SQL execution under the database account. Attackers can drop tables, create new records, or potentially escalate to remote code execution via database features.

## Proof of Concept
1. Deploy Bolo Solo (default settings) and stop before finishing skin configuration. Visiting `/start` shows the fast migration banner, meaning `boloFastMigration=true`.
2. Send the following HTTP request:
   ```http
   POST /oauth/bolo/login HTTP/1.1
   Host: victim.example
   Content-Type: application/x-www-form-urlencoded

   username=attacker&password=Passw0rd!
   ```
3. The server executes `migrateLow()`, deletes existing `adminRole` rows and inserts the attacker’s account. The attacker can now sign in at `/start` and reach `/admin-index.do` with the supplied credentials.
4. For SQL injection, send `username=test', 'x'); DROP TABLE b3_solo_user; --` as the username. The concatenated SQL drops the `user` table during migration.

## Mitigation
- Remove the network-exposed dependency on `boloFastMigration`. Fast migration should require prior authenticated administrator sessions or be limited to CLI tools.
- Replace raw `Statement` usage with parameterized `PreparedStatement` calls to prevent SQL injection.
- Require an explicit one-time token or configuration flag before exposing migration endpoints.

## References
- Source: `src/main/java/org/b3log/solo/processor/OAuthProcessor.java`
- Source: `src/main/java/org/b3log/solo/service/UpgradeService.java`

