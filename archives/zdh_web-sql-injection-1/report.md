# SQL Injection in zdh_web data_ware_house_list6

- **Submitter:** sh7err@vEcho
- **Project:** zdh_web (github.com/zhaoyachao/zdh_web)
- **Tested Version:** master @ `63125e22e7afa0e1649d0d154562823b5fd4c5c9`
- **Vulnerability Class:** SQL Injection

## Summary
The endpoint `POST /data_ware_house_list6` accepts the parameter `label_params`, which is intended to hold a comma-separated list of label names. The controller passes the user-supplied strings directly to `IssueDataMapper.selectByParams`, where they are interpolated into a `FIND_IN_SET('${label_name}', label_params)` clause using MyBatis `${}` substitution. Because `${}` performs raw string expansion, an attacker can break out of the quoted string and inject arbitrary SQL conditions.

## Technical Details
1. `ZdhDataWareController.data_ware_house_list6` splits the attacker-controlled `label_params` string but performs no sanitization or validation.
2. `IssueDataMapper.selectByParams` iterates over each label and emits `FIND_IN_SET('${label_name}', label_params)`.
3. The `${label_name}` placeholder is replaced verbatim, allowing payloads such as `test'),1=1#` to terminate the expression and append new Boolean logic.

Relevant code excerpts:
- `src/main/java/com/zyc/zdh/controller/ZdhDataWareController.java`, lines 70-140.
- `src/main/java/com/zyc/zdh/dao/IssueDataMapper.java`, lines 40-58.

## Proof of Concept
```
POST /data_ware_house_list6 HTTP/1.1
Host: <zdh_host>
Content-Type: application/x-www-form-urlencoded
Cookie: ZDHSESIONID=<valid session>

product_code=demo&current_page=1&page_size=10&label_params=test'),1=1#
```
The injected label forces the mapper to generate `FIND_IN_SET('test'),1=1#, label_params)`; the trailing portion of the original statement is commented out, and the WHERE clause simplifies to `... AND 1=1`, returning every published dataset regardless of the user’s product- or label-level permissions. More complex payloads can be used to union arbitrary data or stack additional queries (depending on the database configuration).

## Impact
Any authenticated user who can call `/data_ware_house_list6` can perform SQL injection against the metadata database. This allows the attacker to bypass product and dimension filters, exfiltrate data from other tenants, or potentially modify records if stacked queries are permitted by the JDBC driver.

## Suggested Remediation
1. Replace `${label_name}` with `#{label_name}` and restructure the query to use parameter binding instead of raw string interpolation. When `FIND_IN_SET` is required, wrap it in a helper expression such as `FIND_IN_SET(#{label_name}, label_params)`.
2. Strictly validate `label_params` against an allowlist of alphanumeric characters before constructing the query.
3. Consider normalizing labels into a separate relation to eliminate the need for dynamic SQL entirely.

## Timeline
- 2025-02-14 – Vulnerability discovered during code audit.

## References
- https://github.com/zhaoyachao/zdh_web/blob/63125e22e7afa0e1649d0d154562823b5fd4c5c9/src/main/java/com/zyc/zdh/dao/IssueDataMapper.java
