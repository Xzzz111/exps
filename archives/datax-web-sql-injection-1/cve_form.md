# CVE Request Form - DataX-Web SQL Injection

## Vulnerability Type Info
**SQL Injection**

## Vendor of the Product(s) Info
**WeiYe-Jing**

GitHub: https://github.com/WeiYe-Jing

## Affected Product(s)/Code Base Info

| Product | Version |
|---------|---------|
| DataX-Web | <= 2.1.2 |

**Fixed Version:** Not yet fixed

## Has Vendor Confirmed or Acknowledged the Vulnerability?
**No**

## Attack Type Info
**Remote**

## Impact Info
- [ ] Code Execution
- [x] Information Disclosure
- [ ] Denial of Service
- [ ] Other
- [ ] Escalation of Privileges

## Affected Component(s)
- datax-admin/src/main/java/com/wugui/datax/admin/tool/meta/BaseDatabaseMeta.java (getMaxId method, lines 44-45; getSQLQueryFields method, lines 14-15)
- datax-admin/src/main/java/com/wugui/datax/admin/tool/query/BaseQueryTool.java (getMaxIdVal method, lines 453-454)
- datax-admin/src/main/java/com/wugui/datax/admin/core/trigger/JobTrigger.java (getMaxId method, line 227)
- JobInfo.readerTable field
- JobInfo.primaryKey field

## Attack Vector(s)
To exploit this vulnerability:

1. An attacker must have valid authentication credentials for DataX-Web (any user role, admin privileges not required)
2. The attacker creates a new data synchronization task via the `/api/job/add` API endpoint
3. The attacker sets `incrementType` to 1 (ID-based incremental synchronization)
4. The attacker injects malicious SQL code into the `readerTable` or `primaryKey` parameters
5. The attacker triggers the task execution via `/api/job/trigger` or waits for scheduled execution
6. The injected SQL is executed against the configured data source database

Example malicious payloads:
- readerTable: `users WHERE 1=1 UNION SELECT password FROM admin_users--`
- primaryKey: `id) FROM users UNION SELECT password FROM admin_users WHERE (1=1`

The vulnerability can be exploited using various SQL injection techniques including:
- UNION-based injection
- Boolean-based blind injection
- Time-based blind injection
- Error-based injection

## Suggested Description of the Vulnerability for Use in the CVE

A SQL injection vulnerability exists in DataX-Web versions <= 2.1.2 in the incremental data synchronization feature. The vulnerability is located in the query construction methods where user-supplied table names and column names from the `readerTable` and `primaryKey` fields are directly concatenated into SQL queries without proper validation or sanitization. When an authenticated user creates an incremental synchronization task with `incrementType` set to 1 (ID-based), the application constructs SQL queries using `String.format()` in the `getMaxId()` method of `BaseDatabaseMeta.java`, which directly incorporates these user-controlled values. The resulting SQL query is then executed via `Statement.executeQuery()` without parameterization in `BaseQueryTool.java`. An attacker can inject arbitrary SQL commands through the `/api/job/add` endpoint, allowing them to extract sensitive data, modify database records, or execute administrative database commands depending on the configured data source privileges. The vulnerability affects the `getMaxId()` and `getSQLQueryFields()` methods and can be exploited using UNION-based, error-based, or time-based blind SQL injection techniques.

CVSS 3.1 Score: 9.1 (Critical)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

## Discoverer(s)/Credits Info
**s1ain**

## Reference(s) Info
https://github.com/WeiYe-Jing/datax-web
https://github.com/WeiYe-Jing/datax-web/blob/master/datax-admin/src/main/java/com/wugui/datax/admin/tool/meta/BaseDatabaseMeta.java
https://github.com/WeiYe-Jing/datax-web/blob/master/datax-admin/src/main/java/com/wugui/datax/admin/tool/query/BaseQueryTool.java
https://github.com/WeiYe-Jing/datax-web/blob/master/datax-admin/src/main/java/com/wugui/datax/admin/core/trigger/JobTrigger.java
https://owasp.org/www-community/attacks/SQL_Injection

## Additional Information

### Root Cause Analysis
The vulnerability stems from three main issues:

1. **Lack of Input Validation:** The `readerTable` and `primaryKey` fields are String types that accept arbitrary user input without any format validation or sanitization.

2. **Unsafe SQL Construction:** The `BaseDatabaseMeta.getMaxId()` method uses `String.format()` to directly concatenate user input into SQL:
   ```java
   return String.format("select max(%s) from %s", primaryKey, tableName);
   ```

3. **Non-Parameterized Execution:** The constructed SQL is executed using `Statement.executeQuery()` instead of `PreparedStatement`, making it vulnerable to SQL injection.

### Data Flow
1. User submits task creation request to `/api/job/add` with malicious `readerTable` or `primaryKey`
2. `JobServiceImpl.add()` saves the values to database without validation
3. When task executes, `JobTrigger.getMaxId()` retrieves these values
4. `BaseQueryTool.getMaxIdVal()` calls `BaseDatabaseMeta.getMaxId()` to construct SQL
5. Malicious SQL is executed against the data source via `Statement.executeQuery()`

### Technical Details

**Vulnerable Code Example:**
```java
// BaseDatabaseMeta.java
public String getMaxId(String tableName, String primaryKey) {
    // Direct string formatting - VULNERABLE
    return String.format("select max(%s) from %s", primaryKey, tableName);
}

// BaseQueryTool.java
public long getMaxIdVal(String tableName, String primaryKey) {
    String sql = this.databaseInterface.getMaxId(tableName, primaryKey);
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(sql); // Executes injected SQL
    // ...
}
```

**Attack Scenario:**
```json
POST /api/job/add
{
  "incrementType": 1,
  "readerTable": "users WHERE 1=0 UNION SELECT password,username,email FROM admin_users--",
  "primaryKey": "id"
}
```

**Generated SQL:**
```sql
SELECT MAX(id) FROM users WHERE 1=0 UNION SELECT password,username,email FROM admin_users-- where 1=0
```

### Impact Assessment
- **Severity:** Critical (CVSS 9.1)
- **Exploitability:** High (requires only basic authentication)
- **Data at Risk:**
  - All data in configured data sources
  - Database credentials stored in job_jdbc_datasource table
  - User credentials in job_user table
  - Business-critical data being synchronized

### Proof of Concept
A complete proof of concept is available in the detailed vulnerability report, including:
- Multiple injection techniques (UNION, error-based, time-based blind)
- Sqlmap automation examples
- Manual exploitation steps
- Data exfiltration examples

### Known Limitations
Unlike typical SQL injection vulnerabilities, table and column names cannot be parameterized using `PreparedStatement` in standard SQL. This means the fix requires:
1. Strict whitelist validation (alphanumeric and underscore only)
2. Identifier escaping (using backticks or quotes)
3. Database metadata verification
4. Input length restrictions

### Recommended Remediation
1. **Immediate:** Implement strict input validation with regex `^[a-zA-Z_][a-zA-Z0-9_]{0,63}$`
2. **Immediate:** Add identifier escaping for table and column names
3. **Short-term:** Validate against actual database metadata
4. **Long-term:** Implement least-privilege database access
5. **Long-term:** Add comprehensive audit logging

### Similar Vulnerabilities
This class of SQL injection affecting table/column names is similar to:
- CVE-2021-27928 (MariaDB Connector/J)
- CVE-2020-9484 (Apache Tomcat)
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command

### Testing Methodology
The vulnerability was discovered through:
1. Manual code review of SQL construction methods
2. Data flow analysis from user input to SQL execution
3. Manual exploitation testing with various SQL injection payloads
4. Verification with sqlmap automated tool
