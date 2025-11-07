# Vulnerability Report – SQL Injection in OWASP Benchmark for Java

## Submitter
- sh7err@vEcho

## Summary
The servlet `BenchmarkTest00018`, reachable at `/sqli-00/BenchmarkTest00018`, builds an INSERT statement by concatenating the value of a user-controlled HTTP header directly into the SQL string. Because the statement is executed via `java.sql.Statement` without parameterization, a remote attacker can inject arbitrary SQL commands in the context of the Benchmark database, enabling data tampering or further compromise.

## Product Information
- **Vendor:** OWASP Foundation
- **Product:** OWASP Benchmark for Java
- **Version:** 1.2 (latest master)
- **Environment:** Default Derby database initialized by `DatabaseHelper`

## Vulnerability Details
- **Vulnerability Type:** SQL Injection (CWE-89)
- **Attack Surface:** HTTP POST/GET endpoint `/sqli-00/BenchmarkTest00018`
- **Affected Component:** `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00018.java` (`doPost` method)

### Technical Description
`BenchmarkTest00018` reads the first value of the header `BenchmarkTest00018`, URL-decodes it, and interpolates it inside an INSERT statement:
```java
String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";
Statement statement = DatabaseHelper.getSqlStatement();
statement.executeUpdate(sql);
```
No validation or escaping is performed. Any single quote that the attacker inserts closes the literal and allows arbitrary SQL to run with the privileges of the application account.

### Proof of Concept
```
curl -i -X POST \
     -H "BenchmarkTest00018=abc'),('attacker','pwn" \
     http://<host>:8080/benchmark/sqli-00/BenchmarkTest00018
```
The injected payload adds a new row `(attacker, pwn)` to the `users` table. A destructive payload such as `foo'); DROP TABLE USERS;--` will drop application tables.

### Impact
Attackers can create, modify, or delete data inside the Benchmark database, potentially chaining the issue into authentication bypass, persistence, or data disclosure. Depending on the backing DBMS, SQL injection may also lead to command execution via database-specific features.

### Suggested Mitigations
1. Replace raw string concatenation with `PreparedStatement` parameters and bind user input via `setString`.
2. Apply strict validation to the custom header and reject unexpected characters.
3. Isolate database credentials with the minimum privileges required and disable ad-hoc INSERT/DDL permissions for web-facing accounts.

### Additional Notes
This servlet exists to demonstrate how SQL injection scanners behave. It must not be shipped unchanged in production deployments of OWASP Benchmark or derivative projects.
