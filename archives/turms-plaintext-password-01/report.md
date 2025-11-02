# Turms Server - Admin Password Plaintext Caching Vulnerability

## NAME OF AFFECTED PRODUCT(S)

- **Product**: Turms - Open Source Instant Messaging Engine (Server Common Module)
- **Vendor Homepage**: https://github.com/turms-im/turms

## AFFECTED AND/OR FIXED VERSION(S)

- **Submitter**: s1ain
- **Affected Version(s)**: Turms v0.10.0-SNAPSHOT and earlier versions
- **Software Link**: https://github.com/turms-im/turms
- **Fixed Version**: Not fixed yet

## PROBLEM TYPE

- **Vulnerability Type**: CWE-256: Plaintext Storage of a Password / CWE-532: Insertion of Sensitive Information into Log File
- **Root Cause**: The `BaseAdminService` authentication mechanism caches administrator passwords in plaintext within the `AdminInfo` object to optimize performance. When authentication succeeds, the raw password is stored in memory without encryption or hashing.
- **Impact**:
  - Memory dump exposure - Passwords can be extracted from heap dumps, memory snapshots, or core dumps
  - Debugger access - Passwords readable through debugging tools in development/testing environments
  - Serialization risk - If cache is persisted, passwords may be written to disk
  - PCI DSS compliance violation - Storing plaintext passwords violates security standards
  - Privilege escalation - Compromised admin passwords grant full system control

## DESCRIPTION

A critical security vulnerability exists in Turms server's administrator authentication system. The `BaseAdminService` class caches administrator passwords in plaintext memory to avoid repeated bcrypt verification overhead. While the code uses bcrypt hashing for database storage, successful authentication results in the raw password being stored in the `AdminInfo` object's `rawPassword` field. This creates multiple attack vectors including memory dumps, process debugging, and potential cache serialization, exposing all administrator credentials to attackers with system access.

## Code Analysis

**Vulnerable Location 1**: `turms-server-common/src/main/java/im/turms/server/common/domain/admin/bo/AdminInfo.java:34`

**Vulnerable Code**:
```java
@Data
@AllArgsConstructor
public final class AdminInfo {
    private final Admin admin;
    private String rawPassword;  // ← Plaintext password stored in memory!
}
```

**Vulnerable Location 2**: `turms-server-common/src/main/java/im/turms/server/common/domain/admin/service/BaseAdminService.java:221-240`

**Vulnerable Code**:
```java
public Mono<Long> authenticate(
        @NotNull @NoWhitespace String loginName,
        @NotNull @NoWhitespace String rawPassword) {
    // ... validation code ...

    AdminInfo adminInfo = loginNameToAdminInfo.get(loginName);
    if (adminInfo != null) {
        String correctRawPassword = adminInfo.getRawPassword();
        // If the password doesn't match, it may happen due to the outdated cache,
        // so compare the input password with the one stored in MongoDB.
        if (correctRawPassword != null && correctRawPassword.equals(rawPassword)) {
            return Mono.just(adminInfo.getAdmin().getId());
        }
    }
    return queryAdminByLoginName(loginName).flatMap(admin -> {
        boolean isValidPassword =
                passwordManager.matchesAdminPassword(rawPassword, admin.getPassword());
        if (!isValidPassword) {
            return Mono.empty();
        }
        AdminInfo info = idToAdminInfo.get(admin.getId());
        if (info != null) {
            info.setRawPassword(rawPassword);  // ← Caching plaintext password!
        }
        return Mono.just(admin.getId());
    });
}
```

## Authentication Requirements

This is not an authentication bypass vulnerability. However, attackers with local system access (through other vulnerabilities, malicious insiders, or compromised servers) can extract administrator passwords without cracking hashes.

## Vulnerability Details and POC

**Vulnerability Type**: Sensitive Data Exposure - Plaintext Password Storage in Memory

**Vulnerability Location**:
- File 1: `turms-server-common/src/main/java/im/turms/server/common/domain/admin/bo/AdminInfo.java`
- Field: `rawPassword` at line 34
- File 2: `turms-server-common/src/main/java/im/turms/server/common/domain/admin/service/BaseAdminService.java`
- Method: `authenticate()` at lines 237
- Cache: `loginNameToAdminInfo` and `idToAdminInfo` maps

**Attack Scenario 1 - Memory Dump**:
```bash
# Attacker gains shell access to server
# Generate heap dump of running Turms process
jmap -dump:format=b,file=heap.bin <turms-pid>

# Extract AdminInfo objects from heap dump
jhat heap.bin
# Browse to http://localhost:7000 and search for AdminInfo instances
# All admin passwords visible in rawPassword field
```

**Attack Scenario 2 - Debugger Attachment**:
```bash
# In development/testing environment
jdb -attach localhost:5005

# Set breakpoint and inspect
stop in im.turms.server.common.domain.admin.service.BaseAdminService.authenticate
print adminInfo.rawPassword  # ← Plaintext password exposed
```

**Attack Scenario 3 - Log/Error Exposure**:
If logging frameworks accidentally serialize `AdminInfo` objects, passwords may appear in log files.

## Attack Results

Successful exploitation results in:
- Complete exposure of all administrator passwords
- No cryptographic protection - passwords are immediately usable
- Persistent exposure - passwords remain in memory until server restart
- Compliance violations - PCI DSS, GDPR, SOC 2 requirements breached
- Lateral movement - Compromised admin credentials enable full system takeover

## Suggested Repair

1. **Remove password caching entirely** (Recommended):
```java
public Mono<Long> authenticate(String loginName, String rawPassword) {
    return queryAdminByLoginName(loginName)
        .flatMap(admin -> {
            boolean isValid = passwordManager.matchesAdminPassword(
                rawPassword, admin.getPassword()
            );
            return isValid ? Mono.just(admin.getId()) : Mono.empty();
        });
}
```

2. **Alternative: Use short-lived JWT tokens** instead of password re-validation:
```java
// After first successful authentication, issue JWT token
String token = jwtService.generateToken(admin.getId(), Duration.ofHours(1));

// Subsequent requests validate token instead of password
public Mono<Long> authenticateWithToken(String token) {
    return jwtService.validateAndExtractUserId(token);
}
```

3. **Remove `rawPassword` field** from `AdminInfo` class:
```java
@Data
@AllArgsConstructor
public final class AdminInfo {
    private final Admin admin;
    // Remove: private String rawPassword;
}
```

4. **Security best practices**:
   - Never store passwords in plaintext, even in memory
   - Use secure session management (tokens, signed cookies)
   - Implement proper cache invalidation
   - Add security warnings in documentation

5. **Compliance alignment**:
   - Follow PCI DSS requirement 8.2.1 (render passwords unreadable)
   - Align with OWASP guidelines on password handling
   - Conduct security code review for similar patterns

## CVSS Score

**CVSS v3.1**: 6.5 (Medium-High)
- Attack Vector (AV): Local
- Attack Complexity (AC): Low
- Privileges Required (PR): High (system access)
- User Interaction (UI): None
- Scope (S): Unchanged
- Confidentiality (C): High
- Integrity (I): High
- Availability (A): None

**Vector String**: CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N

Note: While the base score is 6.5, the real-world impact is severe as it affects privileged administrator accounts and violates fundamental security principles and compliance requirements.
