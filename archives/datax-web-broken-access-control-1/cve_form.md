# CVE Request Form - DataX-Web Broken Access Control

## Vulnerability Type Info
**Broken Access Control / Horizontal Privilege Escalation**

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
- [x] Other (Unauthorized data modification, task manipulation)
- [x] Escalation of Privileges

## Affected Component(s)
- datax-admin/src/main/java/com/wugui/datax/admin/controller/JobInfoController.java (remove method line 73, update method line 66, stop method line 79, start method line 85, triggerJob method line 96)
- datax-admin/src/main/java/com/wugui/datax/admin/service/impl/JobServiceImpl.java (remove, update, start, stop methods)
- All task management operations (/api/job/remove, /api/job/update, /api/job/start, /api/job/stop, /api/job/trigger)

## Attack Vector(s)
To exploit this vulnerability:

1. An attacker must have valid authentication credentials for DataX-Web as any regular user
2. The attacker identifies task IDs belonging to other users (via enumeration or information disclosure)
3. The attacker sends HTTP requests to task management endpoints with target task IDs
4. No authorization check is performed to verify if the attacker owns the task or has permission to access it
5. The operation succeeds, allowing the attacker to view, modify, delete, start, stop, or trigger other users' tasks

Example attack scenarios:

**Scenario 1 - Unauthorized Deletion:**
```bash
POST /api/job/remove/500
Authorization: Bearer <attacker_token>
```
Result: Task 500 (owned by another user) is deleted

**Scenario 2 - Data Exfiltration via Task Modification:**
```bash
POST /api/job/update
{
  "id": 500,
  "writerDatasourceId": 999  // Attacker's server
}
```
Result: Task now sends data to attacker's server

**Scenario 3 - Information Disclosure:**
```bash
GET /api/job/pageList
```
Result: Retrieve all tasks including sensitive configuration data

The vulnerability affects all CRUD operations on tasks, allowing complete horizontal privilege escalation between users.

## Suggested Description of the Vulnerability for Use in the CVE

A broken access control vulnerability exists in DataX-Web versions <= 2.1.2 that allows authenticated users to perform unauthorized operations on tasks belonging to other users. Although the application implements a permission checking mechanism via the `JobUser.validPermission()` method, this validation is not enforced in critical task management operations including task deletion, modification, starting, stopping, and triggering. An authenticated attacker can exploit this vulnerability by directly calling the affected API endpoints (`/api/job/remove/{id}`, `/api/job/update`, `/api/job/start`, `/api/job/stop`, `/api/job/trigger`) with task IDs belonging to other users. The vulnerability is located in the `JobInfoController` and `JobServiceImpl` classes where methods such as `remove()`, `update()`, `start()`, `stop()`, and `triggerJob()` fail to verify task ownership or user permissions before performing operations. This allows horizontal privilege escalation, enabling attackers to view sensitive task configurations (including database credentials), modify tasks to exfiltrate data to attacker-controlled servers, delete critical synchronization tasks causing denial of service, or trigger unauthorized task executions. The impact includes information disclosure, data manipulation, and service disruption.

CVSS 3.1 Score: 8.1 (High)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

## Discoverer(s)/Credits Info
**s1ain**

## Reference(s) Info
https://github.com/WeiYe-Jing/datax-web
https://github.com/WeiYe-Jing/datax-web/blob/master/datax-admin/src/main/java/com/wugui/datax/admin/controller/JobInfoController.java
https://github.com/WeiYe-Jing/datax-web/blob/master/datax-admin/src/main/java/com/wugui/datax/admin/service/impl/JobServiceImpl.java
https://github.com/WeiYe-Jing/datax-web/blob/master/datax-admin/src/main/java/com/wugui/datax/admin/entity/JobUser.java
https://owasp.org/Top10/A01_2021-Broken_Access_Control/

## Additional Information

### Root Cause Analysis

The vulnerability stems from incomplete implementation of the designed security model:

1. **Permission Model Exists But Not Enforced:**
   - The `JobUser` entity has a `validPermission(int jobGroup)` method
   - The method correctly checks if a user is an admin or has permission for a specific job group
   - However, this method is never called in task operation controllers

2. **Evidence of Abandoned Implementation:**
   ```java
   // JobLogController.java line 48 - Commented out permission check
   //JobInfoController.validPermission(request, jobGroup);
   // Comment: "Only admin can query all; regular users can only query permitted jobGroups"
   ```
   This suggests developers were aware of the need but didn't implement it.

3. **Missing Ownership Validation:**
   - Tasks have a `userId` field identifying the owner
   - Controllers never verify if `currentUserId == task.userId`
   - No check for admin role either

### Data Flow

1. User A creates Task 500 with `userId = 100`
2. User B (userId = 200) sends request: `POST /api/job/remove/500`
3. `JobInfoController.remove(500)` receives request
4. No permission check performed
5. `JobServiceImpl.remove(500)` directly deletes task
6. Task 500 is deleted without ownership validation

### Technical Details

**Permission Checking Mechanism (Designed):**
```java
public boolean validPermission(int jobGroup) {
    if ("1".equals(this.role)) {
        return true;  // Admin
    } else {
        // Check if jobGroup is in user's permission list
        for (String permissionItem : this.permission.split(",")) {
            if (String.valueOf(jobGroup).equals(permissionItem)) {
                return true;
            }
        }
        return false;
    }
}
```

**Vulnerable Implementation (Actual):**
```java
@PostMapping(value = "/remove/{id}")
public ReturnT<String> remove(@PathVariable(value = "id") int id) {
    // Missing: permission check
    // Missing: ownership verification
    return jobService.remove(id);
}
```

### Impact Assessment

- **Severity:** High (CVSS 8.1)
- **Exploitability:** High (requires only basic authentication)
- **Affected Operations:**
  - DELETE: Remove tasks
  - UPDATE: Modify task configuration
  - EXECUTE: Start/stop/trigger tasks
  - READ: View task details and configurations

### Real-World Attack Scenario

**Malicious Insider Attack:**
1. Employee B (regular user) wants to steal company data
2. Employee B enumerates tasks to find high-value data sync tasks
3. Employee B modifies Task 500 (owned by Employee A) to send data to external server
4. Employee B triggers task execution
5. Sensitive customer data is exfiltrated
6. Employee B deletes task to cover tracks

**Impact:**
- Data breach
- Compliance violations (GDPR, etc.)
- Business disruption
- No audit trail of unauthorized access

### Proof of Concept

Complete PoC available in detailed report including:
- Bash script for automated exploitation
- Multiple attack vectors (delete, modify, trigger)
- Evidence of successful unauthorized operations
- Information disclosure examples

### Known Affected Endpoints

| Endpoint | Method | Operation | Authorization Check |
|----------|--------|-----------|-------------------|
| /api/job/remove/{id} | POST | Delete task | ❌ None |
| /api/job/update | POST | Modify task | ❌ None |
| /api/job/start | POST | Start task | ❌ None |
| /api/job/stop | POST | Stop task | ❌ None |
| /api/job/trigger | POST | Execute task | ❌ None |
| /api/job/{id} | GET | View task | ❌ None |
| /api/job/pageList | GET | List tasks | ❌ None (lists all) |

### Recommended Remediation

**Immediate Actions (Critical):**

1. Implement permission checks in all controllers:
```java
if (!jobSecurityService.hasPermission(currentUserId, jobId, operation)) {
    return new ReturnT<>(FAIL_CODE, "Access denied");
}
```

2. Add ownership validation in service layer
3. Filter task listings by user permissions

**Long-term Improvements:**
1. Use AOP for centralized authorization
2. Implement comprehensive audit logging
3. Add unit tests for authorization checks
4. Conduct security code review of all controllers

### Testing Methodology

The vulnerability was discovered through:
1. Code review identifying missing authorization checks
2. Analysis of permission model implementation
3. Manual exploitation testing with multiple user accounts
4. Verification of successful unauthorized operations
5. Impact assessment through attack scenario simulation

### Similar Vulnerabilities

This broken access control pattern is similar to:
- OWASP Top 10 2021 - A01:Broken Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-284: Improper Access Control
- CWE-862: Missing Authorization
