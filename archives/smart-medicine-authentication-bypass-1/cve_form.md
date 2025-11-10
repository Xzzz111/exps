# CVE Request Form - Smart-Medicine Authentication Bypass

## Vulnerability Type Info
**Broken Authentication**

## Vendor of the Product(s) Info
**Vendor Name**: XueWei (薛伟同学)

**Vendor Website**: http://xuewei.world

**Vendor Contact**: Available through GitHub repository

**Note**: This is an open-source educational project

## Affected Product(s)/Code Base Info

### Product: Smart-Medicine (智慧医药系统)

**Version(s) Affected**: All versions up to and including current release (commit cc3ec30)

**Version Status**: No fixed version available yet

**Source Repository**: https://github.com/xw213400/smart-medicine

**Programming Language**: Java (Spring Boot 2.6.7)

## Vendor Acknowledgment
**Has vendor confirmed or acknowledged the vulnerability?**
No (Not yet reported to vendor)

## Attack Type Info
**Remote**

## Impact Info
- [x] Code Execution (Indirect - through data manipulation)
- [x] Information Disclosure
- [x] Denial of Service
- [x] Escalation of Privileges
- [x] Other: Data Integrity Compromise, Financial Loss (API abuse)

## Affected Component(s)
```
src/main/java/world/xuewei/config/MvcConfig.java (lines 48-61),
src/main/java/world/xuewei/controller/BaseController.java (lines 77, 93),
src/main/java/world/xuewei/controller/IllnessController.java,
src/main/java/world/xuewei/controller/MedicineController.java,
src/main/java/world/xuewei/controller/FeedbackController.java,
src/main/java/world/xuewei/controller/IllnessKindController.java,
src/main/java/world/xuewei/controller/IllnessMedicineController.java,
LoginHandlerInterceptor (disabled)
```

## Attack Vector(s)
To exploit this vulnerability:

1. An attacker sends an unauthenticated HTTP POST request to any administrative endpoint
2. No credentials or authentication tokens are required
3. The attack can be performed remotely over the network
4. Example: `curl -X POST "http://target/illness/delete" -d "id=1"`

The vulnerability exists because the authentication interceptor is completely commented out in the source code (`MvcConfig.java` lines 48-61), allowing direct access to all protected endpoints without any authentication checks.

## Suggested Description for CVE

**Title**: Authentication Bypass in Smart-Medicine System

**Description**:

Smart-Medicine (智慧医药系统) contains a critical authentication bypass vulnerability due to the login interceptor being completely disabled in the source code. The `addInterceptors()` method in `src/main/java/world/xuewei/config/MvcConfig.java` (lines 48-61) is entirely commented out, which disables all authentication checks throughout the application. This allows remote unauthenticated attackers to directly access administrative functions including creating, modifying, or deleting disease records, medicine information, and system configurations without any credentials. The vulnerability also enables abuse of integrated AI API services, potentially causing significant financial damage. All versions up to and including the current release (commit cc3ec30) are affected.

**CVSS v3.1 Score**: 9.1 (Critical)

**CVSS v3.1 Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

## Discoverer(s)/Credits Info
**sh7err@vEcho**

## Reference(s) Info
https://github.com/xw213400/smart-medicine
https://github.com/xw213400/smart-medicine/blob/main/src/main/java/world/xuewei/config/MvcConfig.java
http://xuewei.world

## Additional Information

### Technical Background
This is an educational/demonstration project based on Spring Boot framework. The vulnerability appears to be a development oversight where the authentication interceptor was disabled (commented out) and never re-enabled for production deployment.

### Real-World Impact
Despite being an educational project, this vulnerability demonstrates a critical security flaw that could have severe real-world consequences if deployed:

1. **Medical Data Integrity**: In a healthcare context, tampering with disease and medicine information could lead to patients receiving incorrect medical advice
2. **Financial Impact**: The system integrates with Alibaba's Tongyi Qianwen AI API, and unauthorized access allows attackers to abuse this service, potentially incurring significant costs
3. **Regulatory Compliance**: Such vulnerabilities could violate healthcare data protection regulations

### Exploitation Complexity
- **Attack Complexity**: Low
- **Privileges Required**: None
- **User Interaction**: None
- **Scope**: Unchanged
- **Network Access**: Required

### Recommended Fix
Enable the authentication interceptor by uncommenting the configuration in `MvcConfig.java` and implement proper role-based access control for administrative functions.

### Affected Functionality
- Disease management (CRUD operations)
- Medicine management (CRUD operations)
- Feedback system (CRUD operations)
- Disease classification management
- AI-powered medical consultation (cost implications)

---

**Submitter**: sh7err@vEcho

**Submission Date**: 2025-11-10

**Report Version**: 1.0
