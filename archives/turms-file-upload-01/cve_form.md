# CVE Application Form - Turms Image Upload File Type Validation Bypass

## Vulnerability Type Info
**Unrestricted Upload of File with Dangerous Type**

## Vendor of the Product(s) Info
**Vendor**: Turms Project (turms-im)
**Vendor Homepage**: https://github.com/turms-im/turms

## Affected Product(s)/Code Base Info

| Product | Version |
|---------|---------|
| Turms AI-Serving Module | v0.10.0-SNAPSHOT and earlier |

**Fixed Version**: Not fixed yet

## Optional
**Has vendor confirmed or acknowledged the vulnerability?**
No - The vulnerability has not been publicly disclosed to the vendor yet.

## Attack Type Info
**Remote**

## Impact Info
- [x] Information Disclosure
- [x] Code Execution (potential, depending on server configuration)
- [ ] Denial of Service
- [ ] Escalation of Privileges
- [x] Other: Stored XSS, File Upload Bypass

## Affected Component(s)
`turms-ai-serving/src/main/java/im/turms/ai/domain/ocr/controller/OcrController.java`, file upload handler with `@FormData(contentType = MediaTypeConst.IMAGE)` annotation

## Attack Vector(s)
To exploit this vulnerability:
1. Attacker prepares a malicious file (executable, script, HTML with JavaScript, web shell, etc.)
2. Attacker crafts an HTTP POST request to the OCR endpoint with multipart/form-data
3. Attacker sets the Content-Type header to an image MIME type (e.g., "image/png") in the form field
4. Attacker may also rename the file with an image extension (e.g., "malicious.exe" → "image.png")
5. Server receives the upload and checks the `@FormData(contentType = MediaTypeConst.IMAGE)` annotation
6. Annotation check passes because Content-Type header claims it's an image (client-controlled)
7. Server does NOT validate actual file content using magic bytes or file signatures
8. Malicious file is accepted and stored on the server
9. Depending on server configuration, attacker may:
   - Execute uploaded code if files are processed server-side
   - Achieve stored XSS if files are served to users
   - Use uploaded files as staging for further attacks

## Suggested Description of the Vulnerability for Use in the CVE
Turms AI-Serving module v0.10.0-SNAPSHOT and earlier contains an improper file type validation vulnerability in the OCR image upload functionality. The `OcrController` in `turms-ai-serving/src/main/java/im/turms/ai/domain/ocr/controller/OcrController.java` uses the `@FormData(contentType = MediaTypeConst.IMAGE)` annotation to restrict uploads to image files, but this constraint is not properly enforced. The system relies solely on client-provided Content-Type headers and file extensions without validating actual file content using magic bytes (file signatures). An attacker can upload arbitrary file types including executables, scripts, HTML, or web shells by setting the Content-Type header to "image/*" or using an image file extension. This bypass enables potential server-side code execution, stored XSS, or information disclosure depending on how uploaded files are processed and served. CVSS v3.1 Base Score: 5.3 (Medium) - AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

## Discoverer(s)/Credits Info
s1ain

## Reference(s) Info
https://github.com/turms-im/turms
https://github.com/turms-im/turms/blob/develop/turms-ai-serving/src/main/java/im/turms/ai/domain/ocr/controller/OcrController.java
https://cwe.mitre.org/data/definitions/434.html
https://cwe.mitre.org/data/definitions/646.html
https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
https://www.filesignatures.net/

## Additional Information
- **Severity**: Medium (CVSS 5.3), potentially Critical if code execution is achieved
- **CWE ID**: CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-646 (Reliance on File Name or Extension)
- **Vulnerability Type**: Improper Input Validation / File Upload Bypass
- **Authentication Required**: Depends on deployment configuration
- **Attack Complexity**: Low
- **Disclosure Date**: 2025-11-02
- **Status**: Unpatched

**Technical Details**:
- Annotation `@FormData(contentType = MediaTypeConst.IMAGE)` is declarative only, not enforced
- No magic byte (file signature) validation implemented
- Client controls Content-Type header and filename
- Server trusts client-provided metadata without verification

**Common Magic Bytes for Valid Images**:
- PNG: `89 50 4E 47 0D 0A 1A 0A`
- JPEG: `FF D8 FF`
- GIF: `47 49 46 38` (GIF8)
- BMP: `42 4D`
- TIFF: `49 49 2A 00` (little-endian) or `4D 4D 00 2A` (big-endian)

**Recommended Fixes**:
1. Implement magic byte validation to verify actual file content
2. Use image parsing libraries (ImageIO, Apache Tika) to validate files
3. Validate file extensions as secondary defense layer
4. Store uploaded files outside web root
5. Use randomized filenames to prevent direct access
6. Set proper Content-Disposition headers when serving files
7. Implement antivirus scanning for uploaded files

**Potential Impact Scenarios**:
1. **Code Execution**: If uploaded files are processed server-side (e.g., ImageMagick vulnerabilities)
2. **Stored XSS**: If uploaded files are served with incorrect Content-Type headers
3. **Web Shell**: If web-accessible upload directory allows script execution
4. **Information Disclosure**: Upload crafted files to probe server behavior
5. **DoS**: Upload files that crash image processing libraries
