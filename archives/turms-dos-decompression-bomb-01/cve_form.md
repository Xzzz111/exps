# CVE Application Form - Turms Image Decompression Bomb DoS

## Vulnerability Type Info
**Improper Handling of Highly Compressed Data (Data Amplification)**

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
- [ ] Information Disclosure
- [ ] Code Execution
- [x] Denial of Service
- [ ] Escalation of Privileges
- [ ] Other

## Affected Component(s)
`turms-ai-serving/src/main/java/ai/djl/opencv/ExtendedOpenCVImage.java`, `read()` method line 37, `turms-ai-serving/src/main/java/im/turms/ai/domain/ocr/controller/OcrController.java`

## Attack Vector(s)
To exploit this vulnerability:
1. Attacker creates a malicious image file (PNG, JPEG, etc.) with extreme dimensions (e.g., 65535x65535 pixels)
2. The image is compressed to a small file size (~10-20 MB) but will expand to gigabytes when decompressed
3. Attacker uploads the malicious image to the Turms AI-serving OCR endpoint via HTTP POST request
4. The `ExtendedOpenCVImage.read()` method loads the image using OpenCV's `imread()` without validating dimensions
5. The image decompresses in memory (up to 12.9 GB for 65535x65535 RGB), causing immediate OutOfMemoryError
6. The AI-serving module crashes, resulting in denial of service
7. Multiple concurrent uploads can amplify the attack and prevent service recovery

## Suggested Description of the Vulnerability for Use in the CVE
Turms AI-Serving module v0.10.0-SNAPSHOT and earlier contains an image decompression bomb denial of service vulnerability. The `ExtendedOpenCVImage` class in `ai/djl/opencv/ExtendedOpenCVImage.java` loads images using OpenCV's `imread()` function without validating dimensions or pixel count before decompression. An attacker can upload a specially crafted compressed image file (e.g., PNG) that is small when compressed (~10-20 MB) but expands to gigabytes of memory (up to 12.9 GB for a 65535x65535 pixel image) when loaded. This causes immediate memory exhaustion, OutOfMemoryError, and service crash. No authentication is required if the OCR service is publicly accessible. Multiple requests can completely deny service availability. CVSS v3.1 Base Score: 7.5 (High) - AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

## Discoverer(s)/Credits Info
s1ain

## Reference(s) Info
https://github.com/turms-im/turms
https://github.com/turms-im/turms/blob/develop/turms-ai-serving/src/main/java/ai/djl/opencv/ExtendedOpenCVImage.java#L37
https://cwe.mitre.org/data/definitions/409.html
https://cwe.mitre.org/data/definitions/770.html
https://en.wikipedia.org/wiki/Zip_bomb

## Additional Information
- **Severity**: High (CVSS 7.5)
- **CWE ID**: CWE-409 (Improper Handling of Highly Compressed Data), CWE-770 (Allocation of Resources Without Limits)
- **Vulnerability Type**: Denial of Service - Decompression Bomb
- **Authentication Required**: Depends on deployment (may be exploitable without authentication)
- **Attack Complexity**: Low
- **Disclosure Date**: 2025-11-02
- **Status**: Unpatched

**Technical Details**:
- Attack amplification ratio: ~1,290x (10 MB compressed → 12.9 GB decompressed)
- Maximum exploitable image dimensions: 65535x65535 pixels (PNG format limit)
- Memory consumption formula: width × height × 3 bytes (RGB) = up to 12.9 GB
- No rate limiting or resource throttling implemented
- Vulnerability affects all image formats supported by OpenCV (PNG, JPEG, BMP, TIFF, etc.)

**Recommended Fix**:
Implement dimension validation before image loading:
- Maximum dimension: 10,000 pixels (width or height)
- Maximum pixel count: 25,000,000 pixels (25 megapixels)
- Maximum file size: 10 MB
- Add rate limiting on upload endpoint
