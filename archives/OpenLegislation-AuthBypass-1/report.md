# OpenLegislation API authentication bypass via spoofed `X-Forwarded-For`

# NAME OF AFFECTED PRODUCT(S)

- OpenLegislation (New York State Senate)

## Vendor Homepage

- https://github.com/nysenate/OpenLegislation

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- sh7err@vEcho

## VERSION(S)

- 3.10.2 (current `dev` branch, no patch available)

## Software Link

- https://github.com/nysenate/OpenLegislation

# PROBLEM TYPE

## Vulnerability Type

- Authentication bypass / improper authentication

## Root Cause

- `ApiAuthFilter` trusts any `X-Forwarded-For` header supplied by the client and uses it to satisfy the configurable IP whitelist (`api.auth.ip.whitelist`). If the header value matches the whitelist regexp (default `127.0.0.1`), the filter skips API key validation entirely. Because the application never verifies that the header was injected by a trusted reverse proxy, any remote client can spoof the header and be treated as a whitelisted host.

## Impact

- Attackers can access every `/api/3/**` endpoint that normally requires a valid API key, including administrative APIs, without possessing any credentials. This exposes legislative data, management functionality, and configuration toggles to the public internet.

# DESCRIPTION

The OpenLegislation stack uses Apache Shiro to gate most REST endpoints behind the `ApiAuthFilter`. The filter is supposed to allow unauthenticated access only when the request originates from trusted hosts listed in `api.auth.ip.whitelist`. However, in `src/main/java/gov/nysenate/openleg/api/auth/ApiAuthFilter.java` lines 44‑80, the filter unconditionally sets `ipAddress` to the user-controlled `X-Forwarded-For` header (falling back to `getRemoteAddr()` only when the header is absent). Because there is no upstream verification that requests pass through a known proxy, any client can send `X-Forwarded-For: 127.0.0.1` (the default whitelist value) and bypass authentication entirely.

This behavior directly contradicts the intended design described in `docs/backend/index.md`, where the whitelist is only meant for deployments that *actually* restrict network access to a trusted proxy or internal subnet. In the default configuration, all HTTP clients can elevate themselves to trusted users.

# **Code Analysis**

- `ApiAuthFilter.doFilter()` (lines 44‑52) sets `ipAddress` to the `X-Forwarded-For` header and calls `authenticate(...)` before allowing the request to proceed.
- `authenticate(...)` (lines 72‑80) first tries API-key auth when the `key` parameter is present. When the key is missing, it simply evaluates `ipAddress.matches(filterAddress)` or falls back to the Shiro subject being permitted for the UI. No verification of header provenance occurs.
- `app.properties.example` ships with `api.auth.enable = true` and `api.auth.ip.whitelist = 127.0.0.1`, so a single spoofed header satisfies the regex out of the box.

No additional middleware rewrites or strips the header, so the value remains entirely attacker controlled.

# No login or authorization is required to exploit this vulnerability

# Vulnerability details and POC

## Exploitation Steps

1. Send a request to any protected API endpoint **without** the `key` parameter. Observe the 401 `API_KEY_REQUIRED` response.
2. Repeat the request but inject a spoofed header that matches the whitelist regexp:

```http
GET /api/3/admin/environment HTTP/1.1
Host: victim.example.com
X-Forwarded-For: 127.0.0.1
User-Agent: proof
Accept: application/json
```

3. The server now believes the request originated from localhost, so Shiro grants the `admin:envEdit`-protected controller without requiring an API key. Any `/api/3/**` route (bill search, admin account management, notifications, etc.) is similarly exposed.

## Expected vs Actual

- **Expected:** Only requests that truly originate from explicitly configured internal hosts bypass the API key requirement.
- **Actual:** Any internet client can set `X-Forwarded-For` to a matching string (e.g., `127.0.0.1`) and bypass authentication, regardless of their real IP.

# Attack results

Unauthenticated attackers gain full read/write capability across the OpenLegislation REST interface, including sensitive administration endpoints (user management, environment toggles, cache/index maintenance). This leads to information disclosure, denial of service through destructive API actions, and potential downstream compromise if admin controls trigger server-side processing jobs.

# Suggested repair

1. Only trust `X-Forwarded-For` headers from known reverse-proxy addresses (use servlet container support such as Tomcat `RemoteIpValve` or Spring `ForwardedHeaderFilter`), and default to `getRemoteAddr()` for all other requests.
2. Alternatively, remove the header parsing from `ApiAuthFilter` entirely and rely on the deployment platform to inject `proxy-addr` information into `ServletRequest`.
3. Keep the whitelist feature disabled unless deployments can guarantee that only trusted infrastructure can reach the service, and document that it must not be exposed directly to the public internet.
4. Add audit logging and automated tests to ensure that the API key requirement cannot be bypassed via header spoofing in the future.
